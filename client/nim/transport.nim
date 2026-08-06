## Miau agent transport: TLS socket with certificate pinning, length-prefixed
## AES-256-GCM encrypted frames, hand-rolled protobuf Envelope codec.
##
## Frame layout (mirrors backend/codec.py):
##   [4 bytes: uint32 big-endian length]
##   [12 bytes: nonce]
##   [N bytes: ciphertext || 16-byte GCM tag]
import net, std/streams, std/strutils, std/os
import nativesockets
import nimcrypto
import miau_codec, miau_config
import ca_embedded

const
  GCMNonceLen = 12
  GCMTagLen = 16
  MaxFrame = 8 * 1024 * 1024

type
  FrameError* = object of CatchableError
  Transport* = ref object
    socket: Socket
    ctx: SslContext
    key: seq[byte]
    connected: bool

proc hexToBytes*(s: string): seq[byte] =
  ## Parse hex string into byte seq (used for aes key).
  var i = 0
  while i + 1 < s.len:
    result.add(parseHexInt(s[i .. i + 1]).byte)
    i += 2

proc setKey*(t: Transport, hexKey: string) =
  t.key = hexToBytes(hexKey)

proc waitReadable*(t: Transport, timeoutMs: int): bool =
  ## Returns true if at least one byte is available to read within timeout.
  var fds = @[t.socket.getFd()]
  let n = selectRead(fds, timeoutMs)
  return n > 0

proc toBytes(s: string): seq[byte] =
  for c in s: result.add(byte(c))

proc toBytes(b: openArray[byte]): seq[byte] =
  newSeq(result, b.len)
  copyMem(result[0].addr, b[0].unsafeAddr, b.len)

proc toStr*(b: openArray[byte]): string =
  result = newString(b.len)
  copyMem(result[0].addr, b[0].unsafeAddr, b.len)

proc close*(t: Transport) =
  if t != nil and t.connected:
    try: t.socket.close()
    except: discard
    t.connected = false

proc encryptPayload*(key: seq[byte], plain: string): seq[byte] =
  ## nonce(12) || AES-GCM(plain, tag=16)  -- mirrors backend codec.
  var nonce = newSeq[byte](GCMNonceLen)
  discard randomBytes[byte](nonce)  # CSPRNG fill
  var gcm: GCM[aes256]
  gcm.init(key, nonce, @[])
  var ct = newSeq[byte](plain.len)
  var tag = newSeq[byte](GCMTagLen)
  gcm.encrypt(toBytes(plain), ct, tag)
  result = nonce & ct & tag

proc decryptPayload*(key: seq[byte], body: seq[byte]): string =
  ## body = nonce(12) || ct || tag(16)
  if body.len < GCMNonceLen + GCMTagLen:
    raise newException(FrameError, "frame too short")
  let nonce = body[0 ..< GCMNonceLen]
  let ctLen = body.len - GCMNonceLen - GCMTagLen
  let ct = body[GCMNonceLen ..< GCMNonceLen + ctLen]
  let tag = body[body.len - GCMTagLen .. ^1]
  var gcm: GCM[aes256]
  gcm.init(key, nonce, @[])
  var pt = newSeq[byte](ctLen)
  if not gcm.decrypt(ct, pt, tag):
    raise newException(FrameError, "decrypt auth failed")
  return toStr(pt)

proc readExact(t: Transport, n: int): seq[byte] =
  ## Read exactly n bytes from the socket.
  result = newSeq[byte](n)
  var got = 0
  while got < n:
    var buf = newString(n - got)
    let k = t.socket.recv(buf, n - got)
    if k <= 0:
      raise newException(FrameError, "connection closed")
    for i in 0 ..< k:
      result[got + i] = byte(buf[i])
    got += k

proc sendEnvelope*(t: Transport, env: Envelope) =
  ## Serialize envelope -> encrypt -> send length-prefixed frame.
  let plain = encodeEnvelope(env)
  let frame = encryptPayload(t.key, plain)
  var prefix = newSeq[byte](4)
  prefix[0] = byte((frame.len shr 24) and 0xff)
  prefix[1] = byte((frame.len shr 16) and 0xff)
  prefix[2] = byte((frame.len shr 8) and 0xff)
  prefix[3] = byte(frame.len and 0xff)
  t.socket.send(toStr(prefix))
  t.socket.send(toStr(frame))

proc readEnvelope*(t: Transport): Envelope =
  ## Read one frame, decrypt, parse envelope.
  let hdr = t.readExact(4)
  let n = (hdr[0].int shl 24) or (hdr[1].int shl 16) or
          (hdr[2].int shl 8) or hdr[3].int
  if n == 0: return Envelope()
  if n > MaxFrame:
    raise newException(FrameError, "frame too large: " & $n)
  let body = t.readExact(n)
  let plain = decryptPayload(t.key, body)
  result = decodeEnvelope(plain)
proc writeEmbeddedCa(): string =
  ## Write embedded CA to a temp file, return its path.
  let tmpDir = getTempDir()
  let caPath = tmpDir / "miau_ca.crt"
  writeFile(caPath, CaCertPem)
  return caPath

proc connect*(t: Transport, host: string, port: Port,
              caPem: string, pinSha256: string) =
  ## Establish TLS with cert validation against our CA + fingerprint pin.
  t.key = hexToBytes(AgentAesKey)
  # Use embedded CA if caPem path is empty or file doesn't exist
  var caToUse = caPem
  if caPem.len == 0 or not fileExists(caPem):
    caToUse = writeEmbeddedCa()
  let ctx = newContext(protVersion = protSSLv23, verifyMode = CVerifyPeer,
                       caFile = caToUse)
  var sock = newSocket()
  sock.connect(host, port)
  try:
    ctx.wrapConnectedSocket(sock, handshakeAsClient, host)
  except:
    sock.close()
    raise

  # Certificate pin: verify SHA256 fingerprint of the peer leaf cert.
  var ok = false
  try:
    let certs = sock.getPeerCertificates()
    if certs.len > 0:
      let fp = $sha256.digest(certs[0])
      ok = cmpIgnoreStyle(fp, pinSha256) == 0
  except:
    ok = false
  if not ok:
    sock.close()
    raise newException(FrameError, "certificate pin mismatch")

  t.socket = sock
  t.ctx = ctx
  t.connected = true
