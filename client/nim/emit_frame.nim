## Cross-check: produce an encrypted frame that Python backend/codec.py must
## be able to decrypt. Outputs binary to stdout.
import miau_codec, transport, std/strutils

var env = Envelope(
  version: 1'u32, token: "miau_test", seq: 42'u64,
  timestamp: 1700000000'u64, packetType: PACKET_HEARTBEAT,
  payload: "hello miau",
  hasVersion: true, hasToken: true, hasSeq: true, hasTimestamp: true,
  hasPacketType: true, hasPayload: true
)

let plain = encodeEnvelope(env)

# Fake transport just to reuse frame crypto
let key = hexToBytes("167fb08080e66058a89a20538ebca3705aa67578369a64f4e0ca847e9aa82b49")
let frame = encryptPayload(key, plain)
var prefix = newSeq[byte](4)
prefix[0] = byte((frame.len shr 24) and 0xff)
prefix[1] = byte((frame.len shr 16) and 0xff)
prefix[2] = byte((frame.len shr 8) and 0xff)
prefix[3] = byte(frame.len and 0xff)

let payload = toStr(prefix) & toStr(frame)
writeFile("frame.bin", payload)
echo "wrote frame.bin len=", payload.len
