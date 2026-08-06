import miau_codec, std/strutils

var env = Envelope(
  version: 1'u32, token: "miau_test_token", seq: 42'u64,
  timestamp: 1700000000'u64, packetType: PACKET_HEARTBEAT,
  payload: "hi",
  hasVersion: true, hasToken: true, hasSeq: true, hasTimestamp: true,
  hasPacketType: true, hasPayload: true
)

let enc = encodeEnvelope(env)
echo "encoded len: ", enc.len
echo "hex: ", toHex(enc)

let dec = decodeEnvelope(enc)
assert dec.hasVersion and dec.version == 1'u32
assert dec.hasToken and dec.token == "miau_test_token"
assert dec.hasSeq and dec.seq == 42'u64
assert dec.hasTimestamp and dec.timestamp == 1700000000'u64
assert dec.hasPacketType and dec.packetType == PACKET_HEARTBEAT
assert dec.hasPayload and dec.payload == "hi"
echo "decode OK"

# Command decode test
var cmd = Command(
  id: 7'u64, cmdType: CMD_SHELL_EXEC, args: "dir C:\\",
  hasId: true, hasCmdType: true, hasArgs: true
)
var cs = ""
cs = encodeResponse((id: 1'u64, status: RESP_OK, message: "ok", data: "xx", final: true))
echo "response hex: ", toHex(cs)
echo "ALL OK"
