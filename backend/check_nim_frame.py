"""Cross-language check: decrypt a frame produced by the Nim agent."""
import codec, messages_pb2 as pb, enums_pb2 as en

key = bytes.fromhex("167fb08080e66058a89a20538ebca3705aa67578369a64f4e0ca847e9aa82b49")
with open("frame.bin", "rb") as fh:
    data = fh.read()

env = codec.read_frame(__import__("io").BytesIO(data), key)
print("packet_type:", env.packet_type, "(expect 3 HEARTBEAT)")
print("token:", env.token)
print("seq:", env.seq, "ts:", env.timestamp)
print("payload:", env.payload)
assert env.packet_type == en.PACKET_HEARTBEAT
assert env.token == "miau_test"
assert env.payload == b"hello miau"
print("CROSS-LANG OK: Nim frame decryptable in Python")
