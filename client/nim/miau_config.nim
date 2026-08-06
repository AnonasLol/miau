## Miau agent build-time configuration.
## The builder injects these via -d: defines. Defaults below for dev.
##   -d:miauServer="host"
##   -d:miauPort=9000
##   -d:miauToken="token"
##   -d:miauAesKey="hex"
##   -d:miauPin="SHA256HEX"
##   -d:miauCaPath="server.crt"
##   -d:miauInterval=15
const
  ServerAddr* {.strdefine.} = "127.0.0.1"
  ServerPort* {.intdefine.} = 9000
  AgentToken* {.strdefine.} = "miau_dev_token"
  AgentAesKey* {.strdefine.} = ""
  ServerPin* {.strdefine.} = ""
  CaPath* {.strdefine.} = "server.crt"
  HbInterval* {.intdefine.} = 15
  ClientVersion* = "1.0.0"

  ## Pre-shared key for the unauthenticated auth handshake. Mirrors
  ## backend listener._psk(): hb_interval big-endian in 32 bytes.
  ## Hex of 15 = 31 zero bytes + 0x0f.
  PskHex* {.strdefine.} = "000000000000000000000000000000000000000000000000000000000000000f"
