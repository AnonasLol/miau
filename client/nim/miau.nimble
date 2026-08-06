# Package
version       = "1.0.0"
author        = "Miau"
description   = "Miau agent (Nim core)"
license       = "MIT"
srcDir        = "."

# Dependencies
requires "nim >= 2.0.0"
requires "nimcrypto >= 0.7.0"

task test, "run pb codec test":
  exec "nim c -r test_pb.nim"
