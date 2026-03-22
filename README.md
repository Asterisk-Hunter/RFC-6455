# RFC 6455 - The WebSocket Protocol - Implementation

Computer Networks Lab Assignment

## What This Is

A from-scratch implementation of **RFC 6455 (The WebSocket Protocol)** in Python using raw TCP sockets. No WebSocket libraries used - every byte on the wire is constructed and parsed manually per the RFC specification.

## Features Implemented

| # | Feature | RFC Section | File |
|---|---------|-------------|------|
| 1 | HTTP Upgrade Handshake | Section 4 | `server.py` `client.py` |
| 2 | Frame Parsing & Construction | Section 5.2 | `server.py` `client.py` |
| 3 | Text Messaging with Broadcast | Section 5.6, 6 | `server.py` |
| 4 | Ping/Pong Heartbeat | Section 5.5.2, 5.5.3 | `server.py` `client.py` |
| 5 | Connection Close Handling | Section 5.5.1, 7 | `server.py` `client.py` |

## Project Structure

```
RFC-6455/
├── frontend/
│   └── index.html              # Browser chat UI (GitHub Pages)
├── backend/
│   ├── server.py               # WebSocket server (Python, raw sockets)
│   ├── client.py               # WebSocket CLI client
│   └── Procfile                # Render deployment config
├── docs/
│   └── RFC_6455_WebSocket_Plan.md  # Detailed plan & PPT outline
├── README.md
└── .gitignore
```

## Requirements

- Python 3.6+
- No external packages (only standard library: `socket`, `hashlib`, `base64`, `struct`, `select`, `threading`)
- Any modern web browser (Chrome, Firefox, Edge)

## Local Development

### 1. Start the Server

```bash
cd backend
python server.py
```

### 2. Open the Frontend

Open `frontend/index.html` in your browser. It auto-connects to `ws://localhost:8765`.

Open **multiple tabs** to test multi-client broadcast.

### 3. Or Use the CLI Client

```bash
cd backend
python client.py --name Alice
```

## Deployment

### Frontend → GitHub Pages

1. Go to repo **Settings → Pages**
2. Source: **Deploy from a branch**
3. Branch: `main`, folder: `/frontend`
4. Save → your site goes live at `https://asterisk-hunter.github.io/RFC-6455/`

### Backend → Render

1. Go to [render.com](https://render.com) → **New Web Service**
2. Connect this GitHub repo
3. Settings:
   - **Root Directory:** `backend`
   - **Build Command:** *(leave empty)*
   - **Start Command:** `python server.py`
   - **Environment:** Python 3
4. Render auto-sets the `PORT` env var — `server.py` reads it automatically
5. After deploy, copy your URL (e.g. `https://rfc-6455.onrender.com`)

### Link Frontend ↔ Backend

Open `frontend/index.html` and update this line with your Render URL:

```javascript
const RENDER_HOST = 'rfc-6455.onrender.com';
```

Then commit and push — GitHub Pages redeploys automatically.

## How the Protocol Works

### Handshake (HTTP Upgrade)

```
Client                                          Server
  |--- GET / HTTP/1.1 ---------------------------->|
  |    Upgrade: websocket                          |
  |    Connection: Upgrade                         |
  |    Sec-WebSocket-Key: dGhlIHN...==             |
  |    Sec-WebSocket-Version: 13                   |
  |                                                |
  |<--- HTTP/1.1 101 Switching Protocols ----------|
  |     Upgrade: websocket                         |
  |     Connection: Upgrade                        |
  |     Sec-WebSocket-Accept: s3pPLM...==          |
  |                                                |
  |<========= WebSocket Connection ===============>|
```

### Frame Format

```
 0                   1                   2
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 ...
+-+-+-+-+-------+-+-------------+---------------...
|F|R|R|R| opcode|M| Payload len | Masking-key  ...
|I|S|S|S|  (4)  |A|    (7)      |  (4 bytes)   ...
|N|V|V|V|       |S|             |              ...
+-+-+-+-+-------+-+-------------+---------------...

Opcodes: 0x1=Text  0x8=Close  0x9=Ping  0xA=Pong
```

### Masking

Client-to-server frames MUST be masked (XOR with 4-byte key). This is a security requirement per RFC 6455 Section 5.3 to prevent cache poisoning on intermediaries.

```
j = i MOD 4
transformed[i] = original[i] XOR masking_key[j]
```

## Viva Preparation

See `docs/RFC_6455_WebSocket_Plan.md` for:
- Full protocol explanation
- PPT outline (16 slides)
- 15+ viva questions with answers
- Architecture diagrams
- Code walkthrough guide
