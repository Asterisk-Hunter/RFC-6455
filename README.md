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
CN-assignment/
├── server.py                 # WebSocket server (Python, raw sockets)
├── client.py                 # WebSocket client (Python, raw sockets)
├── static/
│   └── index.html            # Browser client for demo
├── docs/
│   └── RFC_6455_WebSocket_Plan.md   # Detailed plan & PPT outline
└── README.md                 # This file
```

## Requirements

- Python 3.6+
- No external packages (only standard library: `socket`, `hashlib`, `base64`, `struct`, `select`, `threading`)
- Any modern web browser (Chrome, Firefox, Edge)

## Quick Start

### 1. Start the Server

```bash
python server.py
```

Output:
```
[SERVER] WebSocket server listening on ws://localhost:8765
[SERVER] Open multiple browser tabs to test multi-client chat
[SERVER] Press Ctrl+C to stop
```

### 2. Connect Using Browser (Recommended for Demo)

Open `static/index.html` in your browser. The page will auto-connect to the server.

Open **multiple tabs** to test multi-client broadcast.

### 3. Connect Using Python Client

In a **separate terminal** (keep server running):

```bash
python client.py --name Alice
```

In another terminal:
```bash
python client.py --name Bob
```

Type messages and press Enter. Messages are broadcast to all connected clients.

### 4. CLI Options

**Server:**
```bash
python server.py --host 0.0.0.0 --port 9000 --ping-interval 15
```

**Client:**
```bash
python client.py --host localhost --port 8765 --name Charlie
```

Client commands during chat:
- Type a message and press Enter to send
- `/close` - Send a Close frame (proper shutdown)
- `/quit` - Send Close and exit
- `Ctrl+C` - Force disconnect

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

## Demo Walkthrough

1. Run `python server.py`
2. Open browser tab 1, open browser tab 2
3. Tab 1 sends "Hello" -> Tab 2 sees "You: Hello"
4. Tab 2 sends "Hi!" -> Tab 1 sees "You: Hi!"
5. Open tab 3 -> Server broadcasts "User-xxxxx connected"
6. Close tab 1 -> Server broadcasts "User-xxxxx disconnected"
7. Watch server logs for: handshake details, frame bytes, ping/pong timestamps

## Viva Preparation

See `docs/RFC_6455_WebSocket_Plan.md` for:
- Full protocol explanation
- PPT outline (16 slides)
- 15+ viva questions with answers
- Architecture diagrams
- Code walkthrough guide
