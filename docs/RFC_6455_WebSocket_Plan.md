# RFC 6455 - The WebSocket Protocol
## Computer Networks Lab - Implementation Plan

---

## Table of Contents
1. [RFC Overview](#1-rfc-overview)
2. [History & Motivation](#2-history--motivation)
3. [Working Principle](#3-working-principle)
4. [Key Concepts](#4-key-concepts)
5. [Features We Are Implementing](#5-features-we-are-implementing)
6. [Architecture & Design](#6-architecture--design)
7. [Implementation Plan](#7-implementation-plan)
8. [PPT Outline](#8-ppt-outline)
9. [Viva Questions & Answers](#9-viva-questions--answers)
10. [Testing & Demo Plan](#10-testing--demo-plan)

---

## 1. RFC Overview

| Field | Detail |
|-------|--------|
| **RFC Number** | 6455 |
| **Title** | The WebSocket Protocol |
| **Authors** | Ian Fette (Google), Alexey Melnikov (Isode Ltd.) |
| **Date** | December 2011 |
| **Status** | Proposed Standard (Internet Engineering Task Force) |
| **Transport** | TCP (ports 80 for ws://, 443 for wss://) |
| **Purpose** | Full-duplex, bidirectional communication over a single TCP connection |

**Abstract:** WebSocket enables two-way communication between a client (typically a browser) and a remote host. It starts with an HTTP handshake that "upgrades" the connection to WebSocket, then maintains a persistent connection for bidirectional data transfer using a lightweight framing protocol.

---

## 2. History & Motivation

### The Problem Before WebSocket

Traditional web apps needing real-time communication had to **abuse HTTP**:

```
Client                          Server
  |--- HTTP GET /poll --------->|   (request)
  |<--- HTTP Response ----------|   (response)
  |--- HTTP GET /poll --------->|   (request again...)
  |<--- HTTP Response ----------|   (response again...)
  |    ... repeats endlessly ...
```

**Techniques used (all inefficient):**

| Technique | How it works | Problem |
|-----------|-------------|---------|
| **Polling** | Client sends requests every N seconds | Wastes bandwidth, high latency |
| **Long Polling** | Server holds request open until data available | Still half-duplex, HTTP overhead per message |
| **HTTP Streaming** | Response stays open, server pushes data | Proxy issues, buffer problems, non-standard |
| **Server-Sent Events** | One-way server-to-client only | Not bidirectional |

### The Solution: WebSocket

```
Client                          Server
  |--- HTTP Upgrade Request ---->|   (1 handshake)
  |<--- 101 Switching Protocols-|
  |                              |
  |<====== WebSocket ==========>|   (persistent, full-duplex)
  |<====== Connection =========>|
```

**Advantages over HTTP polling:**
- Single persistent TCP connection (not one request per message)
- Minimal overhead: ~2-14 bytes per frame vs HTTP headers (hundreds of bytes)
- True full-duplex: both sides send simultaneously
- Lower latency: no HTTP request/response cycle
- Server can push data anytime without client asking first

### Timeline
- **2008:** WebSocket concept first proposed by Ian Hickson (WHATWG)
- **2010:** Multiple draft versions (hybi working group at IETF)
- **2011 (Dec):** RFC 6455 published as Proposed Standard
- **2011:** Major browsers start implementing (Chrome 16, Firefox 7, Safari 6)
- **Today:** Used by millions of apps (Slack, Discord, trading platforms, games)

---

## 3. Working Principle

### 3.1 Connection Lifecycle

```
  CLOSED ---[ Handshake ]---> OPEN ---[ Data Transfer ]---> CLOSING ---[ Close ]---> CLOSED
```

### 3.2 Opening Handshake (HTTP Upgrade)

**Client sends:**
```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Origin: http://example.com
Sec-WebSocket-Version: 13
```

**Server responds:**
```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

**How `Sec-WebSocket-Accept` is computed (critical for implementation):**
```
1. Take Sec-WebSocket-Key value: "dGhlIHNhbXBsZSBub25jZQ=="
2. Concatenate with magic GUID: "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
   Result: "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
3. Compute SHA-1 hash of the concatenated string
4. Base64-encode the SHA-1 hash
   Result: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
```

### 3.3 Data Framing

After handshake, all data is sent as **frames**. The base framing protocol:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                 |
+---------------------------------------------------------------+
```

**Key fields:**

| Field | Bits | Description |
|-------|------|-------------|
| FIN | 1 | 1 = final fragment of message |
| RSV1-3 | 3 | Reserved (0 unless extension negotiated) |
| Opcode | 4 | Frame type (see below) |
| MASK | 1 | 1 = payload is masked (client-to-server MUST be masked) |
| Payload length | 7+16/64 | 0-125: actual length, 126: next 2 bytes, 127: next 8 bytes |
| Masking key | 0 or 32 | Present if MASK=1; XOR key for payload |
| Payload data | variable | The actual message data |

### 3.4 Opcodes

| Opcode | Value | Type | Description |
|--------|-------|------|-------------|
| 0x0 | 0 | Continuation | Fragment of a fragmented message |
| 0x1 | 1 | Data (Text) | UTF-8 text frame |
| 0x2 | 2 | Data (Binary) | Binary data frame |
| 0x8 | 8 | Control (Close) | Connection close signal |
| 0x9 | 9 | Control (Ping) | Heartbeat ping |
| 0xA | 10 | Control (Pong) | Heartbeat pong (response to ping) |

### 3.5 Masking

- **Client-to-Server:** MUST be masked (security requirement per RFC)
- **Server-to-Client:** MUST NOT be masked
- **Why:** Prevents cache poisoning attacks on intermediaries (proxies)
- **How:** XOR the payload with a 4-byte masking key, byte by byte
  ```
  j = i MOD 4
  transformed[i] = original[i] XOR masking_key[j]
  ```

### 3.6 Closing Handshake

```
Client                          Server
  |--- Close Frame (0x8) ------->|
  |<--- Close Frame (0x8) -------|
  |    (TCP connection closed)    |
```

- Either side can initiate
- Close frame may contain a 2-byte status code + optional UTF-8 reason
- After sending Close, peer does NOT send further data

### 3.7 Ping/Pong (Keep-Alive)

```
Server                          Client
  |--- Ping Frame (0x9) ------->|
  |<--- Pong Frame (0xA) -------|
```

- Server sends Ping, client MUST respond with Pong (same payload)
- Used as heartbeat to detect dead connections
- Control frames max payload: 125 bytes

---

## 4. Key Concepts

### WebSocket URIs
- `ws://example.com/chat` - Unencrypted (port 80 default)
- `wss://example.com/chat` - Encrypted via TLS (port 443 default)

### Subprotocols
- Application-level protocols layered on WebSocket
- Negotiated via `Sec-WebSocket-Protocol` header during handshake
- Examples: `chat`, `graphql-ws`, `mqtt`

### Extensions
- Protocol extensions negotiated during handshake
- Examples: `permessage-deflate` (compression)

### States
| State | Description |
|-------|-------------|
| CONNECTING | Connection not yet established |
| OPEN | Handshake complete, data can be transferred |
| CLOSING | Close handshake started, not yet complete |
| CLOSED | Connection closed or could not be opened |

---

## 5. Features We Are Implementing

### Core 5 Features (Required)

| # | Feature | RFC Section | Difficulty | Why Include |
|---|---------|-------------|------------|-------------|
| 1 | **HTTP Upgrade Handshake** | Section 4 | Medium | Foundation of WebSocket; shows protocol-level understanding |
| 2 | **Frame Parsing & Construction** | Section 5.2 | Hard | The core technical challenge; bit-level manipulation |
| 3 | **Text Messaging** | Section 5.6, 6 | Medium | Demonstrates practical usage (chat) |
| 4 | **Ping/Pong Heartbeat** | Section 5.5.2-3 | Easy | Shows deeper protocol coverage; keeps connections alive |
| 5 | **Connection Close Handling** | Section 5.5.1, 7 | Easy-Medium | Most students skip this; shows completeness |

### Bonus Feature (For Extra Points)

| # | Feature | Why Include |
|---|---------|-------------|
| 6 | **Multi-client Broadcast** | Makes demo 10x better; real chat room |

### What We Are NOT Implementing (and why)

| Feature | Reason to Skip |
|---------|---------------|
| Binary frames | Complexity without much demo value for a lab |
| Fragmentation | Rare use case; adds significant complexity |
| Extensions (compression) | Too complex for lab scope |
| WSS (TLS) | Requires certificate management; adds deployment complexity |
| Subprotocol negotiation | Optional; not core to demonstrating the protocol |

---

## 6. Architecture & Design

### Technology Choice: Python with Raw Sockets

**Why Python + raw sockets (no WebSocket library):**
- We MUST use raw sockets to demonstrate understanding of the protocol
- Using a library like `websockets` would defeat the purpose
- Python is readable and good for lab demonstration
- `hashlib` for SHA-1, `base64` for encoding (standard library only)

### Project Structure

```
CN-assignment/
├── RFC_6455_WebSocket_Plan.md    (this file)
├── server.py                     (WebSocket server)
├── client.py                     (WebSocket client - CLI)
├── static/
│   └── index.html                (Browser-based client for demo)
└── README.md                     (usage instructions)
```

### Module Breakdown

```
server.py
├── generate_accept_key()     # SHA-1 + Base64 handshake key
├── parse_handshake()         # Parse HTTP upgrade request
├── build_handshake_response()# Build 101 response
├── parse_frame()             # Decode binary frame into fields
├── build_frame()             # Encode fields into binary frame
├── unmask_payload()          # XOR unmasking
├── handle_ping()             # Respond with pong
├── handle_close()            # Close handshake
├── broadcast()               # Send message to all clients
└── main()                    # Server loop (select/poll for multiplexing)

client.py
├── generate_key()            # Random Base64 nonce
├── build_handshake()         # Build HTTP upgrade request
├── validate_response()       # Check Sec-WebSocket-Accept
├── build_frame()             # Encode frame (masked)
├── parse_frame()             # Decode frame
├── send_message()            # Send text frame
└── main()                    # Client loop
```

---

## 7. Implementation Plan

### Phase 1: Handshake (Feature 1)

```python
# server.py - Handshake handling

import socket
import hashlib
import base64

MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def generate_accept_key(sec_websocket_key):
    """
    RFC 6455 Section 4.2.2:
    1. Concatenate key + GUID
    2. SHA-1 hash
    3. Base64 encode
    """
    concat = sec_websocket_key + MAGIC_GUID
    sha1_hash = hashlib.sha1(concat.encode('utf-8')).digest()
    accept_key = base64.b64encode(sha1_hash).decode('utf-8')
    return accept_key

def parse_handshake(data):
    """Parse client's HTTP upgrade request"""
    headers = {}
    lines = data.decode('utf-8').split('\r\n')
    request_line = lines[0]  # GET /chat HTTP/1.1

    for line in lines[1:]:
        if ': ' in line:
            key, value = line.split(': ', 1)
            headers[key.lower()] = value

    return request_line, headers

def build_handshake_response(accept_key):
    """Build the 101 Switching Protocols response"""
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept_key}\r\n"
        "\r\n"
    )
    return response.encode('utf-8')
```

### Phase 2: Frame Parsing (Feature 2) - THE HARDEST PART

```python
# server.py - Frame parsing

import struct

def parse_frame(data):
    """
    Parse a WebSocket frame per RFC 6455 Section 5.2.

    Frame structure:
    Byte 0: FIN(1) + RSV(3) + Opcode(4)
    Byte 1: MASK(1) + Payload length(7)
    Then: extended payload length (if 126 or 127)
    Then: masking key (if MASK=1) - 4 bytes
    Then: payload data
    """
    byte0 = data[0]
    byte1 = data[1]

    fin = (byte0 >> 7) & 0x1
    opcode = byte0 & 0x0F
    masked = (byte1 >> 7) & 0x1
    payload_length = byte1 & 0x7F

    offset = 2  # current byte position

    # Extended payload length
    if payload_length == 126:
        payload_length = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
    elif payload_length == 127:
        payload_length = struct.unpack('!Q', data[offset:offset+8])[0]
        offset += 8

    # Masking key
    masking_key = None
    if masked:
        masking_key = data[offset:offset+4]
        offset += 4

    # Payload
    payload = data[offset:offset+payload_length]

    # Unmask
    if masked and masking_key:
        payload = unmask_payload(payload, masking_key)

    return {
        'fin': fin,
        'opcode': opcode,
        'masked': masked,
        'payload_length': payload_length,
        'payload': payload
    }

def unmask_payload(payload, masking_key):
    """
    RFC 6455 Section 5.3:
    j = i MOD 4
    transformed_octet_i = original_octet_i XOR masking_key_octet_j
    """
    unmasked = bytearray(len(payload))
    for i in range(len(payload)):
        unmasked[i] = payload[i] ^ masking_key[i % 4]
    return bytes(unmasked)

def build_frame(opcode, payload, masked=False):
    """
    Build a WebSocket frame.

    Opcodes: 0x1=text, 0x8=close, 0x9=ping, 0xA=pong
    """
    frame = bytearray()

    # Byte 0: FIN=1, RSV=000, Opcode
    frame.append(0x80 | opcode)  # FIN set + opcode

    payload_len = len(payload)

    # Byte 1+: MASK bit + payload length
    if payload_len <= 125:
        mask_bit = 0x80 if masked else 0x00
        frame.append(mask_bit | payload_len)
    elif payload_len <= 65535:
        mask_bit = 0x80 if masked else 0x00
        frame.append(mask_bit | 126)
        frame.extend(struct.pack('!H', payload_len))
    else:
        mask_bit = 0x80 if masked else 0x00
        frame.append(mask_bit | 127)
        frame.extend(struct.pack('!Q', payload_len))

    # Masking key + masked payload (if masked)
    if masked:
        import os
        masking_key = os.urandom(4)
        frame.extend(masking_key)
        masked_payload = bytearray(len(payload))
        for i in range(len(payload)):
            masked_payload[i] = payload[i] ^ masking_key[i % 4]
        frame.extend(masked_payload)
    else:
        frame.extend(payload)

    return bytes(frame)
```

### Phase 3: Server with Multi-client Support (Features 3-6)

```python
# server.py - Main server loop

import socket
import select

OPCODE_TEXT = 0x1
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA

class WebSocketServer:
    def __init__(self, host='localhost', port=8765):
        self.host = host
        self.port = port
        self.clients = {}  # socket -> state info
        self.server_socket = None

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"WebSocket server listening on ws://{self.host}:{self.port}")

        while True:
            read_list = [self.server_socket] + list(self.clients.keys())
            readable, _, _ = select.select(read_list, [], [], 1.0)

            for sock in readable:
                if sock is self.server_socket:
                    self.accept_client()
                else:
                    self.handle_client(sock)

    def accept_client(self):
        """Accept new TCP connection and perform WebSocket handshake"""
        client_sock, addr = self.server_socket.accept()
        print(f"New connection from {addr}")

        # Read handshake
        data = client_sock.recv(4096)
        request_line, headers = parse_handshake(data)

        # Validate
        if headers.get('upgrade') != 'websocket':
            client_sock.close()
            return

        # Compute accept key
        key = headers.get('sec-websocket-key', '')
        accept_key = generate_accept_key(key)

        # Send response
        response = build_handshake_response(accept_key)
        client_sock.sendall(response)

        self.clients[client_sock] = {'addr': addr}
        print(f"WebSocket connection established with {addr}")

    def handle_client(self, sock):
        """Handle incoming data from a connected client"""
        try:
            data = sock.recv(4096)
            if not data:
                self.remove_client(sock)
                return

            frame = parse_frame(data)

            if frame['opcode'] == OPCODE_TEXT:
                message = frame['payload'].decode('utf-8')
                print(f"Received: {message}")
                # Broadcast to all clients
                self.broadcast(message, exclude=sock)

            elif frame['opcode'] == OPCODE_PING:
                # Respond with pong
                pong_frame = build_frame(OPCODE_PONG, frame['payload'])
                sock.sendall(pong_frame)

            elif frame['opcode'] == OPCODE_CLOSE:
                # Close handshake
                close_frame = build_frame(OPCODE_CLOSE, frame['payload'])
                sock.sendall(close_frame)
                self.remove_client(sock)

        except Exception as e:
            print(f"Error: {e}")
            self.remove_client(sock)

    def broadcast(self, message, exclude=None):
        """Send message to all connected clients"""
        frame = build_frame(OPCODE_TEXT, message.encode('utf-8'))
        for client_sock in list(self.clients.keys()):
            if client_sock != exclude:
                try:
                    client_sock.sendall(frame)
                except:
                    self.remove_client(client_sock)

    def remove_client(self, sock):
        if sock in self.clients:
            addr = self.clients[sock]['addr']
            del self.clients[sock]
            sock.close()
            print(f"Client {addr} disconnected")

if __name__ == '__main__':
    server = WebSocketServer()
    server.start()
```

### Phase 4: Browser Client for Demo

```html
<!-- static/index.html -->
<!DOCTYPE html>
<html>
<head><title>WebSocket Chat</title></head>
<body>
<h2>WebSocket Chat - RFC 6455 Demo</h2>
<div id="messages" style="border:1px solid #ccc; height:300px; overflow-y:scroll; padding:10px;"></div>
<input type="text" id="msgInput" placeholder="Type a message...">
<button onclick="sendMessage()">Send</button>

<script>
const ws = new WebSocket('ws://localhost:8765');

ws.onopen = () => {
    addMessage('[System] Connected');
};

ws.onmessage = (event) => {
    addMessage('Other: ' + event.data);
};

ws.onclose = () => {
    addMessage('[System] Disconnected');
};

function sendMessage() {
    const input = document.getElementById('msgInput');
    ws.send(input.value);
    addMessage('You: ' + input.value);
    input.value = '';
}

function addMessage(msg) {
    const div = document.getElementById('messages');
    div.innerHTML += msg + '<br>';
    div.scrollTop = div.scrollHeight;
}
</script>
</body>
</html>
```

---

## 8. PPT Outline

### Slide 1: Title Slide
- **Title:** Implementation of RFC 6455 - The WebSocket Protocol
- Lab name, team members, date

### Slide 2: Introduction & Motivation
- Problem: HTTP is half-duplex, request-response only
- Need for real-time bidirectional communication
- Limitations of polling, long-polling, HTTP streaming

### Slide 3: History
- 2008: Concept proposed by Ian Hickson
- 2010-2011: IETF hybi working group drafts
- December 2011: RFC 6455 published
- Today: Used in Slack, Discord, trading, gaming, IoT

### Slide 4: Protocol Overview
- Two phases: Handshake + Data Transfer
- Starts as HTTP, upgrades to WebSocket
- Framed messages over persistent TCP connection
- Diagram: HTTP upgrade flow

### Slide 5: Working Principle - Handshake
- Client sends HTTP GET with `Upgrade: websocket`
- Server responds with 101 Switching Protocols
- Key exchange: Sec-WebSocket-Key + GUID -> SHA-1 -> Base64
- Show actual handshake request/response

### Slide 6: Working Principle - Frame Format
- Visual diagram of frame structure
- Explain FIN, Opcode, MASK, Payload length
- Bit-level breakdown

### Slide 7: Key Functionalities
- Text/Binary frames
- Ping/Pong heartbeat
- Connection close handshake
- Masking (security)
- Subprotocols & Extensions

### Slide 8: What We Implemented (5 features)
- 1. HTTP Upgrade Handshake
- 2. Frame Parsing & Construction
- 3. Text Messaging with Broadcast
- 4. Ping/Pong Heartbeat
- 5. Connection Close Handling

### Slide 9: Implementation Architecture
- Technology: Python raw sockets (no library)
- Server architecture diagram
- Module breakdown

### Slide 10: Code Walkthrough - Handshake
- Sec-WebSocket-Accept computation
- Key code snippets

### Slide 11: Code Walkthrough - Frame Parsing
- Bit manipulation for frame fields
- Masking/unmasking XOR logic
- Most complex part of implementation

### Slide 12: Code Walkthrough - Server & Chat
- Multi-client handling with select()
- Broadcasting logic
- Ping/Pong implementation

### Slide 13: Demo
- Live demonstration
- Show: browser tab 1 <-> browser tab 2 real-time chat
- Show: server logs (handshake, frames, ping/pong)

### Slide 14: Key Talking Points
- Why masking? (security against cache poisoning)
- Why SHA-1? (not for security, just uniqueness proof)
- WebSocket vs HTTP/2 Server Push
- WebSocket vs WebTransport (emerging)

### Slide 15: Possible Improvements
- Add TLS support (wss://)
- Implement permessage-deflate extension
- Subprotocol negotiation
- Binary frame support
- Reconnection handling

### Slide 16: References
- RFC 6455
- MDN WebSocket API documentation
- Related RFCs: 2616 (HTTP), 4648 (Base64), FIPS.180-3 (SHA-1)

---

## 9. Viva Questions & Answers

### Basic Questions

**Q: What is RFC 6455?**
A: RFC 6455 defines the WebSocket Protocol - a standard for full-duplex, bidirectional communication between a client and server over a single TCP connection, starting with an HTTP upgrade handshake.

**Q: Why was WebSocket needed?**
A: HTTP is request-response (half-duplex). Real-time apps needed polling, which wastes bandwidth and adds latency. WebSocket provides a persistent, full-duplex channel.

**Q: How does the handshake work?**
A: Client sends HTTP GET with `Upgrade: websocket` header and a `Sec-WebSocket-Key`. Server responds with 101 status, `Upgrade: websocket`, and `Sec-WebSocket-Accept` (SHA-1 hash of key + magic GUID, base64-encoded).

**Q: What is the magic GUID?**
A: `258EAFA5-E914-47DA-95CA-C5AB0DC85B11` - a fixed string defined in RFC 6455, concatenated with the client's key before hashing. It ensures only true WebSocket servers can respond correctly.

### Frame Questions

**Q: Explain the frame format.**
A: Byte 0: FIN(1 bit) + RSV(3 bits) + Opcode(4 bits). Byte 1: MASK(1 bit) + Payload length(7 bits). Extended length if needed. 4-byte masking key if masked. Then payload data.

**Q: What are the opcodes?**
A: 0x1 = Text, 0x2 = Binary, 0x0 = Continuation, 0x8 = Close, 0x9 = Ping, 0xA = Pong.

**Q: Why is masking required from client to server?**
A: To prevent cache poisoning attacks on intermediaries (proxies). An attacker could craft HTTP requests that look like valid responses. Masking ensures the bytes on the wire don't match predictable patterns.

**Q: Why is server-to-client NOT masked?**
A: The server is trusted (it opted-in to WebSocket). Masking from server provides no additional security benefit, and removing it reduces overhead.

### Advanced Questions

**Q: What is the difference between WebSocket and HTTP/2 Server Push?**
A: HTTP/2 Server Push is still one-directional (server pushes resources the client might need). WebSocket is truly bidirectional. HTTP/2 Push doesn't allow client to send arbitrary messages.

**Q: What is WebTransport and how does it compare?**
A: WebTransport (emerging standard) runs over HTTP/3 (QUIC). It supports multiple streams, unreliable delivery (like UDP), and is more flexible. It's a potential successor but WebSocket is still dominant.

**Q: Why SHA-1 and not SHA-256?**
A: The accept key computation is NOT for cryptographic security. It's just a proof that the server understood the WebSocket handshake. SHA-1 is sufficient and was the standard when RFC 6455 was written (2011).

**Q: What happens if the handshake validation fails?**
A: The connection is not established. If `Sec-WebSocket-Accept` doesn't match the expected value, or status is not 101, the client MUST close the connection.

**Q: Explain close codes.**
A: 1000 = Normal, 1001 = Going Away, 1002 = Protocol Error, 1003 = Unsupported Data, 1006 = Abnormal (no close frame), 1007 = Invalid Data, 1008 = Policy Violation, 1009 = Message Too Big, 1010 = Missing Extension, 1011 = Internal Error.

**Q: What is fragmentation?**
A: A message can be split across multiple frames. First frame has opcode + FIN=0, continuation frames have opcode 0x0, last frame has opcode 0x0 + FIN=1. Useful for large messages without knowing size upfront.

### Implementation Questions

**Q: How did you handle multiple clients?**
A: Used `select()` to multiplex I/O across multiple sockets in a single thread. The server socket accepts new connections, client sockets handle data.

**Q: Why not use threads instead of select()?**
A: `select()` is simpler for a lab demo and avoids threading complexity (locks, synchronization). It also directly demonstrates event-driven I/O which is how most WebSocket servers work.

**Q: How do you parse variable-length payload?**
A: If payload length byte is 0-125, that's the actual length. If 126, read next 2 bytes as unsigned 16-bit integer. If 127, read next 8 bytes as unsigned 64-bit integer.

---

## 10. Testing & Demo Plan

### Test Checklist

| # | Test | Expected Result |
|---|------|----------------|
| 1 | Browser connects to server | Handshake completes, server logs "WebSocket connection established" |
| 2 | Type message in browser 1 | Message appears in browser 2 |
| 3 | Type message in browser 2 | Message appears in browser 1 |
| 4 | Open 3+ tabs | All tabs see all messages |
| 5 | Close a tab | Server logs disconnection, other tabs unaffected |
| 6 | Server sends ping | Client responds with pong (check server logs) |
| 7 | Invalid handshake | Server rejects connection |
| 8 | Masking verification | Frame bytes are different from payload (masked) |

### Demo Script

```
1. Start server:  python server.py
2. Open http://localhost:8765 in browser (or open static/index.html)
3. Open second tab
4. In tab 1: type "Hello from tab 1"
5. Show it appears in tab 2
6. In tab 2: type "Hi back!"
7. Show it appears in tab 1
8. Open tab 3, show broadcast works
9. Close tab 1, show server log says "disconnected"
10. Point out in logs: handshake, frame bytes, ping/pong timestamps
```

---

## Quick Reference: Frame Byte Layout

```
Example: Text frame "Hello" (5 bytes), unmasked, FIN=1
  0x81 = 10000001 (FIN=1, opcode=0x01)
  0x05 = 00000101 (MASK=0, length=5)
  0x48 0x65 0x6c 0x6c 0x6f = "Hello"

Example: Text frame "Hello" (5 bytes), masked, FIN=1
  0x81 = 10000001 (FIN=1, opcode=0x01)
  0x85 = 10000101 (MASK=1, length=5)
  0x37 0xfa 0x21 0x3d = masking key
  0x7f 0x9f 0x4d 0x51 0x58 = masked "Hello"
```

---

*Last updated: 2026-03-22*
