"""
RFC 6455 - The WebSocket Protocol - Server Implementation
Computer Networks Lab

Implements:
  1. HTTP Upgrade Handshake (Section 4)
  2. Frame Parsing & Construction (Section 5.2)
  3. Text Messaging with Multi-client Broadcast (Section 5.6, 6)
  4. Ping/Pong Heartbeat (Section 5.5.2, 5.5.3)
  5. Connection Close Handling (Section 5.5.1, 7)
"""

import socket
import select
import struct
import hashlib
import base64
import threading
import time
import os

# =============================================================================
# Constants
# =============================================================================

MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Opcodes (Section 5.2)
OPCODE_CONTINUATION = 0x0
OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA

# Close codes (Section 7.4.1)
CLOSE_NORMAL = 1000
CLOSE_GOING_AWAY = 1001
CLOSE_PROTOCOL_ERROR = 1002
CLOSE_UNSUPPORTED = 1003
CLOSE_ABNORMAL = 1006

# States
STATE_CONNECTING = 0
STATE_OPEN = 1
STATE_CLOSING = 2
STATE_CLOSED = 3


# =============================================================================
# Handshake Functions (Section 4)
# =============================================================================

def generate_accept_key(sec_websocket_key):
    """
    Section 4.2.2 - Compute Sec-WebSocket-Accept.

    Steps:
      1. Concatenate Sec-WebSocket-Key + magic GUID
      2. Compute SHA-1 hash
      3. Base64-encode the result

    Example:
      Key: "dGhlIHNhbXBsZSBub25jZQ=="
      Concat: "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
      SHA-1: 0xb3 0x7a 0x4f 0x2c ...
      Base64: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    """
    concatenated = sec_websocket_key + MAGIC_GUID
    sha1_digest = hashlib.sha1(concatenated.encode('utf-8')).digest()
    accept_key = base64.b64encode(sha1_digest).decode('utf-8')
    return accept_key


def parse_http_request(raw_data):
    """
    Section 4.2.1 - Parse the client's opening handshake.

    Returns (request_line, headers_dict) or None on failure.
    """
    try:
        text = raw_data.decode('utf-8')
    except UnicodeDecodeError:
        return None

    lines = text.split('\r\n')
    if len(lines) < 2:
        return None

    request_line = lines[0]

    # Parse headers into a dict (case-insensitive keys)
    headers = {}
    for line in lines[1:]:
        if ': ' in line:
            key, value = line.split(': ', 1)
            headers[key.lower()] = value

    return request_line, headers


def validate_handshake(request_line, headers):
    """
    Section 4.2.1 - Validate the client handshake.

    Checks:
      - Must be a GET request
      - Must have Upgrade: websocket
      - Must have Connection: Upgrade
      - Must have Sec-WebSocket-Version: 13
      - Must have Sec-WebSocket-Key
    """
    # Check request line
    parts = request_line.split(' ')
    if len(parts) < 3 or parts[0] != 'GET':
        return False, "Not a GET request"

    # Check required headers
    if headers.get('upgrade', '').lower() != 'websocket':
        return False, "Missing or invalid Upgrade header"

    # Connection header can contain multiple values
    connection = headers.get('connection', '').lower()
    if 'upgrade' not in connection:
        return False, "Missing Upgrade in Connection header"

    if headers.get('sec-websocket-version') != '13':
        return False, "Unsupported WebSocket version (need 13)"

    if 'sec-websocket-key' not in headers:
        return False, "Missing Sec-WebSocket-Key"

    return True, "OK"


def build_handshake_response(accept_key, subprotocol=None):
    """
    Section 4.2.2 - Build the server's opening handshake response.

    Returns raw bytes of the HTTP 101 response.
    """
    lines = [
        "HTTP/1.1 101 Switching Protocols",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Accept: {accept_key}",
    ]

    if subprotocol:
        lines.append(f"Sec-WebSocket-Protocol: {subprotocol}")

    lines.append("")  # empty line to end headers
    lines.append("")  # extra CRLF

    return "\r\n".join(lines).encode('utf-8')


# =============================================================================
# Frame Parsing & Construction (Section 5.2)
# =============================================================================

def parse_frame(data):
    """
    Section 5.2 - Parse a WebSocket frame.

    Frame structure:
      Byte 0: FIN(1) RSV1(1) RSV2(1) RSV3(1) Opcode(4)
      Byte 1: MASK(1) PayloadLen(7)
      [Extended payload length: 2 bytes if 126, 8 bytes if 127]
      [Masking key: 4 bytes if MASK=1]
      [Payload data: PayloadLen bytes]

    Returns dict with fin, rsv, opcode, masked, payload_length,
    masking_key, payload, header_length (for reading from stream).
    """
    if len(data) < 2:
        return None

    byte0 = data[0]
    byte1 = data[1]

    fin = (byte0 >> 7) & 0x1
    rsv1 = (byte0 >> 6) & 0x1
    rsv2 = (byte0 >> 5) & 0x1
    rsv3 = (byte0 >> 4) & 0x1
    opcode = byte0 & 0x0F

    masked = (byte1 >> 7) & 0x1
    payload_length = byte1 & 0x7F

    offset = 2

    # Extended payload length
    if payload_length == 126:
        if len(data) < offset + 2:
            return None
        payload_length = struct.unpack('!H', data[offset:offset + 2])[0]
        offset += 2
    elif payload_length == 127:
        if len(data) < offset + 8:
            return None
        payload_length = struct.unpack('!Q', data[offset:offset + 8])[0]
        offset += 8

    # Masking key
    masking_key = None
    if masked:
        if len(data) < offset + 4:
            return None
        masking_key = data[offset:offset + 4]
        offset += 4

    # Ensure we have the full payload
    if len(data) < offset + payload_length:
        return None

    payload = data[offset:offset + payload_length]

    # Unmask if needed (Section 5.3)
    if masked and masking_key:
        payload = unmask_payload(payload, masking_key)

    return {
        'fin': fin,
        'rsv1': rsv1,
        'rsv2': rsv2,
        'rsv3': rsv3,
        'opcode': opcode,
        'masked': masked,
        'payload_length': payload_length,
        'masking_key': masking_key,
        'payload': payload,
        'header_length': offset,
        'total_length': offset + payload_length,
    }


def unmask_payload(payload, masking_key):
    """
    Section 5.3 - Client-to-Server Masking.

    The masking does not affect the length of the payload.
    transformed_octet_i = original_octet_i XOR masking_key_octet_(i MOD 4)
    """
    unmasked = bytearray(len(payload))
    for i in range(len(payload)):
        unmasked[i] = payload[i] ^ masking_key[i % 4]
    return bytes(unmasked)


def mask_payload(payload, masking_key):
    """
    Mask a payload using the given 4-byte key.
    Same XOR operation as unmasking (XOR is symmetric).
    """
    masked = bytearray(len(payload))
    for i in range(len(payload)):
        masked[i] = payload[i] ^ masking_key[i % 4]
    return bytes(masked)


def build_frame(opcode, payload, masked=False, fin=True):
    """
    Section 5.2 - Construct a WebSocket frame.

    Parameters:
      opcode: frame type (OPCODE_TEXT, OPCODE_CLOSE, etc.)
      payload: bytes to send
      masked: if True, apply masking (client-to-server must be masked)
      fin: if True, this is the final fragment

    Returns raw bytes of the complete frame.
    """
    frame = bytearray()

    # Byte 0: FIN + RSV (all 0) + Opcode
    byte0 = (0x80 if fin else 0x00) | opcode
    frame.append(byte0)

    payload_len = len(payload)

    # Byte 1+: MASK bit + Payload length
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

    # Masking key + masked payload
    if masked:
        masking_key = os.urandom(4)
        frame.extend(masking_key)
        frame.extend(mask_payload(payload, masking_key))
    else:
        frame.extend(payload)

    return bytes(frame)


# =============================================================================
# Read a complete frame from a socket (handles partial reads)
# =============================================================================

def recv_exact(sock, num_bytes):
    """Read exactly num_bytes from the socket."""
    data = b''
    while len(data) < num_bytes:
        chunk = sock.recv(num_bytes - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def recv_frame(sock):
    """
    Read a complete WebSocket frame from the socket.
    Handles variable-length headers and partial reads.
    Returns the parsed frame dict, or None if connection closed.
    """
    # Read first 2 bytes
    header_start = recv_exact(sock, 2)
    if not header_start:
        return None

    byte0 = header_start[0]
    byte1 = header_start[1]

    fin = (byte0 >> 7) & 0x1
    opcode = byte0 & 0x0F
    masked = (byte1 >> 7) & 0x1
    payload_length = byte1 & 0x7F

    # Read extended payload length if needed
    if payload_length == 126:
        ext_len = recv_exact(sock, 2)
        if not ext_len:
            return None
        payload_length = struct.unpack('!H', ext_len)[0]

    elif payload_length == 127:
        ext_len = recv_exact(sock, 8)
        if not ext_len:
            return None
        payload_length = struct.unpack('!Q', ext_len)[0]

    # Read masking key
    masking_key = None
    if masked:
        masking_key = recv_exact(sock, 4)
        if not masking_key:
            return None

    # Read payload
    payload = b''
    if payload_length > 0:
        payload = recv_exact(sock, payload_length)
        if not payload:
            return None

    # Unmask
    if masked and masking_key:
        payload = unmask_payload(payload, masking_key)

    return {
        'fin': fin,
        'opcode': opcode,
        'masked': masked,
        'payload_length': payload_length,
        'payload': payload,
    }


# =============================================================================
# WebSocket Connection Class
# =============================================================================

class WebSocketConnection:
    """Represents a single WebSocket connection to a client."""

    def __init__(self, sock, addr):
        self.socket = sock
        self.addr = addr
        self.state = STATE_OPEN
        self.last_ping_time = None
        self.last_pong_time = None
        self.username = f"User-{addr[1]}"  # Simple username based on port
        self.room = "general"  # default room

    def send_frame(self, opcode, payload):
        """Send a frame to this client. Server-to-client frames are NOT masked."""
        if self.state == STATE_CLOSED:
            return False
        frame = build_frame(opcode, payload, masked=False, fin=True)
        try:
            self.socket.sendall(frame)
            return True
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.state = STATE_CLOSED
            return False

    def send_text(self, message):
        """Send a text message to this client."""
        return self.send_frame(OPCODE_TEXT, message.encode('utf-8'))

    def send_ping(self, payload=b''):
        """Section 5.5.2 - Send a Ping frame."""
        self.last_ping_time = time.time()
        return self.send_frame(OPCODE_PING, payload)

    def send_close(self, code=CLOSE_NORMAL, reason=''):
        """Section 5.5.1 - Send a Close frame."""
        payload = struct.pack('!H', code)
        if reason:
            payload += reason.encode('utf-8')
        self.state = STATE_CLOSING
        return self.send_frame(OPCODE_CLOSE, payload)

    def close(self):
        """Force close the connection."""
        self.state = STATE_CLOSED
        try:
            self.socket.close()
        except OSError:
            pass


# =============================================================================
# WebSocket Server
# =============================================================================

class WebSocketServer:
    """
    RFC 6455 WebSocket Server.

    Handles multiple clients using select() for I/O multiplexing.
    Implements all 5 core features + broadcast.
    """

    def __init__(self, host='localhost', port=8765, ping_interval=30):
        self.host = host
        self.port = port
        self.ping_interval = ping_interval  # seconds between pings
        self.server_socket = None
        self.clients = {}  # socket -> WebSocketConnection
        self.running = False

    def start(self):
        """Start the WebSocket server."""
        # Create TCP socket - keep blocking for reliable handshake on Windows
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(1.0)  # timeout so we can check self.running
        self.running = True

        print(f"[SERVER] WebSocket server listening on ws://{self.host}:{self.port}")
        print(f"[SERVER] Open multiple browser tabs to test multi-client chat")
        print(f"[SERVER] Press Ctrl+C to stop\n")

        try:
            self._event_loop()
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")
        finally:
            self.stop()

    def _event_loop(self):
        """Main event loop using select() for multiplexing."""
        last_ping_check = time.time()

        while self.running:
            # Build the list of sockets to monitor for incoming data
            read_sockets = []
            for conn in list(self.clients.values()):
                if conn.state in (STATE_OPEN, STATE_CLOSING):
                    read_sockets.append(conn.socket)

            # select() on Windows requires at least one socket in each list
            # If no clients, just do a timed accept loop instead
            if read_sockets:
                try:
                    readable, _, exceptional = select.select(
                        read_sockets, [], read_sockets, 0.5
                    )
                except (ValueError, OSError):
                    break

                for sock in readable:
                    self._handle_client_data(sock)

                for sock in exceptional:
                    self._remove_client(sock)
            else:
                # No clients yet - just sleep a bit while checking for accepts
                time.sleep(0.1)

            # Accept new connections
            self._try_accept()

            # Send periodic pings (heartbeat)
            now = time.time()
            if now - last_ping_check >= self.ping_interval:
                self._send_pings()
                last_ping_check = now

    def _try_accept(self):
        """Try to accept a new connection (non-blocking)."""
        self.server_socket.settimeout(0.0)
        try:
            while True:
                client_sock, addr = self.server_socket.accept()
                self._do_handshake(client_sock, addr)
        except (BlockingIOError, socket.timeout, OSError):
            pass  # no pending connections
        finally:
            self.server_socket.settimeout(1.0)

    # =========================================================================
    # Handshake (Feature 1)
    # =========================================================================

    def _do_handshake(self, client_sock, addr):
        """
        Feature 1: HTTP Upgrade Handshake.

        Section 4.2 - Server-Side Requirements:
          1. Read the client's opening handshake
          2. Validate required headers
          3. Compute Sec-WebSocket-Accept
          4. Send 101 Switching Protocols response
        """
        print(f"[HANDSHAKE] New TCP connection from {addr}")

        # Read the handshake request (client_sock is still blocking here)
        try:
            data = client_sock.recv(4096)
        except (ConnectionResetError, OSError):
            client_sock.close()
            return

        if not data:
            client_sock.close()
            return

        # Parse HTTP request
        parsed = parse_http_request(data)
        if not parsed:
            print(f"[HANDSHAKE] Failed to parse request from {addr}")
            client_sock.close()
            return

        request_line, headers = parsed

        # Validate handshake
        valid, reason = validate_handshake(request_line, headers)
        if not valid:
            print(f"[HANDSHAKE] Invalid handshake from {addr}: {reason}")
            error_response = "HTTP/1.1 400 Bad Request\r\n\r\n"
            try:
                client_sock.sendall(error_response.encode('utf-8'))
            except OSError:
                pass
            client_sock.close()
            return

        # Compute accept key
        sec_key = headers['sec-websocket-key']
        accept_key = generate_accept_key(sec_key)

        # Build and send response
        response = build_handshake_response(accept_key)
        try:
            client_sock.sendall(response)
        except OSError:
            client_sock.close()
            return

        # Read client's join/name frame (sent right after handshake, socket still blocking)
        try:
            client_sock.settimeout(2.0)
            name_data = client_sock.recv(4096)
            if name_data:
                name_frame = parse_frame(name_data)
                if name_frame and name_frame['opcode'] == OPCODE_TEXT:
                    name_payload = name_frame['payload'].decode('utf-8', errors='ignore')
                    if name_payload.startswith('__JOIN__:'):
                        parts = name_payload.split(':', 2)
                        conn_override_name = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
                        conn_room = parts[2].strip() if len(parts) > 2 and parts[2].strip() else None
                    elif name_payload.startswith('__NAME__:'):
                        conn_override_name = name_payload.split(':', 1)[1].strip() or None
                        conn_room = None
                    else:
                        conn_override_name = None
                        conn_room = None
                else:
                    conn_override_name = None
                    conn_room = None
            else:
                conn_override_name = None
                conn_room = None
        except (socket.timeout, BlockingIOError, OSError):
            conn_override_name = None
            conn_room = None

        # Set non-blocking
        client_sock.settimeout(None)
        client_sock.setblocking(False)

        # Add to clients
        conn = WebSocketConnection(client_sock, addr)
        if conn_override_name:
            conn.username = conn_override_name
        if conn_room:
            conn.room = conn_room
        self.clients[client_sock] = conn

        print(f"[HANDSHAKE] WebSocket connection established with {addr}")
        print(f"[HANDSHAKE]   Key: {sec_key}")
        print(f"[HANDSHAKE]   Accept: {accept_key}")
        print(f"[HANDSHAKE]   User: {conn.username} in room: {conn.room}")

        # Notify others in the same room
        self.broadcast_text(
            f"[Server] {conn.username} joined room '{conn.room}'.",
            exclude=client_sock,
            room=conn.room
        )

    # =========================================================================
    # Frame Handling (Features 2, 3, 4, 5)
    # =========================================================================

    def _handle_client_data(self, sock):
        """
        Feature 2: Frame Parsing
        Dispatch to appropriate handler based on opcode.
        """
        conn = self.clients.get(sock)
        if not conn:
            return

        # Read all available data
        try:
            data = sock.recv(65536)
        except BlockingIOError:
            return  # no data yet (shouldn't happen after select, but safe)
        except (ConnectionResetError, OSError):
            self._remove_client(sock)
            return

        if not data:
            # Connection closed by peer (no close frame)
            print(f"[CLOSE] Connection closed abruptly by {conn.addr}")
            self._remove_client(sock)
            return

        # Parse frame from raw data
        frame = parse_frame(data)
        if not frame:
            print(f"[FRAME] Failed to parse frame from {conn.addr}")
            return

        opcode = frame['opcode']
        payload = frame['payload']

        if opcode == OPCODE_TEXT:
            self._handle_text_frame(conn, payload)

        elif opcode == OPCODE_PONG:
            self._handle_pong(conn, payload)

        elif opcode == OPCODE_PING:
            self._handle_ping(conn, payload)

        elif opcode == OPCODE_CLOSE:
            self._handle_close(conn, payload)

        elif opcode == OPCODE_BINARY:
            print(f"[FRAME] Binary frame from {conn.addr} ({len(payload)} bytes)")

        elif opcode == OPCODE_CONTINUATION:
            print(f"[FRAME] Continuation frame from {conn.addr}")

        else:
            print(f"[FRAME] Unknown opcode {opcode} from {conn.addr}")

    # =========================================================================
    # Feature 3: Text Messaging with Broadcast
    # =========================================================================

    def _handle_text_frame(self, conn, payload):
        """Feature 3: Handle incoming text message and broadcast within room."""
        try:
            message = payload.decode('utf-8')
        except UnicodeDecodeError:
            print(f"[TEXT] Invalid UTF-8 from {conn.addr}")
            return

        print(f"[TEXT] {conn.username}@{conn.room}: {message}")

        # Broadcast to all other clients in the same room
        formatted = f"{conn.username}: {message}"
        self.broadcast_text(formatted, exclude=conn.socket, room=conn.room)

    def broadcast_text(self, message, exclude=None, room=None):
        """Send a text message to all connected clients in the same room (except exclude)."""
        frame = build_frame(OPCODE_TEXT, message.encode('utf-8'), masked=False)

        for sock, conn in list(self.clients.items()):
            if sock == exclude:
                continue
            if conn.state != STATE_OPEN:
                continue
            if room and conn.room != room:
                continue
            try:
                sock.sendall(frame)
            except (BrokenPipeError, ConnectionResetError, OSError):
                self._remove_client(sock)

    # =========================================================================
    # Feature 4: Ping/Pong (Section 5.5.2, 5.5.3)
    # =========================================================================

    def _send_pings(self):
        """Send Ping to all clients as heartbeat."""
        for sock, conn in list(self.clients.items()):
            if conn.state != STATE_OPEN:
                continue
            payload = f"ping-{int(time.time())}".encode('utf-8')
            print(f"[PING] Sending ping to {conn.addr}")
            conn.send_ping(payload)

    def _handle_ping(self, conn, payload):
        """
        Section 5.5.2 - A Ping means the sender wants a Pong.
        Respond immediately with a Pong containing the same payload.
        """
        print(f"[PING] Received ping from {conn.addr}, sending pong")
        conn.send_frame(OPCODE_PONG, payload)

    def _handle_pong(self, conn, payload):
        """Section 5.5.3 - Handle incoming Pong (response to our Ping)."""
        conn.last_pong_time = time.time()
        print(f"[PONG] Received pong from {conn.addr}")

    # =========================================================================
    # Feature 5: Connection Close Handling (Section 5.5.1, 7)
    # =========================================================================

    def _handle_close(self, conn, payload):
        """
        Feature 5: Handle Close frame per Section 7.

        If we haven't sent a Close yet, echo one back.
        Then close the underlying TCP connection.
        """
        # Parse close code and reason from payload
        code = CLOSE_NORMAL
        reason = ''
        if len(payload) >= 2:
            code = struct.unpack('!H', payload[:2])[0]
            if len(payload) > 2:
                try:
                    reason = payload[2:].decode('utf-8')
                except UnicodeDecodeError:
                    reason = '<invalid utf-8>'

        print(f"[CLOSE] Close frame from {conn.addr}: code={code}, reason='{reason}'")

        # If we haven't initiated close, send a Close frame back
        if conn.state == STATE_OPEN:
            conn.send_close(CLOSE_NORMAL, 'Server closing')

        conn.close()
        del self.clients[conn.socket]
        print(f"[CLOSE] Connection with {conn.addr} fully closed")

        # Notify others in the same room
        self.broadcast_text(
            f"[Server] {conn.username} left room '{conn.room}'.",
            exclude=None,
            room=conn.room
        )

    def _remove_client(self, sock):
        """Remove a client connection (abnormal close)."""
        conn = self.clients.pop(sock, None)
        if conn:
            conn.close()
            print(f"[CLOSE] Removed client {conn.addr}")
            self.broadcast_text(
                f"[Server] {conn.username} left room '{conn.room}'.",
                exclude=None,
                room=conn.room
            )

    # =========================================================================
    # Shutdown
    # =========================================================================

    def stop(self):
        """Cleanly shut down the server."""
        self.running = False

        # Send close frames to all clients
        for sock, conn in list(self.clients.items()):
            try:
                conn.send_close(CLOSE_GOING_AWAY, 'Server shutting down')
            except OSError:
                pass
            conn.close()

        self.clients.clear()

        if self.server_socket:
            self.server_socket.close()

        print("[SERVER] Server stopped.")


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == '__main__':
    import argparse
    import os

    # Render sets PORT env var; default to 8765 for local dev
    default_port = int(os.environ.get('PORT', 8765))
    default_host = '0.0.0.0' if os.environ.get('PORT') else 'localhost'

    parser = argparse.ArgumentParser(description='RFC 6455 WebSocket Server')
    parser.add_argument('--host', default=default_host, help='Bind address')
    parser.add_argument('--port', type=int, default=default_port, help='Bind port')
    parser.add_argument('--ping-interval', type=int, default=30, help='Ping interval in seconds (default: 30)')
    args = parser.parse_args()

    server = WebSocketServer(host=args.host, port=args.port, ping_interval=args.ping_interval)
    server.start()
