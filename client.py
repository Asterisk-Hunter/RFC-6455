"""
RFC 6455 - The WebSocket Protocol - Client Implementation
Computer Networks Lab

Implements:
  1. HTTP Upgrade Handshake (Section 4.1)
  2. Frame Construction with Masking (Section 5.2, 5.3)
  3. Send/Receive Text Messages (Section 6)
  4. Ping/Pong Response (Section 5.5.2, 5.5.3)
  5. Connection Close (Section 7)

Usage:
  python client.py
  python client.py --host localhost --port 8765
  python client.py --name Alice
"""

import socket
import struct
import hashlib
import base64
import os
import threading
import sys
import time

# =============================================================================
# Constants
# =============================================================================

MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OPCODE_CONTINUATION = 0x0
OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA

CLOSE_NORMAL = 1000
CLOSE_GOING_AWAY = 1001


# =============================================================================
# Utility Functions (shared with server)
# =============================================================================

def generate_sec_key():
    """
    Section 4.1 - Generate a random 16-byte nonce, Base64-encoded.
    The value must be a randomly selected 16-byte value that has been
    base64-encoded.
    """
    random_bytes = os.urandom(16)
    return base64.b64encode(random_bytes).decode('utf-8')


def unmask_payload(payload, masking_key):
    """Section 5.3 - XOR unmasking (same as masking, XOR is symmetric)."""
    unmasked = bytearray(len(payload))
    for i in range(len(payload)):
        unmasked[i] = payload[i] ^ masking_key[i % 4]
    return bytes(unmasked)


def mask_payload(payload, masking_key):
    """Mask a payload using the given 4-byte key."""
    masked = bytearray(len(payload))
    for i in range(len(payload)):
        masked[i] = payload[i] ^ masking_key[i % 4]
    return bytes(masked)


def build_frame(opcode, payload, masked=True, fin=True):
    """
    Section 5.2 - Construct a WebSocket frame.

    Client-to-server frames MUST be masked (Section 5.3).
    """
    frame = bytearray()

    # Byte 0: FIN + RSV(0) + Opcode
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


def parse_frame(data):
    """Parse a WebSocket frame from raw bytes."""
    if len(data) < 2:
        return None

    byte0 = data[0]
    byte1 = data[1]

    fin = (byte0 >> 7) & 0x1
    opcode = byte0 & 0x0F
    masked = (byte1 >> 7) & 0x1
    payload_length = byte1 & 0x7F

    offset = 2

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

    masking_key = None
    if masked:
        if len(data) < offset + 4:
            return None
        masking_key = data[offset:offset + 4]
        offset += 4

    if len(data) < offset + payload_length:
        return None

    payload = data[offset:offset + payload_length]

    if masked and masking_key:
        payload = unmask_payload(payload, masking_key)

    return {
        'fin': fin,
        'opcode': opcode,
        'masked': masked,
        'payload_length': payload_length,
        'payload': payload,
        'total_length': offset + payload_length,
    }


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
    """Read a complete WebSocket frame from the socket."""
    header_start = recv_exact(sock, 2)
    if not header_start:
        return None

    byte0 = header_start[0]
    byte1 = header_start[1]

    fin = (byte0 >> 7) & 0x1
    opcode = byte0 & 0x0F
    masked = (byte1 >> 7) & 0x1
    payload_length = byte1 & 0x7F

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

    masking_key = None
    if masked:
        masking_key = recv_exact(sock, 4)
        if not masking_key:
            return None

    payload = b''
    if payload_length > 0:
        payload = recv_exact(sock, payload_length)
        if not payload:
            return None

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
# WebSocket Client
# =============================================================================

class WebSocketClient:
    """
    RFC 6455 WebSocket Client.

    Performs the opening handshake, sends masked frames,
    receives frames, handles ping/pong, and manages close.
    """

    def __init__(self, host='localhost', port=8765, path='/', username=None):
        self.host = host
        self.port = port
        self.path = path
        self.username = username
        self.socket = None
        self.connected = False
        self.running = False
        self.receive_thread = None

    def connect(self):
        """
        Section 4.1 - Establish a WebSocket Connection.

        Steps:
          1. Open TCP connection
          2. Send HTTP Upgrade request
          3. Read server response
          4. Validate Sec-WebSocket-Accept
        """
        # Step 1: Open TCP connection
        print(f"[CLIENT] Connecting to {self.host}:{self.port}...")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        print(f"[CLIENT] TCP connection established")

        # Step 2: Build and send handshake
        sec_key = generate_sec_key()
        handshake = self._build_handshake(sec_key)
        print(f"[CLIENT] Sending handshake...")
        print(f"[CLIENT]   Sec-WebSocket-Key: {sec_key}")
        self.socket.sendall(handshake.encode('utf-8'))

        # Step 3: Read server response
        response = self.socket.recv(4096).decode('utf-8')
        print(f"[CLIENT] Received response:")
        for line in response.split('\r\n'):
            print(f"[CLIENT]   {line}")

        # Step 4: Validate
        valid = self._validate_response(response, sec_key)
        if not valid:
            print("[CLIENT] Handshake validation FAILED")
            self.socket.close()
            return False

        print("[CLIENT] Handshake successful! Connection is OPEN\n")
        self.connected = True

        # Send username to server as first message
        if self.username:
            name_frame = build_frame(
                OPCODE_TEXT,
                f"__NAME__:{self.username}".encode('utf-8'),
                masked=True
            )
            self.socket.sendall(name_frame)

        return True

    def _build_handshake(self, sec_key):
        """
        Section 4.1 - Client Requirements.

        Build the HTTP Upgrade request with all required headers.
        """
        request = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {sec_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
        )

        if self.username:
            request += f"Sec-WebSocket-Protocol: chat\r\n"

        request += "\r\n"
        return request

    def _validate_response(self, response_text, sec_key):
        """
        Section 4.1 - Validate the server's handshake response.

        Checks:
          - Status line is HTTP/1.1 101
          - Upgrade: websocket
          - Connection: Upgrade
          - Sec-WebSocket-Accept matches expected value
        """
        lines = response_text.split('\r\n')

        # Check status line
        if not lines[0].startswith('HTTP/1.1 101'):
            print(f"[CLIENT] Invalid status line: {lines[0]}")
            return False

        # Parse headers
        headers = {}
        for line in lines[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key.lower()] = value

        # Check Upgrade
        if headers.get('upgrade', '').lower() != 'websocket':
            print("[CLIENT] Missing or invalid Upgrade header")
            return False

        # Check Connection
        if 'upgrade' not in headers.get('connection', '').lower():
            print("[CLIENT] Missing Upgrade in Connection header")
            return False

        # Compute expected accept key
        expected_accept = base64.b64encode(
            hashlib.sha1((sec_key + MAGIC_GUID).encode('utf-8')).digest()
        ).decode('utf-8')

        actual_accept = headers.get('sec-websocket-accept', '')

        if actual_accept != expected_accept:
            print(f"[CLIENT] Sec-WebSocket-Accept mismatch!")
            print(f"[CLIENT]   Expected: {expected_accept}")
            print(f"[CLIENT]   Got:      {actual_accept}")
            return False

        return True

    # =========================================================================
    # Send Methods
    # =========================================================================

    def send_text(self, message):
        """Section 6.1 - Send a text frame (masked, as required for clients)."""
        if not self.connected:
            print("[CLIENT] Not connected")
            return False

        frame = build_frame(OPCODE_TEXT, message.encode('utf-8'), masked=True)
        try:
            self.socket.sendall(frame)
            return True
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.connected = False
            return False

    def send_close(self, code=CLOSE_NORMAL, reason=''):
        """Section 7.1.2 - Send a Close frame."""
        if not self.connected:
            return

        payload = struct.pack('!H', code)
        if reason:
            payload += reason.encode('utf-8')

        frame = build_frame(OPCODE_CLOSE, payload, masked=True)
        try:
            self.socket.sendall(frame)
        except OSError:
            pass

    def send_pong(self, payload=b''):
        """Section 5.5.3 - Send a Pong frame in response to a Ping."""
        frame = build_frame(OPCODE_PONG, payload, masked=True)
        try:
            self.socket.sendall(frame)
        except OSError:
            pass

    # =========================================================================
    # Receive Loop
    # =========================================================================

    def start_receiving(self):
        """Start a background thread to receive and display messages."""
        self.running = True
        self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.receive_thread.start()

    def _receive_loop(self):
        """
        Continuously read frames from the server.

        Handles:
          - Text frames: display message
          - Ping frames: respond with Pong
          - Close frames: close connection
        """
        while self.running and self.connected:
            try:
                frame = recv_frame(self.socket)
                if frame is None:
                    print("\n[CLIENT] Connection closed by server")
                    self.connected = False
                    break

                opcode = frame['opcode']
                payload = frame['payload']

                if opcode == OPCODE_TEXT:
                    message = payload.decode('utf-8')
                    print(f"\r{message}")
                    print("You: ", end='', flush=True)

                elif opcode == OPCODE_PING:
                    # Section 5.5.2: MUST respond with Pong
                    print(f"\r[PING from server]")
                    self.send_pong(payload)
                    print("You: ", end='', flush=True)

                elif opcode == OPCODE_PONG:
                    print(f"\r[PONG from server]")
                    print("You: ", end='', flush=True)

                elif opcode == OPCODE_CLOSE:
                    # Section 7: Respond with Close and close connection
                    code = CLOSE_NORMAL
                    reason = ''
                    if len(payload) >= 2:
                        code = struct.unpack('!H', payload[:2])[0]
                        if len(payload) > 2:
                            try:
                                reason = payload[2:].decode('utf-8')
                            except UnicodeDecodeError:
                                reason = '<invalid>'
                    print(f"\r[CLOSE] Server closing: code={code}, reason='{reason}'")
                    self.connected = False
                    break

                elif opcode == OPCODE_BINARY:
                    print(f"\r[BINARY] {len(payload)} bytes received")

            except (ConnectionResetError, OSError):
                print("\n[CLIENT] Connection lost")
                self.connected = False
                break
            except Exception as e:
                print(f"\n[CLIENT] Error: {e}")
                self.connected = False
                break

    # =========================================================================
    # Main Loop
    # =========================================================================

    def run(self):
        """Interactive chat loop."""
        if not self.connect():
            return

        self.start_receiving()

        print("Commands: /quit to exit, /close to send close frame")
        print("-" * 50)

        try:
            while self.connected:
                try:
                    user_input = input("You: ")
                except EOFError:
                    break

                if not self.connected:
                    break

                if user_input.strip() == '/quit':
                    self.send_close(CLOSE_NORMAL, 'User quit')
                    time.sleep(0.5)
                    break

                elif user_input.strip() == '/close':
                    print("[CLIENT] Sending Close frame...")
                    self.send_close(CLOSE_NORMAL, 'Client requested close')
                    time.sleep(0.5)
                    break

                elif user_input.strip():
                    self.send_text(user_input)

        except KeyboardInterrupt:
            print("\n[CLIENT] Interrupted, closing...")
            self.send_close(CLOSE_GOING_AWAY, 'Interrupted')

        finally:
            self.running = False
            self.connected = False
            try:
                self.socket.close()
            except OSError:
                pass
            print("[CLIENT] Disconnected.")


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='RFC 6455 WebSocket Client')
    parser.add_argument('--host', default='localhost', help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=8765, help='Server port (default: 8765)')
    parser.add_argument('--path', default='/', help='WebSocket path (default: /)')
    parser.add_argument('--name', default=None, help='Your username')
    args = parser.parse_args()

    client = WebSocketClient(
        host=args.host,
        port=args.port,
        path=args.path,
        username=args.name
    )
    client.run()
