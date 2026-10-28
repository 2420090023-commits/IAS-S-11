"""
file_transfer.py
Small helpers for sending/receiving length-prefixed binary blobs and
strings over a socket. Used by sdes_file_client.py and sdes_file_server.py
for the S-DES whole-file exchange (Task 2).
"""

import struct


def send_bytes(sock, data: bytes):
    sock.sendall(struct.pack(">Q", len(data)))
    sock.sendall(data)


def recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            raise ConnectionError("Socket closed before all data was received")
        buf.extend(chunk)
    return bytes(buf)


def recv_bytes(sock) -> bytes:
    (length,) = struct.unpack(">Q", recv_exact(sock, 8))
    return recv_exact(sock, length)


def send_str(sock, text: str):
    send_bytes(sock, text.encode("utf-8"))


def recv_str(sock) -> str:
    return recv_bytes(sock).decode("utf-8")


def preview_hex(data: bytes, n: int = 32) -> str:
    """First n bytes of data as a hex string, with a '...' marker if truncated."""
    head = data[:n].hex()
    return head + (" ..." if len(data) > n else "")


def preview_text(data: bytes, n: int = 64) -> str:
    """First n bytes of data rendered as printable text (best-effort), for
    files that happen to be text. Non-printable bytes show as '.'"""
    head = data[:n]
    rendered = "".join(chr(b) if 32 <= b < 127 else "." for b in head)
    return rendered + (" ..." if len(data) > n else "")
