"""openbeam wire protocol.

All traffic runs inside a mutually-authenticated TLS stream. The application
framing is deliberately boring:

    frame      = u32be(length) + payload
    message    = frame containing a JSON object, {"t": <type>, ...}
    file bytes = a {"t": "data", "nbytes": N} message, immediately followed
                 by N raw bytes (NOT a frame -- streamed, not buffered).

Message flow (C = sender/client, S = receiver/server):

    C -> S  hello       {t, id, name, fp, ver, cert}
                # cert = base64(DER) of the client's self-signed certificate.
                # fp MUST equal sha256(cert); the server rejects mismatches.
    S -> C  challenge   {t, nonce}      # 32 random bytes, base64
    C -> S  proof       {t, sig}        # RSA PKCS#1 v1.5 + SHA-256 signature over
                                       #   nonce || server_fp_hex, base64
    S -> C  welcome     {t, ok, name, id, fp, ver, trusted}
    C -> S  offer       {t, filename, size, sha256, mime}
    S -> C  offer_reply {t, accept, token?, reason?}
    C -> S  data        {t, token, nbytes} + N raw bytes
    S -> C  done        {t, ok, sha256?, error?}
    S -> C  error       {t, error}              (fatal; close after)

Full spec: docs/PROTOCOL.md
"""
from __future__ import annotations

import json
import struct
import socket

MAX_FRAME = 16 * 1024 * 1024  # JSON control frames only; file bytes stream raw
PROTOCOL_VERSION = 1
CHUNK = 64 * 1024


class ProtocolError(Exception):
    pass


def _recvall(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtocolError("connection closed mid-frame")
        buf += chunk
    return bytes(buf)


def send_frame(sock: socket.socket, obj: dict) -> None:
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_FRAME:
        raise ProtocolError(f"frame too large: {len(payload)}")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_frame(sock: socket.socket) -> dict:
    (length,) = struct.unpack(">I", _recvall(sock, 4))
    if length > MAX_FRAME:
        raise ProtocolError(f"frame too large: {length}")
    try:
        obj = json.loads(_recvall(sock, length).decode("utf-8"))
    except ValueError as e:
        raise ProtocolError(f"bad JSON frame: {e}") from e
    if not isinstance(obj, dict) or "t" not in obj:
        raise ProtocolError("frame is not a message")
    return obj


def send_stream(sock: socket.socket, fobj, nbytes: int, progress=None) -> str:
    """Stream nbytes from fobj; returns hex sha256. Raises on short reads."""
    import hashlib

    h = hashlib.sha256()
    remaining = nbytes
    while remaining > 0:
        chunk = fobj.read(min(CHUNK, remaining))
        if not chunk:
            raise ProtocolError("file shrank mid-transfer")
        sock.sendall(chunk)
        h.update(chunk)
        remaining -= len(chunk)
        if progress:
            progress(nbytes - remaining, nbytes)
    return h.hexdigest()


def recv_stream(sock: socket.socket, fobj, nbytes: int, progress=None) -> str:
    """Receive nbytes into fobj; returns hex sha256."""
    import hashlib

    h = hashlib.sha256()
    remaining = nbytes
    while remaining > 0:
        chunk = sock.recv(min(CHUNK, remaining))
        if not chunk:
            raise ProtocolError("connection closed mid-transfer")
        fobj.write(chunk)
        h.update(chunk)
        remaining -= len(chunk)
        if progress:
            progress(nbytes - remaining, nbytes)
    return h.hexdigest()
