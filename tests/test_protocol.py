import socket

import pytest

from openbeam import protocol as P


def test_frame_roundtrip():
    a, b = socket.socketpair()
    try:
        P.send_frame(a, {"t": "hello", "n": 42})
        assert P.recv_frame(b) == {"t": "hello", "n": 42}
    finally:
        a.close()
        b.close()


def test_frame_rejects_garbage():
    a, b = socket.socketpair()
    try:
        a.sendall(b"\xff\xff\xff\xff")
        with pytest.raises(P.ProtocolError):
            P.recv_frame(b)
    finally:
        a.close()
        b.close()
