"""End-to-end transfer tests: real TLS server + client over loopback."""
import hashlib
import os

import pytest

from openbeam import identity as I
from openbeam.client import TransferRejected, UntrustedPeer, send_file
from openbeam.server import BeamServer


@pytest.fixture
def homes(tmp_path, monkeypatch):
    """Isolated OPENBEAM_HOME so tests never touch the real ~/.openbeam."""
    monkeypatch.setenv("OPENBEAM_HOME", str(tmp_path / "ob"))
    return tmp_path


def _server(homes, **kw):
    inbox = homes / "inbox"
    srv = BeamServer(name="receiver", device_id="recv001", port=0, inbox=inbox, **kw)
    srv.start()
    return srv


def _trusted_client_store(server_fp):
    ts = I.TrustStore()
    ts.trust(server_fp, "receiver")
    return ts


def test_happy_path(homes, tmp_path):
    srv = _server(homes, auto_accept=True)
    try:
        src = tmp_path / "hello.txt"
        src.write_bytes(b"hello openbeam " * 1000)
        res = send_file("127.0.0.1", srv.port, src,
                        trust=_trusted_client_store(srv.fp),
                        on_unknown_peer=lambda fp, name: False)
        assert res["ok"]
        received = list(srv.inbox.glob("hello*"))
        assert len(received) == 1
        assert received[0].read_bytes() == src.read_bytes()
        assert res["sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()
    finally:
        srv.stop()


def test_binary_and_empty_files(homes, tmp_path):
    srv = _server(homes, auto_accept=True)
    try:
        for name, data in [("empty.bin", b""), ("rand.bin", bytes(range(256)) * 300)]:
            src = tmp_path / name
            src.write_bytes(data)
            send_file("127.0.0.1", srv.port, src, trust=_trusted_client_store(srv.fp))
            assert (srv.inbox / name).read_bytes() == data
    finally:
        srv.stop()


def test_decline(homes, tmp_path):
    srv = _server(homes, on_offer=lambda offer: False)
    try:
        src = tmp_path / "nope.txt"
        src.write_bytes(b"x")
        with pytest.raises(TransferRejected):
            send_file("127.0.0.1", srv.port, src, trust=_trusted_client_store(srv.fp))
        assert list(srv.inbox.iterdir()) == []
    finally:
        srv.stop()


def test_unknown_peer_blocked_without_consent(homes, tmp_path):
    srv = _server(homes, auto_accept=True)
    try:
        src = tmp_path / "s.txt"
        src.write_bytes(b"x")
        with pytest.raises(UntrustedPeer):
            send_file("127.0.0.1", srv.port, src,
                        trust=I.TrustStore(),  # empty: nobody trusted
                        on_unknown_peer=lambda fp, name: False)
    finally:
        srv.stop()


def test_fingerprint_pin_mismatch(homes, tmp_path):
    srv = _server(homes, auto_accept=True)
    try:
        src = tmp_path / "s.txt"
        src.write_bytes(b"x")
        with pytest.raises(UntrustedPeer):
            send_file("127.0.0.1", srv.port, src,
                        expected_fp="00" * 32,  # wrong pin
                        trust=_trusted_client_store(srv.fp))
    finally:
        srv.stop()


def test_web_decide_flow(homes, tmp_path):
    """Offer waits for decide() (the web-UI flow), then accepts."""
    srv = _server(homes)  # no auto flags, no on_offer -> waits for decide()
    try:
        src = tmp_path / "w.txt"
        src.write_bytes(b"web flow")
        import threading
        result = {}

        def run():
            try:
                result["res"] = send_file("127.0.0.1", srv.port, src,
                                          trust=_trusted_client_store(srv.fp))
            except Exception as e:  # noqa: BLE001
                result["err"] = e

        t = threading.Thread(target=run)
        t.start()
        # wait for the pending offer to appear, then accept it like the web UI
        import time
        deadline = time.time() + 10
        while time.time() < deadline and not srv.pending_offers():
            time.sleep(0.05)
        pending = srv.pending_offers()
        assert len(pending) == 1
        assert srv.decide(pending[0]["token"], True)
        t.join(timeout=15)
        assert result.get("res", {}).get("ok")
        assert (srv.inbox / "w.txt").read_bytes() == b"web flow"
    finally:
        srv.stop()


def test_web_send_path(homes, tmp_path):
    """Browser upload -> daemon -> TLS transfer -> receiver inbox."""
    from openbeam.webui import WebApp

    os.environ["OPENBEAM_HOME"] = str(homes / "obA2")
    alpha = BeamServer(name="alpha", device_id="a1", port=0,
                       inbox=homes / "a2inbox", auto_accept=True)
    alpha.start()
    try:
        os.environ["OPENBEAM_HOME"] = str(homes / "obC2")
        I.load_or_create_identity()

        class Peer:  # noqa: D106
            pass
        p = Peer()
        p.id, p.name, p.host, p.port, p.fp = "a1", "alpha", "127.0.0.1", alpha.port, alpha.fp

        class FakeDiscovery:  # noqa: D106
            @property
            def peers(self):
                return {"a1": p}

        app = WebApp(beam=None, discovery=FakeDiscovery(), trust=I.TrustStore())
        res = app.send_via_browser("a1", "web-test.txt", b"sent from a browser!")
        assert res["ok"], res
        got = list((homes / "a2inbox").glob("*"))
        assert len(got) == 1 and got[0].name == "web-test.txt"
        assert got[0].read_bytes() == b"sent from a browser!"
    finally:
        alpha.stop()


def test_multipart_parser():
    from openbeam.webui import parse_multipart
    boundary = "----WebKitFormBoundaryABC"
    body = (
        b"------WebKitFormBoundaryABC\r\n"
        b'Content-Disposition: form-data; name="peer_id"\r\n\r\n'
        b"peer123\r\n"
        b"------WebKitFormBoundaryABC\r\n"
        b'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n'
        b"Content-Type: text/plain\r\n\r\n"
        b"file-bytes-here\r\n"
        b"------WebKitFormBoundaryABC--\r\n"
    )
    fields = parse_multipart(body, f'multipart/form-data; boundary={boundary}')
    assert fields["peer_id"] == (None, b"peer123")
    assert fields["file"] == ("a.txt", b"file-bytes-here")
