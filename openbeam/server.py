"""Receiving side: TLS server that accepts files.

Policy knobs:
  auto_accept          -- accept everything (testing / kiosk mode)
  auto_accept_trusted  -- accept without prompting from trusted devices
  on_offer(offer)      -- callback returning True/False; used by CLI prompt
                         and the web UI's pending-offer queue. If it returns
                         None, the offer waits for decide() (web UI flow).

Anything not explicitly accepted is declined. Unknown senders never get
silent auto-accept.
"""
from __future__ import annotations

import base64
import hashlib
import os
import socket
import ssl
import threading
import time
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from . import protocol as P
from .identity import TrustStore, fingerprint, load_or_create_identity

OFFER_TIMEOUT = 120
TRANSFER_TIMEOUT = 600


class OfferDeclined(Exception):
    pass


class BeamServer:
    def __init__(
        self,
        *,
        name: str,
        device_id: str,
        port: int = 0,
        inbox: str | Path | None = None,
        auto_accept: bool = False,
        auto_accept_trusted: bool = False,
        on_offer=None,
        trust: TrustStore | None = None,
    ):
        self.name = name
        self.device_id = device_id
        self.inbox = Path(inbox or Path.home() / "Downloads" / "OpenBeam")
        self.auto_accept = auto_accept
        self.auto_accept_trusted = auto_accept_trusted
        self.on_offer = on_offer
        self.trust = trust or TrustStore()
        self.fp = fingerprint()

        key_path, cert_path = load_or_create_identity()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_path), str(key_path))
        # No TLS-layer client certs: CPython aborts the handshake when a
        # self-signed client cert fails CA verification under CERT_OPTIONAL.
        # Client authentication is done at the app layer instead (challenge /
        # response proving private-key possession, see _session).
        ctx.verify_mode = ssl.CERT_NONE
        self._ctx = ctx

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", port))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]

        self._pending: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> tuple[str, int]:
        self.inbox.mkdir(parents=True, exist_ok=True)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True, name="openbeam-server")
        self._thread.start()
        return "0.0.0.0", self.port

    def stop(self) -> None:
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass

    # -- pending offers (web UI) -------------------------------------------
    def pending_offers(self) -> list[dict]:
        with self._lock:
            return [
                {"token": t, "peer": o["peer"], "filename": o["meta"]["filename"],
                 "size": o["meta"]["size"], "trusted": o["trusted"],
                 "age": round(time.time() - o["at"], 1)}
                for t, o in self._pending.items()
            ]

    def decide(self, token: str, accept: bool) -> bool:
        with self._lock:
            offer = self._pending.get(token)
            if not offer:
                return False
            offer["decision"] = bool(accept)
            offer["event"].set()
            return True

    # -- internals ----------------------------------------------------------
    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            tls = self._ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            conn.close()
            return
        tls.settimeout(TRANSFER_TIMEOUT)
        try:
            self._session(tls)
        except (P.ProtocolError, OSError, ssl.SSLError):
            pass
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def _session(self, tls: ssl.SSLSocket) -> None:
        # -- app-layer mutual authentication --------------------------------
        # 1. client presents its self-signed cert in hello
        hello = P.recv_frame(tls)
        if hello.get("t") != "hello":
            raise P.ProtocolError("expected hello")
        try:
            client_der = base64.b64decode(hello["cert"])
            cert = x509.load_der_x509_certificate(client_der)
        except Exception as e:
            raise P.ProtocolError(f"bad client certificate: {e}") from e
        peer_fp = fingerprint(client_der)
        if hello.get("fp") != peer_fp:
            raise P.ProtocolError("claimed fingerprint does not match presented cert")
        peer_name = str(hello.get("name", "unknown"))[:64]

        # 2. challenge/response: prove possession of the cert's private key
        nonce = os.urandom(32)
        P.send_frame(tls, {"t": "challenge",
                           "nonce": base64.b64encode(nonce).decode()})
        proof = P.recv_frame(tls)
        if proof.get("t") != "proof":
            raise P.ProtocolError("expected proof")
        try:
            sig = base64.b64decode(proof["sig"])
            cert.public_key().verify(sig, nonce + self.fp.encode(),
                                     padding.PKCS1v15(), hashes.SHA256())
        except (InvalidSignature, ValueError) as e:
            raise P.ProtocolError(f"bad signature: {e}") from e

        trusted = self.trust.is_trusted(peer_fp)
        if trusted:
            self.trust.touch(peer_fp)
        P.send_frame(tls, {"t": "welcome", "ok": True, "name": self.name,
                           "id": self.device_id, "fp": self.fp,
                           "ver": P.PROTOCOL_VERSION, "trusted": trusted})

        # -- file offer ------------------------------------------------------
        offer = P.recv_frame(tls)
        if offer.get("t") != "offer":
            raise P.ProtocolError("expected offer")
        meta = {
            "filename": os.path.basename(str(offer.get("filename", "file"))) or "file",
            "size": int(offer.get("size", 0)),
            "sha256": str(offer.get("sha256", "")),
            "mime": str(offer.get("mime", "application/octet-stream"))[:128],
        }
        if meta["size"] < 0 or len(meta["sha256"]) != 64:
            P.send_frame(tls, {"t": "error", "error": "bad offer"})
            return

        accept = self._policy(peer_name, peer_fp, trusted, meta)
        token = uuid.uuid4().hex if accept else ""
        P.send_frame(tls, {"t": "offer_reply", "accept": accept,
                           **({"token": token} if accept else {"reason": "declined"})})
        if not accept:
            return

        data_msg = P.recv_frame(tls)
        if data_msg.get("t") != "data" or data_msg.get("token") != token:
            raise P.ProtocolError("expected data")
        nbytes = int(data_msg.get("nbytes", -1))
        if nbytes != meta["size"] or nbytes < 0:
            P.send_frame(tls, {"t": "error", "error": "size mismatch"})
            return

        dest = self._unique_path(meta["filename"])
        tmp = dest.with_suffix(dest.suffix + ".part")
        with open(tmp, "wb") as f:
            digest = P.recv_stream(tls, f, nbytes)
        if digest != meta["sha256"]:
            tmp.unlink(missing_ok=True)
            P.send_frame(tls, {"t": "done", "ok": False, "error": "checksum mismatch"})
            return
        tmp.rename(dest)
        P.send_frame(tls, {"t": "done", "ok": True, "sha256": digest})

    def _policy(self, peer_name: str, peer_fp: str, trusted: bool, meta: dict) -> bool:
        if self.auto_accept:
            return True
        if trusted and self.auto_accept_trusted:
            return True
        record = {"peer": {"name": peer_name, "fp": peer_fp}, "meta": meta,
                  "trusted": trusted, "at": time.time(),
                  "event": threading.Event(), "decision": None}
        token = uuid.uuid4().hex
        with self._lock:
            self._pending[token] = record
        try:
            decision = None
            if self.on_offer is not None:
                decision = self.on_offer({"token": token, "peer": record["peer"],
                                         "filename": meta["filename"], "size": meta["size"],
                                         "trusted": trusted})
            if decision is None:
                # web-UI flow: wait for decide(), else timeout -> decline
                record["event"].wait(OFFER_TIMEOUT)
                decision = record["decision"]
            return bool(decision)
        finally:
            with self._lock:
                self._pending.pop(token, None)

    def _unique_path(self, filename: str) -> Path:
        dest = self.inbox / filename
        stem, suffix = dest.stem, dest.suffix
        i = 1
        while dest.exists():
            dest = self.inbox / f"{stem} ({i}){suffix}"
            i += 1
        return dest
