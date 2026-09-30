"""Sending side: connect to a peer and push a file.

The sender pins the receiver's certificate fingerprint (TOFU). If the peer
is unknown, on_unknown_peer(fp, name) is consulted -- the CLI prompts, the
web UI auto-trusts the peer the user explicitly picked from the LAN list.
A fingerprint that CHANGED for a known name aborts: no silent MITM.
"""
from __future__ import annotations

import base64
import hashlib
import mimetypes
import os
import socket
import ssl
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from . import protocol as P
from .identity import (
    TrustStore, cert_der, device_id, device_name, fingerprint,
    load_or_create_identity, load_private_key,
)


class UntrustedPeer(Exception):
    pass


class TransferRejected(Exception):
    pass


def send_file(
    host: str,
    port: int,
    path: str | Path,
    *,
    expected_fp: str = "",
    trust: TrustStore | None = None,
    on_unknown_peer=None,
    progress=None,
    timeout: int = 30,
) -> dict:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size

    trust = trust or TrustStore()
    key_path, cert_path = load_or_create_identity()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # fingerprint pinning below replaces CA verification
    ctx.load_cert_chain(str(cert_path), str(key_path))

    raw = socket.create_connection((host, port), timeout=timeout)
    tls = ctx.wrap_socket(raw, server_hostname=host)
    tls.settimeout(600)
    try:
        der = tls.getpeercert(binary_form=True)
        if not der:
            raise UntrustedPeer("peer presented no certificate")
        peer_fp = fingerprint(der)

        if expected_fp and peer_fp != expected_fp:
            raise UntrustedPeer("peer fingerprint does not match expected value")

        # -- app-layer mutual authentication --------------------------------
        # Server auth: pin the TLS certificate fingerprint (TOFU, SSH-style).
        # Client auth: present our cert, then sign the server's challenge to
        # prove we hold the private key (TLS client certs can't be used:
        # CPython aborts the handshake when a self-signed client cert fails
        # CA verification under CERT_OPTIONAL).
        my_der = cert_der()
        P.send_frame(tls, {"t": "hello", "id": device_id(), "name": device_name(),
                           "fp": fingerprint(my_der), "ver": P.PROTOCOL_VERSION,
                           "cert": base64.b64encode(my_der).decode()})
        ch = P.recv_frame(tls)
        if ch.get("t") != "challenge":
            raise P.ProtocolError("expected challenge")
        nonce = base64.b64decode(ch["nonce"])
        sig = load_private_key().sign(nonce + peer_fp.encode(),
                                      padding.PKCS1v15(), hashes.SHA256())
        P.send_frame(tls, {"t": "proof", "sig": base64.b64encode(sig).decode()})

        welcome = P.recv_frame(tls)
        if welcome.get("t") != "welcome" or not welcome.get("ok"):
            raise P.ProtocolError("bad welcome")
        # pin check against the fp the server itself claims
        if welcome.get("fp") and welcome["fp"] != peer_fp:
            raise UntrustedPeer("peer certificate does not match its claimed identity")
        peer_name = str(welcome.get("name", "unknown"))

        if not trust.is_trusted(peer_fp):
            allow = on_unknown_peer(peer_fp, peer_name) if on_unknown_peer else False
            if not allow:
                raise UntrustedPeer(f"untrusted peer {peer_name} ({peer_fp[:12]}…)")
            trust.trust(peer_fp, peer_name)
        else:
            trust.touch(peer_fp)

        sha = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(P.CHUNK):
                sha.update(chunk)
        digest = sha.hexdigest()
        mime, _ = mimetypes.guess_type(path.name)

        P.send_frame(tls, {"t": "offer", "filename": path.name, "size": size,
                           "sha256": digest, "mime": mime or "application/octet-stream"})
        reply = P.recv_frame(tls)
        if reply.get("t") != "offer_reply":
            raise P.ProtocolError("expected offer_reply")
        if not reply.get("accept"):
            raise TransferRejected(reply.get("reason", "declined"))
        token = reply["token"]

        P.send_frame(tls, {"t": "data", "token": token, "nbytes": size})
        with open(path, "rb") as f:
            sent_digest = P.send_stream(tls, f, size, progress)
        assert sent_digest == digest

        done = P.recv_frame(tls)
        if done.get("t") != "done" or not done.get("ok"):
            raise P.ProtocolError(f"transfer failed: {done.get('error')}")
        if done.get("sha256") != digest:
            raise P.ProtocolError("receiver checksum mismatch")
        return {"ok": True, "peer": peer_name, "sha256": digest, "size": size}
    finally:
        try:
            tls.close()
        except OSError:
            pass
