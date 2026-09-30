"""Device identity and trust store.

Every device generates a self-signed certificate on first run. Peers are
identified by the SHA-256 fingerprint of that certificate -- no certificate
authority, no accounts, no Apple ID. Trust is TOFU (trust on first use),
the same model SSH uses for host keys.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import socket
import uuid
from pathlib import Path
from urllib.parse import quote, unquote, urlparse, parse_qsl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _home() -> Path:
    return Path(os.environ.get("OPENBEAM_HOME", Path.home() / ".openbeam"))


def key_file() -> Path:
    return _home() / "identity_key.pem"


def cert_file() -> Path:
    return _home() / "identity_cert.pem"


def device_file() -> Path:
    return _home() / "device.json"


def trust_file() -> Path:
    return _home() / "trusted.json"


def _ensure_home() -> Path:
    home = _home()
    home.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(home, 0o700)
    except OSError:
        pass
    return home


def device_name() -> str:
    try:
        return socket.gethostname().split(".")[0] or "openbeam"
    except OSError:
        return "openbeam"


def device_id() -> str:
    """Stable per-device id, persisted on first run."""
    _ensure_home()
    df = device_file()
    if df.exists():
        try:
            return json.loads(df.read_text())["id"]
        except (ValueError, KeyError):
            pass
    did = uuid.uuid4().hex[:12]
    df.write_text(json.dumps({"id": did, "name": device_name()}))
    return did


def load_or_create_identity() -> tuple[Path, Path]:
    """Return (key_path, cert_path), generating a self-signed cert on first run."""
    _ensure_home()
    kf, cf = key_file(), cert_file()
    if kf.exists() and cf.exists():
        return kf, cf
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "openbeam")])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=3650))  # 10 years, like SSH host keys
        .sign(key, hashes.SHA256())
    )
    kf.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(kf, 0o600)
    return kf, cf


def cert_der(cert_path: Path | None = None) -> bytes:
    cp = cert_path or load_or_create_identity()[1]
    cert = x509.load_pem_x509_certificate(Path(cp).read_bytes())
    return cert.public_bytes(serialization.Encoding.DER)


def fingerprint(der: bytes | None = None) -> str:
    """SHA-256 fingerprint (hex) of a DER certificate. Defaults to this device."""
    return hashlib.sha256(der if der is not None else cert_der()).hexdigest()


def load_private_key():
    """Load this device's private key (generating the identity first if needed)."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    kf, _ = load_or_create_identity()
    return load_pem_private_key(kf.read_bytes(), password=None)


def short_fp(fp: str) -> str:
    return f"{fp[:8]}…{fp[-6:]}" if len(fp) > 16 else fp


def trust_uri(name: str, did: str, fp: str) -> str:
    return f"openbeam://trust/v1?fp={fp}&name={quote(name)}&id={quote(did)}"


def parse_trust_uri(uri: str) -> dict:
    """Accept a full openbeam:// URI or a bare 64-hex fingerprint."""
    uri = uri.strip()
    if uri.startswith("openbeam://"):
        q = dict(parse_qsl(urlparse(uri).query))
        fp = q.get("fp", "")
        return {"fp": fp, "name": unquote(q.get("name", "")), "id": q.get("id", "")}
    return {"fp": uri, "name": "", "id": ""}


class TrustStore:
    """TOFU trust store: fingerprint -> {name, id, added, last_seen}."""

    def __init__(self, path: Path | None = None):
        self.path = path or trust_file()
        _ensure_home()
        self._data: dict[str, dict] = {}
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except ValueError:
                self._data = {}

    def save(self) -> None:
        self.path.write_text(json.dumps(self._data, indent=2))

    def is_trusted(self, fp: str) -> bool:
        return fp in self._data

    def trust(self, fp: str, name: str = "", did: str = "") -> None:
        now = _dt.datetime.now(_dt.timezone.utc).isoformat()
        entry = self._data.get(fp, {})
        entry.update({"name": name or entry.get("name", ""), "id": did or entry.get("id", "")})
        entry.setdefault("added", now)
        entry["last_seen"] = now
        self._data[fp] = entry
        self.save()

    def untrust(self, fp: str) -> bool:
        if fp in self._data:
            del self._data[fp]
            self.save()
            return True
        return False

    def touch(self, fp: str) -> None:
        if fp in self._data:
            self._data[fp]["last_seen"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
            self.save()

    def name_of(self, fp: str) -> str:
        return self._data.get(fp, {}).get("name", "")

    def all(self) -> dict[str, dict]:
        return dict(self._data)
