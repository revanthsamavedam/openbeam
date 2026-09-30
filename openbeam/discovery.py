"""mDNS discovery (Bonjour-compatible).

Each device advertises `_openbeam._tcp.local.` with its device id and cert
fingerprint in TXT records, and browses for others. This is the same
discovery substrate AirDrop-adjacent Apple services use (Bonjour); AirDrop
itself layers BLE + AWDL on top, which needs Apple hardware -- see
docs/AIRDROP_PROTOCOL.md for why we stop at mDNS.
"""
from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field

from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser, ServiceStateChange

SERVICE_TYPE = "_openbeam._tcp.local."


@dataclass
class Peer:
    id: str
    name: str
    host: str
    port: int
    fp: str
    last_seen: float = field(default_factory=time.time)


def _lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no traffic sent; just picks the route's source IP
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class Discovery:
    def __init__(self, name: str, device_id: str, port: int, fp: str):
        self.name = name
        self.device_id = device_id
        self.port = port
        self.fp = fp
        self._zc: Zeroconf | None = None
        self._browser: ServiceBrowser | None = None
        self._info: ServiceInfo | None = None
        self._lock = threading.Lock()
        self._peers: dict[str, Peer] = {}

    # -- advertisement ----------------------------------------------------
    def start(self) -> None:
        self._zc = Zeroconf()
        instance = f"{self.name} [{self.device_id[:6]}]"
        self._info = ServiceInfo(
            SERVICE_TYPE,
            f"{instance}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(_lan_ip())],
            port=self.port,
            properties={b"id": self.device_id.encode(), b"fp": self.fp.encode(), b"v": b"1"},
            server=f"{socket.gethostname()}.local.",
        )
        self._zc.register_service(self._info)
        self._browser = ServiceBrowser(self._zc, SERVICE_TYPE, handlers=[self._on_change])

    def _on_change(self, zc: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange) -> None:
        if state_change is ServiceStateChange.Removed:
            with self._lock:
                for pid, peer in list(self._peers.items()):
                    if f"{peer.name} [{peer.id[:6]}].{service_type}" == name:
                        del self._peers[pid]
            return
        info = zc.get_service_info(service_type, name)
        if not info:
            return
        try:
            props = {k.decode(): v.decode() for k, v in info.properties.items()}
            pid = props.get("id", "")
            if not pid or pid == self.device_id:
                return  # ignore ourselves
            addrs = info.parsed_addresses()
            if not addrs:
                return
            peer = Peer(id=pid, name=name[: -len(service_type) - 1].rsplit(" [", 1)[0],
                        host=addrs[0], port=info.port, fp=props.get("fp", ""))
            with self._lock:
                self._peers[pid] = peer
        except (ValueError, IndexError, UnicodeDecodeError):
            pass

    @property
    def peers(self) -> dict[str, Peer]:
        with self._lock:
            return dict(self._peers)

    def stop(self) -> None:
        try:
            if self._zc and self._info:
                self._zc.unregister_service(self._info)
            if self._zc:
                self._zc.close()
        except Exception:
            pass
        finally:
            self._zc = None
