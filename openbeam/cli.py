"""openbeam command line interface."""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import __version__
from .client import TransferRejected, UntrustedPeer, send_file
from .discovery import Discovery
from .identity import (
    TrustStore, device_id, device_name, fingerprint,
    load_or_create_identity, parse_trust_uri, short_fp, trust_uri,
)
from .server import BeamServer


def _bar(done: int, total: int) -> None:
    if total <= 0:
        return
    pct = done * 100 // total
    sys.stdout.write(f"\r  {pct:3d}% ({done}/{total} bytes)")
    sys.stdout.flush()


def cmd_serve(args) -> int:
    name = args.name or device_name()
    did = device_id()
    trust = TrustStore()
    inbox = Path(args.inbox) if args.inbox else None

    web_enabled = not args.no_web

    def on_offer(offer):
        peer, meta = offer["peer"], offer
        tag = "trusted" if offer["trusted"] else "UNTRUSTED"
        print(f"\n📥 Incoming: {meta['filename']} ({meta['size']} bytes) "
              f"from {peer['name']} [{tag}] fp={short_fp(peer['fp'])}")
        if not sys.stdin.isatty():
            if web_enabled:
                print("   → decide in the web UI")
                return None  # wait for browser decision
            print("   → declined (non-interactive; use --auto-accept or enable the web UI)")
            return False
        ans = input("   Accept? [y/N] ").strip().lower()
        if ans == "y" and not offer["trusted"]:
            t = input("   Trust this device from now on? [y/N] ").strip().lower()
            if t == "y":
                trust.trust(peer["fp"], peer["name"])
        return ans == "y"

    beam = BeamServer(name=name, device_id=did, port=args.port, inbox=inbox,
                      auto_accept=args.auto_accept,
                      auto_accept_trusted=args.auto_accept_trusted,
                      on_offer=on_offer, trust=trust)
    host, port = beam.start()
    fp = beam.fp

    disc = Discovery(name, did, port, fp)
    try:
        disc.start()
    except Exception as e:
        print(f"warning: mDNS unavailable ({e}); peers must use host:port", file=sys.stderr)
        disc = None

    web_url = ""
    if web_enabled:
        from .webui import start_web
        web_url = start_web(beam, disc, trust, port=args.web_port)
    else:
        web_url = "(disabled)"

    print(f"🛰  openbeam v{__version__} serving as {name!r} (id {did})")
    print(f"   fingerprint: {fp}")
    print(f"   transfer port: {port}   web UI: {web_url}")
    print(f"   inbox: {beam.inbox}")
    print("   Press Ctrl-C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopping…")
    finally:
        if disc:
            disc.stop()
        beam.stop()
    return 0


def _browse(seconds: float = 4.0):
    did, fp = device_id(), fingerprint()
    disc = Discovery(device_name(), did, 0, fp)
    disc.start()
    try:
        time.sleep(seconds)
        return disc.peers
    finally:
        disc.stop()


def _resolve_peer(spec: str, peers: dict):
    spec = spec.strip()
    if ":" in spec and not spec.startswith("["):
        host, _, port = spec.rpartition(":")
        if port.isdigit():
            return {"id": "", "name": spec, "host": host, "port": int(port), "fp": ""}
    slow = spec.lower()
    for p in peers.values():
        if p.id == spec or p.id.startswith(spec) or p.name.lower() == slow or p.host == spec:
            return {"id": p.id, "name": p.name, "host": p.host, "port": p.port, "fp": p.fp}
    return None


def cmd_send(args) -> int:
    src = Path(args.file)
    if not src.is_file():
        print(f"no such file: {src}", file=sys.stderr)
        return 1
    peers = _browse(args.discover_secs)
    target = None
    if args.to:
        target = _resolve_peer(args.to, peers)
        if not target:
            print(f"unknown peer {args.to!r}; discovered:", file=sys.stderr)
            for p in peers.values():
                print(f"  {p.name}  ({p.host}:{p.port})", file=sys.stderr)
            return 1
    else:
        if not peers:
            print("no peers discovered; use --to host:port", file=sys.stderr)
            return 1
        names = list(peers.values())
        for i, p in enumerate(names):
            print(f"  [{i}] {p.name}  {p.host}:{p.port}  fp={short_fp(p.fp)}")
        try:
            idx = int(input("send to [0]: ").strip() or "0")
            target = {"id": names[idx].id, "name": names[idx].name, "host": names[idx].host,
                      "port": names[idx].port, "fp": names[idx].fp}
        except (ValueError, IndexError, EOFError):
            print("aborted", file=sys.stderr)
            return 1

    trust = TrustStore()

    def on_unknown(fp, peer_name):
        print(f"⚠  unknown device {peer_name!r}  fp={fp}")
        print(f"   full fingerprint: {fp}")
        if args.yes:
            return True
        if not sys.stdin.isatty():
            return False
        return input("   Trust and send? [y/N] ").strip().lower() == "y"

    print(f"➡️  sending {src.name} ({src.stat().st_size} bytes) → {target['name']} …")
    try:
        res = send_file(target["host"], target["port"], src,
                        expected_fp=target.get("fp") or "",
                        trust=trust, on_unknown_peer=on_unknown,
                        progress=_bar)
        print(f"\n✅ sent ({res['sha256'][:12]}…) to {res['peer']}")
        return 0
    except UntrustedPeer as e:
        print(f"\n⛔ {e}", file=sys.stderr)
        return 2
    except TransferRejected as e:
        print(f"\n🙅 receiver declined: {e}", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"\n❌ {e}", file=sys.stderr)
        return 1


def cmd_peers(args) -> int:
    while True:
        peers = _browse(3.0 if args.watch else args.discover_secs)
        if not peers:
            print("(no peers)")
        for p in peers.values():
            print(f"{p.name}  id={p.id}  {p.host}:{p.port}  fp={short_fp(p.fp)}")
        if not args.watch:
            break
        time.sleep(args.watch)
        print("---")
    return 0


def cmd_pair(_args) -> int:
    load_or_create_identity()
    uri = trust_uri(device_name(), device_id(), fingerprint())
    print("Share this with the other device so it can trust you:\n")
    print(f"  {uri}\n")
    try:
        import qrcode
        qr = qrcode.QRCode(border=1)
        qr.add_data(uri)
        qr.print_ascii(invert=True)
    except ImportError:
        print("(install the 'qr' extra for a scannable code: pip install 'openbeam[qr]')")
    print(f"\nfingerprint: {fingerprint()}")
    return 0


def cmd_trust(args) -> int:
    info = parse_trust_uri(args.who)
    fp = info["fp"]
    if len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp.lower()):
        print("not a valid fingerprint or openbeam:// URI", file=sys.stderr)
        return 1
    TrustStore().trust(fp.lower(), args.name or info["name"], info["id"])
    print(f"trusted {short_fp(fp)} ({args.name or info['name'] or 'unnamed'})")
    return 0


def cmd_untrust(args) -> int:
    ok = TrustStore().untrust(args.fp.lower())
    print("removed" if ok else "not found")
    return 0 if ok else 1


def cmd_trusted(_args) -> int:
    ts = TrustStore().all()
    if not ts:
        print("(no trusted devices)")
    for fp, meta in ts.items():
        print(f"{short_fp(fp)}  {meta.get('name', '')}  last seen {meta.get('last_seen', '?')}")
        print(f"  {fp}")
    return 0


def cmd_identity(_args) -> int:
    load_or_create_identity()
    print(f"name:        {device_name()}")
    print(f"id:          {device_id()}")
    print(f"fingerprint: {fingerprint()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="openbeam", description="Open, cross-device file sharing.")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="Advertise this device and receive files")
    s.add_argument("--name", default="")
    s.add_argument("--port", type=int, default=0, help="Transfer port (0 = pick one)")
    s.add_argument("--inbox", default="", help="Where received files land")
    s.add_argument("--web-port", type=int, default=8080)
    s.add_argument("--no-web", action="store_true")
    s.add_argument("--auto-accept", action="store_true", help="Accept everything (kiosk/testing)")
    s.add_argument("--auto-accept-trusted", action="store_true", help="Skip prompt for trusted devices")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("send", help="Send a file to a nearby device")
    s.add_argument("file")
    s.add_argument("--to", default="", help="Peer name, id prefix, or host:port")
    s.add_argument("--yes", action="store_true", help="Trust unknown peers without prompting")
    s.add_argument("--discover-secs", type=float, default=4.0)
    s.set_defaults(fn=cmd_send)

    s = sub.add_parser("peers", help="List discovered devices")
    s.add_argument("--watch", type=float, default=0, metavar="SECS", help="Repeat every SECS seconds")
    s.add_argument("--discover-secs", type=float, default=4.0)
    s.set_defaults(fn=cmd_peers)

    s = sub.add_parser("pair", help="Show a trust code other devices can scan/add")
    s.set_defaults(fn=cmd_pair)

    s = sub.add_parser("trust", help="Trust a device fingerprint or openbeam:// URI")
    s.add_argument("who")
    s.add_argument("--name", default="")
    s.set_defaults(fn=cmd_trust)

    s = sub.add_parser("untrust", help="Remove trust for a fingerprint")
    s.add_argument("fp")
    s.set_defaults(fn=cmd_untrust)

    s = sub.add_parser("trusted", help="List trusted devices")
    s.set_defaults(fn=cmd_trusted)

    s = sub.add_parser("identity", help="Show this device's identity")
    s.set_defaults(fn=cmd_identity)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)
