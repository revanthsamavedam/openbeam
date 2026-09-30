"""Web dashboard: any device with a browser can send/receive, no install.

Served by the `openbeam serve` daemon on the LAN. Uses only the Python
standard library (http.server). Browser uploads are capped at 512 MB --
use the CLI for larger files (it streams).
"""
from __future__ import annotations

import html
import json
import mimetypes
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from .client import UntrustedPeer, TransferRejected, send_file as client_send
from .identity import device_id, device_name, short_fp, trust_uri

MAX_WEB_UPLOAD = 512 * 1024 * 1024

PAGE = """<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>openbeam</title>
<style>
body{font-family:-apple-system,system-ui,sans-serif;max-width:720px;margin:0 auto;
padding:16px;background:#0f1115;color:#e8eaf0}
h1{font-size:1.4em}h2{font-size:1.05em;color:#9fb4ff;margin-top:28px}
section{background:#171a21;border:1px solid #262b36;border-radius:12px;padding:14px;margin:12px 0}
.peer,.offer,.file{display:flex;justify-content:space-between;align-items:center;
padding:8px 0;border-bottom:1px solid #22262f}
.peer:last-child,.offer:last-child,.file:last-child{border-bottom:none}
button{background:#3b6cff;border:none;color:#fff;border-radius:8px;padding:8px 14px;
font-size:.9em;cursor:pointer;margin-left:6px}
button.ghost{background:#2a2f3a}button.danger{background:#a33333}
.mono{font-family:ui-monospace,monospace;font-size:.82em;color:#9aa3b2;word-break:break-all}
select,input[type=file]{background:#0f1115;color:#e8eaf0;border:1px solid #333a48;
border-radius:8px;padding:8px;max-width:100%}
#log{white-space:pre-wrap;font-size:.85em;color:#9aa3b2;margin-top:12px}
.badge{font-size:.72em;background:#243b2a;color:#7de2a0;border-radius:6px;padding:2px 8px}
.badge.untrusted{background:#3d2b23;color:#f0a35e}
a{color:#9fb4ff}
</style></head>
<body>
<h1>📡 openbeam</h1>
<section><h2>This device</h2><div id="me"></div></section>
<section><h2>Nearby devices</h2><div id="peers"><i>scanning…</i></div></section>
<section><h2>Send a file</h2>
<select id="peerSel"></select><br><br>
<input type="file" id="fileIn"><br><br>
<button onclick="sendFile()">Send ➡️</button>
<div id="log"></div></section>
<section><h2>Incoming requests</h2><div id="incoming"><i>none</i></div></section>
<section><h2>Inbox</h2><div id="inbox"><i>empty</i></div></section>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function refresh(){
  const r=await fetch('/api/status'); const s=await r.json();
  $('me').innerHTML=`<b>${esc(s.name)}</b><br><span class="mono">${esc(s.fp)}</span>
    <br><span class="mono">trust: ${esc(s.trust_uri)}</span>`;
  $('peers').innerHTML=s.peers.length?s.peers.map(p=>
    `<div class="peer"><span><b>${esc(p.name)}</b><br><span class="mono">${esc(p.short_fp)}</span></span>
     <span class="mono">${esc(p.host)}</span></div>`).join(''):'<i>no devices found yet</i>';
  $('peerSel').innerHTML=s.peers.map(p=>`<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('');
  $('incoming').innerHTML=s.pending.length?s.pending.map(o=>
    `<div class="offer"><span><b>${esc(o.filename)}</b> (${(o.size/1024).toFixed(1)} KB)<br>
     <span class="mono">from ${esc(o.peer.name)}</span>
     <span class="badge ${o.trusted?'':'untrusted'}">${o.trusted?'trusted':'untrusted'}</span></span>
     <span><button onclick="decide('${o.token}',true)">Accept</button>
     <button class="danger" onclick="decide('${o.token}',false)">Decline</button></span></div>`).join('')
    :'<i>none</i>';
  $('inbox').innerHTML=s.inbox.length?s.inbox.map(f=>
    `<div class="file"><span>${esc(f.name)} <span class="mono">(${(f.size/1024).toFixed(1)} KB)</span></span>
     <a href="/api/inbox/${encodeURIComponent(f.name)}" download><button class="ghost">Download</button></a></div>`).join('')
    :'<i>empty</i>';
}
async function decide(token,accept){
  await fetch(`/api/offers/${token}/${accept?'accept':'decline'}`,{method:'POST'});
  refresh();
}
async function sendFile(){
  const f=$('fileIn').files[0], pid=$('peerSel').value;
  if(!f||!pid){$('log').textContent='pick a device and a file first';return;}
  const fd=new FormData(); fd.append('peer_id',pid); fd.append('file',f);
  $('log').textContent='sending '+f.name+' …';
  const r=await fetch('/api/send',{method:'POST',body:fd});
  const j=await r.json();
  $('log').textContent=j.ok?('✅ sent to '+j.peer):('❌ '+(j.error||'failed'));
  refresh();
}
refresh(); setInterval(refresh,2500);
</script></body></html>
"""


def parse_multipart(body: bytes, content_type: str):
    """Minimal multipart/form-data parser -> {name: (filename, data)}."""
    boundary = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part[len("boundary="):].strip('"').encode()
            break
    if not boundary:
        raise ValueError("no boundary")
    fields: dict[str, tuple[str | None, bytes]] = {}
    for chunk in body.split(b"--" + boundary):
        if not chunk.strip() or chunk.strip() == b"--":
            continue
        head, _, data = chunk.partition(b"\r\n\r\n")
        if not head:
            continue
        data = data.removesuffix(b"\r\n")
        name = filename = None
        for line in head.decode("latin1").split("\r\n"):
            low = line.lower()
            if low.startswith("content-disposition:"):
                for seg in line.split(";"):
                    seg = seg.strip()
                    if seg.startswith("name="):
                        name = seg[5:].strip('"')
                    elif seg.startswith("filename="):
                        filename = seg[9:].strip('"')
        if name:
            fields[name] = (filename, data)
    return fields


class _Handler(BaseHTTPRequestHandler):
    app = None  # set by start_web

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        app = self.app
        if self.path == "/":
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/status":
            self._json(app.status())
        elif self.path.startswith("/api/inbox/"):
            app.serve_inbox_file(self, unquote(self.path[len("/api/inbox/"):]))
        else:
            self._json({"ok": False, "error": "not found"}, 404)

    def do_POST(self):
        app = self.app
        if self.path == "/api/send":
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_WEB_UPLOAD:
                self._json({"ok": False, "error": "file too large for web upload (use the CLI)"}, 413)
                return
            try:
                fields = parse_multipart(self.rfile.read(length),
                                         self.headers.get("Content-Type", ""))
            except ValueError:
                self._json({"ok": False, "error": "bad upload encoding"}, 400)
                return
            peer_id = fields.get("peer_id", (None, b""))[1].decode(errors="replace")
            filename, data = fields.get("file", (None, b""))
            if not peer_id or not data:
                self._json({"ok": False, "error": "need a device and a file"}, 400)
                return
            self._json(app.send_via_browser(peer_id, filename or "upload.bin", data))
        elif self.path.startswith("/api/offers/"):
            parts = self.path.strip("/").split("/")
            if len(parts) == 4 and parts[3] in ("accept", "decline"):
                ok = app.beam.decide(parts[2], parts[3] == "accept")
                self._json({"ok": ok})
            else:
                self._json({"ok": False}, 404)
        else:
            self._json({"ok": False, "error": "not found"}, 404)


class WebApp:
    def __init__(self, beam, discovery, trust):
        self.beam = beam
        self.discovery = discovery
        self.trust = trust

    def status(self):
        peers = []
        if self.discovery:
            for p in self.discovery.peers.values():
                peers.append({"id": p.id, "name": p.name, "host": p.host,
                              "port": p.port, "fp": p.fp, "short_fp": short_fp(p.fp)})
        inbox = []
        for f in sorted(self.beam.inbox.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if f.is_file() and not f.name.endswith(".part"):
                inbox.append({"name": f.name, "size": f.stat().st_size,
                              "mtime": f.stat().st_mtime})
        return {"name": self.beam.name, "id": device_id(), "fp": self.beam.fp,
                "short_fp": short_fp(self.beam.fp),
                "trust_uri": trust_uri(self.beam.name, device_id(), self.beam.fp),
                "peers": peers, "pending": self.beam.pending_offers(), "inbox": inbox}

    def serve_inbox_file(self, handler: _Handler, name: str):
        target = (self.beam.inbox / name).resolve()
        try:
            target.relative_to(self.beam.inbox.resolve())
        except ValueError:
            handler._json({"ok": False}, 404)
            return
        if not target.is_file():
            handler._json({"ok": False}, 404)
            return
        mime, _ = mimetypes.guess_type(target.name)
        handler.send_response(200)
        handler.send_header("Content-Type", mime or "application/octet-stream")
        handler.send_header("Content-Length", str(target.stat().st_size))
        handler.send_header("Content-Disposition", f'attachment; filename="{target.name}"')
        handler.end_headers()
        with open(target, "rb") as f:
            while chunk := f.read(65536):
                handler.wfile.write(chunk)

    def send_via_browser(self, peer_id: str, filename: str, data: bytes):
        if not self.discovery:
            return {"ok": False, "error": "discovery unavailable"}
        peer = self.discovery.peers.get(peer_id)
        if not peer:
            return {"ok": False, "error": "device not found (still nearby?)"}
        import shutil
        import tempfile
        safe = "".join(c for c in filename if c.isalnum() or c in "._- ")[:128] or "upload.bin"
        tmpdir = Path(tempfile.mkdtemp(prefix="openbeam-web-"))
        tmp = tmpdir / safe
        try:
            tmp.write_bytes(data)
            # The user explicitly picked this LAN peer in the UI: TOFU-trust it.
            res = client_send(peer.host, peer.port, tmp,
                              expected_fp=peer.fp, trust=self.trust,
                              on_unknown_peer=lambda fp, name: True)
            return {"ok": True, "peer": res["peer"], "sha256": res["sha256"]}
        except (UntrustedPeer, TransferRejected) as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


def start_web(beam, discovery, trust, port: int = 8080) -> str:
    """Start the dashboard in a background thread; returns its URL."""
    _Handler.app = WebApp(beam, discovery, trust)
    server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True, name="openbeam-web").start()
    return f"http://localhost:{server.server_port}  (LAN: http://<this-device-ip>:{server.server_port})"
