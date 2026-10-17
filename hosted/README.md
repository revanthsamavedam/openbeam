# openbeam online

Hosted version of openbeam: https://openbeam-online.vercel.app

The LAN daemon (`openbeam serve`) can't be hosted as-is — discovery is mDNS
(LAN-only) and its dashboard has no auth. This hosted variant offers two
modes that keep the openbeam feel (share code, explicit approval, SHA-256
verified):

## Live mode (browser-to-browser)

WebRTC data channels via PeerJS. The sender picks a file and gets a 6-char
code; the receiver enters it; the sender taps Accept; the file streams
directly between browsers (DTLS-encrypted) and the receiver verifies its
SHA-256. Nothing is stored on a server; both pages must stay open.
Practical limit ~500 MB (the file is held in memory on both devices).
Signaling defaults to the public PeerJS cloud broker; self-host with
`?broker=host:port`, override ICE/TURN with `?turn=host:port:user:pass`.

## Drop mode (store-and-forward, any network)

For when the other device isn't online, or a network blocks direct
connections. The browser uploads the file straight to Vercel Blob using a
single-use client token issued by `api/blob-upload.js` (HMAC-signed,
1 GB max, `drops/` paths only — a hand-rolled equivalent of the SDK's
`handleUpload`; the token format was mirrored from the `@vercel/blob`
2.8.2 source). `api/register.js` then stores the drop's metadata (name,
size, SHA-256, expiry) as a JSON blob, and `api/resolve.js` looks a code
up again. Functions are dependency-free Node-style handlers calling the
Blob HTTP API directly (`x-api-version: 13`; note the PUT takes the
pathname as a `?pathname=` query parameter plus an
`x-vercel-blob-access: public` header — the URL-path form returns 400).
Drops expire after 24 hours and delete themselves lazily on first lookup
after expiry.

Files here: `index.html` (the whole app), `peerjs.min.js` (vendored
PeerJS 1.5.5), `api/*.js` (drop backend), `package.json` (`type: module`
only), `deploy_mcp.py` (deploys through the connected Vercel connector —
the old REST-token flow is dead, 403; MCP calls must OMIT teamId).

Verification (2026-10-17): drop mode proven end-to-end live — a 200 KB
test file uploaded through the real page (code DPNEWR), resolved via the
API, downloaded back byte-identical (SHA-256 match). Live mode: page,
sender registration, code issue, checksum and the full SDP handshake
verified in real Chromium; an actual WebRTC file crossing could not be
exercised from the build sandbox — its browsers sit on a proxy-only
network where WebRTC UDP cannot run (reproduced with a raw WebRTC
loopback test unrelated to this app).
