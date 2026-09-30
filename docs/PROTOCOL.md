# openbeam wire protocol v1

All traffic runs inside a single TLS 1.2+ stream (server-authenticated;
the client pins the server's certificate fingerprint, TOFU-style like SSH
host keys). Client authentication is a challenge/response at the app layer —
TLS client certificates are deliberately *not* used, because CPython aborts
the handshake when a self-signed client cert fails CA verification under
`CERT_OPTIONAL`, and TOFU has no CA by design.

## Framing

```
frame      = u32be(length) + payload            # length <= 16 MiB
message    = frame containing a JSON object     # {"t": <type>, ...}
file bytes = a {"t":"data","nbytes":N} message, immediately followed by
             N raw bytes (streamed, never buffered as one frame)
```

Strings are UTF-8. Integers are JSON numbers. `t` is always present.

## Handshake (mutual authentication)

```
C -> S  hello      {t:"hello", id, name, fp, ver, cert}
                   cert: base64(DER) of C's self-signed certificate
                   fp MUST equal hex(sha256(DER)); mismatch -> abort
S -> C  challenge  {t:"challenge", nonce}        # 32 random bytes, base64
C -> S  proof      {t:"proof", sig}              # base64(RSA-PKCS1v15-SHA256
                                                #   (nonce || server_fp_hex))
S -> C  welcome    {t:"welcome", ok, name, id, fp, ver, trusted}
```

* `server_fp_hex` is the hex fingerprint of the server's TLS certificate
  as observed by the client — binding the proof to this exact server.
* The server verifies the signature against the public key in the
  presented certificate. Only then is the fingerprint looked up in the
  trust store (`trusted`).
* The client aborts if `welcome.fp` differs from the fingerprint it
  pinned from the TLS handshake (prevents a confused-deputy swap).

Why challenge/response instead of TLS client certs: a fingerprint is a
*public* identifier (broadcast over mDNS, printed in the UI). Accepting a
bare "my fingerprint is X" claim would let anyone who *saw* X impersonate
its owner. The signature proves possession of the private key, which never
leaves the device.

## Transfer

```
C -> S  offer        {t:"offer", filename, size, sha256, mime}
                     filename: basename only, ≤256 chars (server re-baselines)
                     sha256: hex of the whole file
S -> C  offer_reply  {t:"offer_reply", accept, token?, reason?}
C -> S  data         {t:"data", token, nbytes} + N raw bytes
S -> C  done         {t:"done", ok, sha256?, error?}
S -> C  error        {t:"error", error}          # fatal; close after
```

* The receiver's accept policy is local: `auto_accept`, `auto_accept_trusted`,
  an interactive prompt, or an explicit `decide()` from the web UI.
  Anything not explicitly accepted is declined. Timeouts decline.
* `nbytes` must equal `offer.size`; the receiver streams to
  `<name>.part`, verifies sha256, then atomically renames. Mismatch ->
  the partial file is deleted and `done.ok=false`.
* Name collisions in the inbox are resolved as `name (1).ext`, etc.

## Discovery

mDNS/DNS-SD, service type `_openbeam._tcp.local.`:

* instance name: `<device name> [<device id[:6]>]`
* TXT: `id=<device id>`, `fp=<cert fingerprint hex>`, `v=1`
* port: the actual transfer port (ephemeral by default)

This is the same discovery substrate as Bonjour. AirDrop additionally uses
BLE advertisements + AWDL; see `docs/AIRDROP_PROTOCOL.md` for why openbeam
stops at mDNS.

## Trust model

* First run generates a self-signed RSA-2048 certificate (10-year expiry,
  like an SSH host key) in `~/.openbeam/`.
* Peers are trusted by certificate fingerprint (TOFU). `openbeam pair`
  prints an `openbeam://trust/v1?fp=…&name=…&id=…` URI (+ QR) to exchange
  out-of-band; `openbeam trust` imports it.
* The sender aborts if the receiver's fingerprint changed since trust was
  recorded for a *different* name... (v1: any mismatch vs `--to`'s expected
  fp or a stored entry with a conflicting name aborts; TOFU auto-trust is
  always an explicit user action).
* mDNS TXT records expose the fingerprint — that is fine: the fingerprint
  is an identifier, not a secret. Authentication comes from the
  challenge/response, not from fingerprint secrecy.

## Security properties / non-goals

* Confidentiality + integrity on the wire: TLS 1.2+ (server-auth via
  pinning), sha256 end-to-end file verification.
* No protection against a malicious *trusted* peer (same as AirDrop:
  don't trust devices you don't trust).
* mDNS presence is broadcast in the clear on the LAN (same as Bonjour).
  A future `serve --stealth` could disable advertisement (manual
  `host:port` only).
* Web dashboard binds all interfaces with no auth in v1 — it is meant for
  your own LAN / tailscale. Do not expose it to the internet. (Planned:
  token auth, see README roadmap.)
