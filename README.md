# openbeam 📡

**AirDrop-like file sharing, open source, for any device.** Discover nearby
devices over mDNS, approve each transfer, and send files over mutually
authenticated TLS. No accounts, no cloud relay, no vendor lock-in.

* macOS, Linux, Windows — anywhere Python 3.10+ runs
* **Any phone or tablet with a browser** can send and receive through the
  built-in web dashboard — no app install needed

This is *inspired by* AirDrop, not wire-compatible with it: real AirDrop
needs Apple's AWDL Wi-Fi firmware and Apple ID infrastructure (see
[`docs/AIRDROP_PROTOCOL.md`](docs/AIRDROP_PROTOCOL.md) for the breakdown).
openbeam delivers the same UX — nearby devices, tap-to-send, accept/decline —
over standard Wi-Fi that every device already speaks.

## Quickstart

```bash
pip install openbeam            # or: git clone + pip install -e .
openbeam serve                  # advertise this device, receive files
```

On a second device on the same network:

```bash
openbeam send photo.jpg         # pick the destination from discovered peers
```

Or open the dashboard from any device (phone included):

```
http://<your-device-ip>:8080
```

The dashboard shows nearby devices, lets you send files, approve incoming
requests, and download your inbox — all from the browser.

## Commands

| Command | What it does |
|---|---|
| `openbeam serve` | Advertise + receive. `--auto-accept-trusted`, `--auto-accept`, `--inbox DIR`, `--web-port`, `--no-web` |
| `openbeam send FILE [--to PEER]` | Send a file; PEER is a name, id prefix, or `host:port` |
| `openbeam peers [--watch SECS]` | List discovered devices |
| `openbeam pair` | Show a trust URI + QR code for other devices to add you |
| `openbeam trust <fp-or-uri>` | Trust a device |
| `openbeam identity` | Show this device's fingerprint |

## How it works

1. **Discovery** — each device advertises `_openbeam._tcp.local.` via mDNS
   (the same Bonjour substrate Apple devices use), with its device id and
   certificate fingerprint in TXT records.
2. **Identity** — first run generates a self-signed certificate. Peers are
   identified by certificate fingerprint; trust is TOFU, like SSH host keys.
   `openbeam pair` prints a URI/QR to exchange fingerprints out of band.
3. **Transfer** — the sender offers (filename, size, sha256); the receiver
   accepts or declines (terminal prompt or web UI). Bytes stream over TLS
   1.2+ and are checksum-verified before landing in `~/Downloads/OpenBeam/`.
4. **Mutual auth** — the client pins the server's TLS fingerprint, then
   proves possession of its own private key by signing a server challenge.
   (TLS client certs can't be used: CPython aborts the handshake when a
   self-signed client cert fails CA verification — there is no CA in TOFU.)

Full spec: [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Security model

* Everything is encrypted (TLS) and integrity-checked (sha256 end to end).
* Unknown devices can never receive silent auto-accept; the default is
  explicit approval per transfer.
* A changed fingerprint aborts the transfer — no silent MITM.
* Fingerprints are *identifiers*, not secrets (they're broadcast over mDNS);
  authentication comes from the challenge/response, not fingerprint secrecy.
* ⚠️ The web dashboard has no auth in v1 — keep it on your own LAN.
  Don't expose it to the internet.

## Troubleshooting

* **No peers found** — mDNS needs multicast on the LAN. Guest Wi-Fi networks
  and some corporate networks block it. Fall back to
  `openbeam send file --to 192.168.1.5:18443` (the port is printed by `serve`).
* **Port in use** — `serve --port 0` picks an ephemeral port and advertises it.

## Roadmap

* Dashboard auth token + `--stealth` (no mDNS advertisement) mode
* Resume interrupted transfers; folders (tar-streamed)
* BLE advertisements for discovery, closer to AirDrop's "just appears"
* Native phone apps reusing the same protocol
* AWDL experiment (via OWL) to *observe* real AirDrop traffic

## Contributing

Small, focused PRs welcome. Run the tests before pushing:

```bash
pip install -e ".[test]"
pytest
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Be kind.

## License

MIT — see [`LICENSE`](LICENSE).
