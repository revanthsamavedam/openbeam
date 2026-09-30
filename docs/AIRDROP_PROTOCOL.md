# How AirDrop actually works (and what openbeam borrows)

> Protocol research notes, verified via web search 2026-09-30. Kept so the
> design mapping stays honest.

## 1. Discovery: BLE doorbell → AWDL

AirDrop keeps Wi-Fi asleep and uses **Bluetooth LE as a doorbell**. When the
share sheet opens, the device broadcasts an Apple Continuity advertisement
(company ID `0x004C`, sub-type `0x05`) containing **truncated SHA-256 hashes
of the sender's contact identifiers** (historically the top 16 bits of
`SHA256(email + phone)`). Receivers match those hashes against their address
book — on a match (or in "Everyone" mode) they wake their AWDL interface.

**AWDL (Apple Wireless Direct Link)** is Apple's proprietary peer-to-peer
Wi-Fi: master/peer election and synchronization happen via 802.11
**vendor-specific action frames** on fixed "social channels" (ch 6 @ 2.4 GHz,
ch 44 @ 5 GHz). Peers align on availability windows via TLV control frames;
service discovery rides inside those frames (Bonjour `_airdrop._tcp`
records); IPv6 link-local (`fe80::`, EUI-64 derived) comes up over the
virtual `awdl0` interface. **AWDL itself has no encryption or
authentication — frames go in the clear.**

**OWL (Open Wireless Link, seemoo-lab/owl)** is the C-based open
re-implementation of AWDL for Linux/macOS (GPL): user-space via Netlink,
exposes a virtual interface, does the election/sync dance with real Apple
hardware. Status: experimental, reverse-engineered, incomplete — and Apple
drifts the protocol (channel-sequence behavior changed on iOS 26). 2026
community forks (e.g. jedbillyb/owl) add monitor-mode workarounds for
MediaTek chips (MT7921): hackable, but hardware-finicky.

## 2. Transfer: plain HTTPS over AWDL

Once IPv6 is up, the AirDrop app protocol is strikingly ordinary: **TLS
1.2/1.3 over AWDL IPv6**, sender connects to the receiver on **TCP 8770**,
then HTTP POSTs with binary-plist bodies:

* **`/Discover`** — identity/service query; status codes encode the mode:
  100 (Everyone), 200 (contact matched), 401 (contacts-only, no match)
* **`/Hello`** — handshake / keepalive
* **`/Ask`** — sender describes file(s) + thumbnail metadata; the receiver
  prompts "Accept / Decline"; iOS 18+ uses chunked encoding with no
  Content-Length (a known OpenDrop bug class)
* **`/Upload`** — file bytes on the *same TLS connection* as Ask, must carry
  the `TransferID` from `/Ask`; legacy `application/x-cpio`, iOS 18+ uses
  **`application/x-dvzip`** (framed zlib blocks → ODC CPIO archive,
  `070707` magic)
* **`/Exchange`, `/SharedIdentity`, `/Error`** — identity/certificate
  exchange and control

Fragility notes from the field: Apple devices reject malformed framings
silently (TLS close, no HTTP error); a missing `TransferID` hard-blocks
delivery.

## 3. Identity

* **Everyone mode:** no identity verification at all — any device in AWDL
  range can open TLS and talk to the HTTP API. This is the surface
  open-source implementations exploit.
* **Contacts Only:** each Apple ID is bound by an **Apple-signed
  certificate** to its contact identifiers; devices exchange certs + SHA-256
  hashes of identifiers and each side checks them against its local contacts
  (mutual contact matching). Newer iOS (26.2 beta) adds **PIN pairing** —
  a 30-day trusted pairing without contacts; Everyone mode auto-reverts to
  Contacts Only after ~10 minutes.

## 4. Open-source implementations (2026 status)

* **OpenDrop** (seemoo-lab/opendrop, Python, GPL): the canonical
  HTTP/plist-layer implementation. Runs on macOS (native `awdl0`) or Linux
  via OWL; needs a Wi-Fi adapter OWL supports (monitor mode, ideally
  concurrent monitor+managed). Active forks: a GUI, and `opendrop-rs` /
  `luftlift-rs`, a Rust rewrite with detailed protocol docs.
* **airdrop-mt7921** (jedbillyb, 2026): the freshest working reference —
  proved **both directions** against iOS 26 (byte-exact photo receive,
  successful send), at poor throughput (~45–67 kB/s) with occasional
  dropped transfer tails.
* **What works:** Everyone-mode send/receive against real iPhones —
  demonstrably, in 2026, with enough hacking.
* **What doesn't:** Contacts Only (impossible without Apple's signing key),
  reliable throughput, robustness across iOS version drift.

## 5. Hard blockers for wire compatibility

1. **AWDL in firmware/drivers** — no mainstream Wi-Fi stack implements it;
   you need monitor mode + user-space AWDL (OWL) or Apple silicon. Most
   chips can't do it; some can't do concurrent monitor+managed (kills normal
   Wi-Fi during transfer).
2. **Apple ID infrastructure** — Contacts Only needs an Apple-signed
   identity record: genuinely unforgeable. Open devices are forever
   Everyone-mode, and iOS silently reverts to Contacts Only after 10 min.
3. **Undocumented, drifting protocol** — chunked-only POSTs, dvzip,
   TransferID semantics change between iOS releases; open implementations
   chase by capture-and-diff.
4. **BLE doorbell asymmetry** — a non-Apple device can craft Continuity
   advertisements but can never emit genuine truncated Apple-ID hashes.

## Feasibility verdict

**Everyone-mode wire compatibility: feasible but fragile** — demonstrated
end-to-end on Linux in 2026, gated on Wi-Fi chip support, brittle across
iOS updates. **Full compatibility incl. Contacts Only: not feasible** —
Apple's signed identity records are a hard cryptographic blocker.

## What openbeam takes from AirDrop

| AirDrop concept              | openbeam equivalent                          |
|------------------------------|----------------------------------------------|
| Nearby discovery             | mDNS/DNS-SD (`_openbeam._tcp.local.`)        |
| Accept/decline per transfer  | offer → accept/decline (CLI prompt / web UI) |
| Encrypted transport          | TLS 1.2+                                     |
| Device identity via certs    | self-signed certs, fingerprint-pinned (TOFU) |
| "Everyone / Contacts Only"   | trusted-only auto-accept; manual approve     |

## What openbeam deliberately does NOT do

* **Wire compatibility with real AirDrop.** Per the verdict above, that's a
  fragile, hardware-gated, Apple-drift-chasing project — a different repo
  (see OpenDrop + OWL). openbeam is *AirDrop-like*, not *AirDrop-compatible*:
  the same UX over standard Wi-Fi any device can speak.
* **BLE discovery.** Needs platform Bluetooth stacks + background modes;
  mDNS covers the LAN case for v1.

## Roadmap notes

* BLE advertisements for discovery on supported platforms would bring the UX
  closer to AirDrop's "just appears".
* An AWDL experiment (via OWL) could one day let openbeam *observe* real
  AirDrop traffic — out of scope for v1.
