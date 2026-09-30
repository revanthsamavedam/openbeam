# How AirDrop actually works (and what openbeam borrows)

> Research notes on Apple's protocols, kept so the design mapping stays
> honest. Last reviewed 2026-09-30.

## AirDrop, layer by layer

*To be filled in from the protocol research pass — the short version:*

1. **Discovery — Bluetooth LE.** A device that enables AirDrop broadcasts BLE
   advertisements containing a truncated hash of the owner's Apple ID /
   phone number / email ("AirDrop ID"). Nearby devices compare the truncated
   hashes against their contacts to decide "Contacts Only" visibility —
   without revealing full identifiers over the air.
2. **Transport — AWDL (Apple Wireless Direct Link).** A proprietary Wi-Fi
   peer-to-peer protocol (custom 802.11 action frames, channel hopping).
   This is the hard part: it needs Apple Wi-Fi firmware/driver support.
   The [OWL project](https://github.com/seemoo-lab/owl) reverse-engineered
   it for macOS/Linux with patched drivers.
3. **Session — TLS over AWDL.** Once peers find each other, AirDrop runs an
   HTTP-like RPC over TLS (plist-encoded, e.g. `/Discover`), negotiates
   the transfer, asks the receiver to accept, then streams the files with
   metadata (thumbnails, UTIs).
4. **Identity — Apple ID.** Trust is rooted in Apple ID certificates and the
   contacts graph, not TOFU.

## Existing open efforts

* **OpenDrop** — Python AirDrop-compatible sender/receiver for Linux; needs a
  compatible Wi-Fi card and is effectively unmaintained.
* **OWL (Open Wireless Link)** — the AWDL reverse engineering; research-grade.

## What openbeam takes from AirDrop

| AirDrop concept              | openbeam equivalent                          |
|------------------------------|----------------------------------------------|
| Nearby discovery             | mDNS/DNS-SD (`_openbeam._tcp.local.`)        |
| Accept/decline per transfer  | offer → accept/decline (CLI prompt / web UI) |
| Encrypted transport          | TLS 1.2+                                     |
| Device identity via certs    | self-signed certs, fingerprint-pinned (TOFU) |
| "Everyone / Contacts Only"   | trusted-only auto-accept; manual approve     |

## What openbeam deliberately does NOT do

* **Wire compatibility with real AirDrop.** That requires AWDL
  (Apple firmware) and Apple ID infrastructure. openbeam is
  *AirDrop-like*, not *AirDrop-compatible* — the same UX over standard
  Wi-Fi any device can speak.
* **BLE discovery.** Needs platform Bluetooth stacks + background modes;
  mDNS covers the LAN case for v1.

## Roadmap notes

* An AWDL experiment (via OWL) could one day let openbeam *see* AirDrop
  advertisements, but full interop is out of scope for v1.
* BLE advertisements for discovery on supported platforms would bring the
  UX closer to AirDrop's "just appears".
