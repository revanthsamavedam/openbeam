# Contributing to openbeam

Thanks for stopping by. A few ground rules:

* **Small PRs.** One idea per PR, with tests if it touches the protocol,
  crypto, or transfer paths.
* **The protocol is a contract.** Changes to `docs/PROTOCOL.md` need a
  version bump discussion in the PR — old and new peers should degrade
  gracefully, never corrupt.
* **No new required dependencies** without discussion. The web dashboard
  stays stdlib-only on purpose.
* **Security first.** If you spot something, open an issue (or email the
  maintainer for sensitive reports) before a public PR.
* Run `pytest` — it should be green before you push.

Good first areas: dashboard auth token, `--stealth` mode, transfer resume,
folder sends, BLE discovery experiments.
