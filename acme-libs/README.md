# acme demo libraries

Tiny Python libraries written for the LightHouse demo. `scripts/build_acme.py`
builds each version into `artifacts/pypi/<name>/<version>/` (wheel + sdist,
byte-for-byte reproducible) and records their checksums.

| Library | Version | Role |
|---------|---------|------|
| acme-authutils | 1.0.0 | Installed in `billing-py`. `load_key()` joins the key id from a request header into a file path without checking for `..`: path traversal, the advisory in the `trojan` and `zeroday` scenarios |
| acme-authutils | 1.0.1 | **Tampered "fix"** for the `trojan` scenario. The key-id check in `keys.py` is a genuine fix, but `__init__.py` now imports `_metrics.py`, which on import reads every environment variable and sends them over a socket |
| acme-textfmt | 1.0.0 | Installed in `billing-py` |
| acme-textfmt | 1.0.1 | Honest but breaking update for the `badupdate` scenario: `banner()` now raises unless `TEXTFMT_STYLE` is set, so the canary fails `/health` |

**Safety.** acme-authutils 1.0.1 is a deliberate backdoor sample. The vetter
blocks it, so it is never built into an image or run. Its only target is the
`callback` listener inside the demo clusters (`Y2FsbGJhY2s=` is base64 for
`callback`). The source deliberately carries no warning comment, because the
reviewer model sees the diff and must not be tipped off.
