# Running the honeypot (v1)

A working end-to-end implementation of the plan: the Go server libraries + scoring
engine, the `@botdetect/client` browser library, and the 3-step funnel honeypot.

## Prerequisites

- Go 1.24+
- (optional) Node + a Chromium for driving the funnel in tests

## Run

```bash
make run          # builds ./bin/honeypot and serves https://localhost:8443
# or:
go run ./honeypot/server
```

The server generates a **self-signed** cert for local dev and terminates TLS
itself (required for Layer-3 capture), speaking **HTTP/1.1** so header order is
reliably captured. Open <https://localhost:8443/> and accept the cert warning.

Config via env: `BD_ADDR` (`:8443`), `BD_WEB_DIR` (`honeypot/web`),
`BD_CLIENT_JS` (`packages/client/botdetect.js`), `BD_SCORING` (`config/scoring.json`).

## What works

| Piece | Status |
|-------|--------|
| `go/tlscapture` — ClientHello → JA3/JA4 (hand-rolled parser) | ✅ curl and Chrome produce **different** JA4; classified library vs browser |
| `go/httpcapture` — header values + order | ✅ order captured off the decrypted stream; library shapes classified |
| `go/ipasn` — datacenter classification | ✅ offline CIDR list |
| `go/engine` — SignalSet → Report (logistic, bands, contradictions, automationType, critical floor) | ✅ + unit tests |
| `@botdetect/client` — passive Layer 1, CDP-leak probe, scroll/click provenance, form behavior, report render, `autostart` | ✅ |
| honeypot — 3-step funnel, session, cross-nav consistency, funnel-integrity | ✅ |

## Verified behavior

- **plain curl** → `automated` (~82%), type `scripted` (library TLS + minimal Accept + library header order).
- **curl with a spoofed Chrome UA** → `automated` 100%, tripping the critical `tls_ua_vendor_mismatch` (real Chrome can't emit a curl ClientHello).
- **headless Chromium (Playwright)** → `automated` 100%, type `headless`; TLS classified `browser` (GREASE), and the human-like wheel scroll correctly did **not** trip `scroll_teleport`.

## Not yet implemented (documented as future)

- HTTP/2 fingerprint (server is HTTP/1.1-only for reliable header-order capture).
- Node/Python server ports (`node/`, `python/` are stubs — see their READMEs).
- Client-side `@botdetect/engine` JS scoring (server-side scoring only for now).
- A calibrated `scoring.json` from captured fixtures (weights are hand-set defaults).
- Web Bot Auth signature verification (presence check only).

## Deploy (sketch)

For production, replace the self-signed cert with a real one (the server owns TLS,
so **no CDN/managed-TLS proxy in front** or Layer 3 is lost — see docs/01):
point DNS at a VM with a static IP, terminate TLS in-process (autocert or cert
files), open 443, run behind systemd. See docs/02 §6–7. We can pick a concrete
target together.
