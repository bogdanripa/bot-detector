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

## Two modes

The root (`/`) is a chooser linking two modes, each running the same 3-step funnel:

- **`/test` — production mode.** Enforces, **aggressively by default** — it blocks
  anything not clearly `human` (i.e. `suspicious` *or* `automated`; "better block
  than not"). On every navigation the server computes a **server-only** verdict
  (TLS/JA4 + header order + IP, before any client JS) and returns **HTTP 403** (the
  "not allowed" page) at/above the threshold. If a client passes the server gate but
  the full client+server verdict crosses it, the client **redirects to
  `/test/forbidden`**. No report is shown. Tune with `BD_ENFORCE_BAND=suspicious`
  (default, aggressive) or `automated` (conservative). A real browser still passes
  the server gate on first paint — the aggressive threshold catches the *suspicious
  middle* (VMs, odd/stealth configs), not clean browsers.
- **`/debug` — diagnostic mode.** Never blocks or redirects. The result page renders
  the full checklist (per-check status + value + explanation), the contradictions,
  and the overall automation probability / `automationType`.

Verified: `curl /test` → **403** (server-only); headless Chromium on `/test` →
served, then **client-redirected to `/test/forbidden`**; `curl`/browser on
`/debug` → **200** with the full report.

Config via env: `BD_ADDR` (`:8443`), `BD_WEB_DIR` (`honeypot/web`),
`BD_CLIENT_JS` (`packages/client/botdetect.js`), `BD_SCORING` (`config/scoring.json`),
`BD_IPASN_TSV` (optional IP→ASN table, see below).

## IP → ASN (residential vs. hosting)

By default the classifier uses a small built-in list of cloud ranges (zero-config).
For full coverage of every routed IP, load the **free, public-domain**
[iptoasn.com](https://iptoasn.com) table — it's a sorted in-memory interval table
searched by binary search, **~137 ns/lookup over 250k ranges** (allocation-free):

```bash
make fetch-ipdata                                   # downloads data/ip2asn-v4.tsv.gz
BD_IPASN_TSV=data/ip2asn-v4.tsv.gz make run
```

Classification: an IP resolves to its ASN + org, then to `hosting` (datacenter/
cloud), `mobile`, `isp` (residential), or `unknown` (unlisted — *not* assumed
residential). `hosting` sets `isDatacenter` and contributes the mild `ip_datacenter`
signal. A MaxMind `.mmdb` can be plugged in via the `Provider` interface if you
have a license, but the iptoasn table is equally fast and free. Note: **residential
proxies** (real ISP IPs rented by bot operators) will classify as `isp` and are the
honest limit of IP-based signals — which is why it's weighted as a contributor, not
proof.

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

## Deploy

**Full free (GCP) walkthrough: [`deploy/README.md`](deploy/README.md).** In short:

- The server owns TLS (JA3/JA4 capture), so it runs on a **plain VM — never behind
  a CDN / managed-TLS load balancer**, or Layer 3 is lost.
- It's a **single self-contained binary** — web pages, client JS, and scoring
  config are **embedded** (`embed.go`). You copy one file.
- TLS is auto-managed: set `BD_DOMAIN=you.example.com` and it fetches + renews a
  **Let's Encrypt** cert in-process (needs :80 for the ACME challenge). Or bring
  your own with `BD_CERT`/`BD_KEY`. No domain → self-signed (dev).

```bash
make build-linux                 # static linux/amd64 binary → bin/
HOST=user@VM_IP ./deploy/deploy.sh   # build + scp + systemctl restart
```

Recommended target: **GCP always-free `e2-micro`** (us-west1/central1/east1) +
a free **DuckDNS** domain + Let's Encrypt = **$0**. Steps in
[`deploy/README.md`](deploy/README.md).

**Push-to-deploy:** [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml)
tests, builds the static binary, and ships it over SSH on every push (after a
one-time VM setup + three repo secrets — see
[`deploy/README.md` §5](deploy/README.md)). Until the secrets are set it just
runs build+test and skips the deploy step.
