# 10 — Privacy, Security & Abuse

A tool that computes fingerprints must hold itself to a higher privacy standard
than the systems it diagnoses. The governing principle: **the tool reports to the
visitor about themselves and forgets them.**

---

## 1. Data handling & privacy

### 1.1 Statelessness by default

- The report is computed per request and returned to the caller. **Nothing is
  persisted** beyond the 60-second correlation nonce (Topology B), which holds a
  UUID and a transport report and self-expires.
- No fingerprint database, no cross-session identity, no cookies beyond an
  optional single probe cookie (which is functional, not tracking, and disclosed).
- No third-party requests from the frontend (see [docs/08 §6](08-frontend-ui.md#6-keeping-the-frontend-fingerprint-clean)),
  so no data leaks to CDNs/analytics.

### 1.2 What counts as personal data

Fingerprints (canvas/audio/WebGL hashes, IP, font list) are **personal data /
online identifiers** under GDPR and similar regimes. Because we compute them:

- **Disclose** clearly, on the page, what is collected and that it's shown back to
  the visitor and not stored. A short, plain-language privacy note in the footer,
  linking to a fuller policy.
- **Do not transmit typed content** from the behavioral test input — only timing
  metrics. Make that explicit in the UI.
- **IP handling:** used transiently for ASN/geo lookup and shown in the report;
  not logged with the fingerprint in a way that builds a profile. If you log for
  ops, truncate/anonymize the IP (e.g. drop the last octet) in persistent logs.
- If you ever add opt-in persistence (e.g. "save this report to compare later"),
  it must be **explicit, disclosed, and deletable** — the original plan's gotcha:
  "don't silently persist fingerprints beyond the session unless that's an
  intended, disclosed feature."

### 1.3 Legal posture

- Ship a `PRIVACY.md` and surface it in the UI.
- Because it's a self-diagnostic (visitor inspects themselves), the processing
  basis is straightforward, but still: disclose, minimize, don't retain.
- Add a clear **scope statement** (from [docs/00](00-overview.md)): diagnostic
  only; no bypass/evasion/tracking.

---

## 2. Abuse & rate limiting

The endpoint accepts POSTed JSON and does per-request work (ASN lookup, scoring).
Protect it without harming the diagnostic use case.

| Control | Setting | Rationale |
|---------|---------|-----------|
| Body size cap | 256 KiB, return `413` above | Layer-1 payloads are small; cap stops abuse. |
| Rate limit | Per-IP token bucket (e.g. 30 analyze/min) → `429` with `retryAfterMs` | The tool is interactive; humans re-run occasionally, not dozens of times a second. |
| Nonce single-use + 60s TTL | Enforced in the store | Prevents replay and unbounded nonce accumulation. |
| CORS locked to app origin (probe) | `Access-Control-Allow-Origin: https://app.example.com` | The probe is not a general-purpose fingerprint API. |
| No open JA3/JA4 API | The probe's `/result` requires the server-to-server bearer token | Don't become a free TLS-fingerprinting service for others' scraping. |
| Timeouts | Read/write/idle timeouts on both servers | Slowloris and hung-connection resistance. |

### 2.1 Don't build an evasion oracle

A subtle abuse vector: a stealth-tooling author could hammer the tool to
**tune their evasion** ("did my patch remove the tell?"). Mitigations, in line
with the non-goals:

- The report explains *why* a signal is suspicious (educational) but does **not**
  ship copy-paste evasion recipes.
- Rate limiting blunts automated tuning loops.
- No public bulk API; the report is per-interactive-session.
- This is a soft boundary — the tool is fundamentally a mirror, and a mirror can
  be used to check your disguise. We accept the educational framing and refuse to
  package evasion, rather than pretending the information is secret.

---

## 3. Application security

| Concern | Control |
|---------|---------|
| Input validation | Strictly parse Layer-1 JSON against a schema; reject unknown/oversized fields; never `eval` or reflect client input into HTML unescaped. |
| XSS | The report renders captured values (including a client-controlled User-Agent) — **escape everything** on render; the UI builds DOM via `textContent`, never `innerHTML` with raw values. |
| CSP | `default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'` — self-contained frontend makes this strict CSP easy. |
| Header injection | When echoing header values into the report, treat them as opaque strings; don't reflect into response headers. |
| SSRF | The only outbound calls are the app→probe `/result` (fixed origin) and optional ASN/geo lookups (fixed provider) — no client-controlled URLs are fetched. |
| Secrets | The app↔probe shared bearer token lives in env/secret manager, never in the repo or client. |
| TLS | Probe uses modern TLS config (the ClientHello it *serves* is irrelevant; the one it *reads* is the client's). App uses the GFE's managed TLS. |
| Dependency surface | Minimal Go deps (utls, x/net/http2, an ASN lib); no frontend deps. Fewer deps = smaller attack surface and less fingerprint noise. |
| DoS on the probe | The probe does cheap parsing; cap concurrent conns, set aggressive timeouts, and it's a single small box — fronting it with a pure L4 rate-limiter is fine (L4 doesn't terminate TLS). |

---

## 4. Logging & observability (privacy-aware)

- **Structured logs** for ops: request id, timing, verdict bucket, coverage,
  which topology — **not** the full fingerprint tied to a persistent identifier.
- **Anonymize IPs** in any retained logs (truncate).
- **Metrics** (counts, not identities): analyze requests/min, verdict
  distribution, probe reachability rate, nonce hit/miss/expiry rate, p50/p95
  latency, error rate. These tell you if the probe is being blocked in the wild
  (a high probe-miss rate is operationally important and privacy-neutral).
- **No fingerprint retention** in metrics — aggregate only.
- Alert on: probe down (coverage collapses to Topology A), error-rate spike,
  nonce-store failures.

---

## 5. Cost & operational notes

- **Main app (Cloud Run):** scales to zero; cost is per-request and trivial at
  diagnostic-tool volumes. Set a max-instance cap to bound spend under abuse.
- **Edge probe (VM/VPS):** a fixed small monthly cost (e2-micro / $5 VPS). It's
  the only always-on component. One instance is enough; if it dies, the app
  degrades to Topology A automatically.
- **ASN/geo:** offline static list = free; a paid provider adds per-lookup cost —
  cache aggressively (ASN rarely changes per IP within a session).
- **Nonce store:** Firestore free tier covers diagnostic volumes; the in-memory
  probe-map option is free.
