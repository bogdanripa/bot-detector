# 10 — Privacy, Security & Abuse

A tool that computes fingerprints must hold itself to a higher privacy standard
than the systems it diagnoses. The governing principle: **the tool reports to the
visitor about themselves and forgets them.**

---

## 1. Data handling & privacy

### 1.1 Statelessness by default

- The report is computed per request and returned to the caller. **Nothing is
  persisted** beyond the short-TTL session (a `sessionId → connectionSignals` map,
  ~10 min) that ties the two phases together and self-expires.
- No fingerprint database, no cross-session identity, and only one functional
  `Secure; HttpOnly; SameSite=Strict` session cookie (not tracking, and disclosed).
- No third-party requests from the frontend (see [docs/08 §6](08-frontend-ui.md#6-keeping-the-frontend-fingerprint-clean)),
  so no data leaks to CDNs/analytics.

### 1.2 What counts as personal data

Fingerprints (canvas/audio/WebGL hashes, IP, font list) are **personal data /
online identifiers** under GDPR and similar regimes. Because we compute them:

- **Disclose** clearly, on the page, what is collected and that it's shown back to
  the visitor and not stored. A short, plain-language privacy note in the footer,
  linking to a fuller policy.
- **Do not transmit typed content** from the on-page form — only interaction
  dynamics (counts, timings, variances). Field values never leave the browser.
  Make that explicit in the UI, next to the form.
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
| Body size cap | 256 KiB, return `413` above | Layer-1/behavior payloads are small; cap stops abuse. |
| Rate limit | Per-IP token bucket (e.g. 30 analyze/min) → `429` with `retryAfterMs` | The tool is interactive; humans re-run occasionally, not dozens of times a second. |
| Session-bound analyze | `/api/analyze` requires a valid, unexpired `sessionId`; `phase 2` requires a prior `phase 1` | Prevents replayed/forged payloads and unbounded session accumulation. |
| Same-origin only | `Sec-Fetch-Site: same-origin` expected on analyze; strict CSP `default-src 'self'` | The analyze endpoint serves our own page, not third parties. |
| No open JA3/JA4 API | The transport signals are computed internally and only returned inside a session's report | Don't become a free TLS-fingerprinting service for others' scraping. |
| Timeouts | Read/write/idle timeouts on the server | Slowloris and hung-connection resistance. |

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
| SSRF | The only outbound calls are optional ASN/geo lookups to a fixed provider — no client-controlled URLs are fetched. |
| Secrets | Any provider API key (ASN/geo) lives in env/secret manager, never in the repo or client. |
| TLS | The server uses a modern TLS *serving* config; the ClientHello it *reads* (the client's) is the fingerprint input and is never trusted as a serving parameter. |
| Dependency surface | Minimal Go deps (utls, x/net/http2, an ASN lib); no frontend deps. Fewer deps = smaller attack surface and less fingerprint noise. |
| DoS | Cheap parsing per request; cap concurrent conns, set aggressive read/write/idle timeouts. One box; if you front it, use a pure L4 (TLS-passthrough) rate-limiter — never L7, which would re-terminate TLS. |

---

## 4. Logging & observability (privacy-aware)

- **Structured logs** for ops: request id, timing, verdict band, phase, whether a
  critical contradiction fired — **not** the full fingerprint tied to a persistent
  identifier.
- **Anonymize IPs** in any retained logs (truncate).
- **Metrics** (counts, not identities): analyze requests/min, band distribution,
  phase-1-only vs. phase-2-completed rate (how many visitors interact with the
  form), session hit/miss/expiry rate, p50/p95 latency, error rate.
- **No fingerprint retention** in metrics — aggregate only.
- Alert on: error-rate spike, session-store failures, TLS/cert-renewal failures,
  a sudden collapse in captured Layer-3 (would indicate a misconfigured proxy in
  front re-terminating TLS).

---

## 5. Cost & operational notes

- **Server (VM/VPS):** a single always-on box (e2-small / small VPS) is the whole
  footprint — it serves the app *and* captures all layers. Fixed small monthly
  cost; scale vertically first.
- **TLS:** in-process autocert (Let's Encrypt) — free; watch cert-renewal.
- **ASN/geo:** offline static list = free; a paid provider adds per-lookup cost —
  cache aggressively (ASN rarely changes per IP within a session).
- **Session store:** an in-memory map with a TTL sweeper is free and sufficient for
  one instance; move to Redis only if you scale horizontally behind an L4
  (TLS-passthrough) load balancer.
