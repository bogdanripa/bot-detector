# 02 — Deployment

Concrete infrastructure for the chosen design: **a single self-hosted Go server
that terminates its own TLS and captures all three layers on one connection**,
serving a two-phase detection flow. The old split-with-edge-probe design is kept
only as a [serverless fallback appendix](#appendix--serverless-fallback-split-deployment).

---

## 1. The server

One Go binary does everything:

```
GET  /                → serves index.html (the instrumented form) + a bootstrap
                        island containing the sessionId; captures this connection's
                        Layer 2 + Layer 3 signals and stores them under sessionId
GET  /app.js, /app.css, /static/*   → static assets (embed.FS)
POST /api/analyze     → phase 1 (passive Layer 1) and phase 2 (form behavior);
                        merges with stored connection signals, returns the report
GET  /api/health      → liveness
GET  /api/reference   → (optional) reference fingerprint DB for the UI's compare view
```

Because the page, the assets, and the API are one origin on one server:

- the **navigation** to `GET /` is where we capture the client's true header
  order and `Sec-Fetch-Mode: navigate`;
- the same TLS handshake yields the ClientHello (JA3/JA4) and, if `h2` is
  negotiated, the HTTP/2 fingerprint;
- the socket `RemoteAddr` is the real client IP;
- no cross-origin fetch, no nonce — a `sessionId` cookie/island ties the phases
  together.

### 1.1 Connection-signal capture at `GET /`

TLS/H2/header-order are properties of the **connection**, captured during the
handshake and the first request. We stash them per-connection and join them to
the HTTP request:

```go
// One store: sessionId -> connectionSignals (TTL ~10 min).
// TLS captured in GetConfigForClient; H2 + header order captured by reading
// frames/raw bytes; all keyed by the connection's remote addr, then bound to
// the sessionId minted when GET / is served.
srv := &http.Server{
    Addr:      ":443",
    TLSConfig: tlsCfg,                // GetConfigForClient computes JA3/JA4, stores by RemoteAddr
    ConnContext: func(ctx context.Context, c net.Conn) context.Context {
        return context.WithValue(ctx, connKey, c.RemoteAddr())
    },
    Handler: router,                  // GET / mints sessionId, binds connSignals[remoteAddr] -> session
}
log.Fatal(srv.ListenAndServeTLS("", "")) // certs via autocert
```

> **HTTP-keepalive / H2 multiplexing note.** The phase-1/phase-2 `POST
> /api/analyze` calls may reuse the same TLS connection as the navigation (so same
> JA4) or open a new one. Either way we bind Layer 2/3 to the session at the
> **navigation** (`GET /`), because that's the request with true browser
> header-order and navigation `Sec-Fetch-*` semantics. The API POSTs are `fetch`
> requests and carry `Sec-Fetch-Mode: cors`/`same-origin`, which we record
> separately (a POST that *doesn't* look same-origin is itself a signal — the
> payload may have been replayed outside the page).

### 1.2 Host configuration

| Setting | Value | Reason |
|---------|-------|--------|
| Host | Compute Engine VM (e2-small) or a VPS with a static IP | Need a raw :443 socket and our own cert. |
| TLS | `autocert` (Let's Encrypt) in-process | Our process runs the handshake — required for Layer 3. |
| Process mgmt | `systemd` unit (or a container on the VM) with auto-restart | Single always-on service. |
| Ports | 443 (HTTPS), 80 (ACME challenge + redirect) | autocert HTTP-01, plus redirect to HTTPS. |
| Firewall | 80/443 in; deny the rest | Minimal surface. |
| Scaling | Vertical first; one box handles diagnostic volume. For horizontal, move the session store to Redis and front with an **L4 (TCP passthrough)** LB — never L7, which would re-terminate TLS. | Preserve the socket. |
| Logs/metrics | Structured logs, anonymized IPs; Prometheus/OpenTelemetry | See [docs/10](10-privacy-security.md). |

### 1.3 Header hygiene

Even self-hosted, filter hop-by-hop and any proxy headers before analysis, and
keep an allow-list of the headers we actually score (see
[docs/05](05-layer2-http.md)). If you ever front the box with an L4 proxy that
adds `PROXY protocol` or a single trusted `X-Forwarded-For`, parse the real client
IP from that one trusted hop; otherwise use `RemoteAddr`.

---

## 2. The two-phase API flow

```
1. Browser GET app.example.com/  (navigation)
     → server captures connSignals (TLS/JA4, H2, header order, IP/ASN),
       mints sessionId, stores connSignals under it (TTL 10m),
       serves index.html with <script id="bootstrap">{ "sessionId": "…" }</script>
       and sets a Secure;HttpOnly;SameSite=Strict cookie with the same id.

2. app.js runs on load:
     - collects passive Layer 1
     - POST /api/analyze { reportVersion, sessionId, phase: 1, layer1 }
     - server merges connSignals + layer1, scores, returns report@phase1
     - UI renders banner + probability + checklist immediately

3. User interacts with the on-page form; app.js records interaction dynamics.
   On submit (or after N seconds of interaction):
     - POST /api/analyze { reportVersion, sessionId, phase: 2, behavior }
     - server merges behavior into the session's signals, RE-scores,
       returns report@phase2 (higher confidence)
     - UI updates banner + probability + checklist in place, marking which
       checks changed
```

The server keeps the phase-1 result in the session so phase 2 is a delta re-score,
not a full re-collect. See [docs/03](03-api-contract.md) for the exact schemas.

---

## 3. TLS & DNS

```
app.example.com  →  A/AAAA to the server's static IP  (autocert / Let's Encrypt)
```

- One domain, one origin. HTTPS via in-process autocert; port 80 serves the
  ACME HTTP-01 challenge and 301-redirects everything else to HTTPS.
- No CDN, no managed LB with TLS, no Cloudflare orange-cloud — any of those
  re-terminate TLS and destroy Layer 3.

---

## 4. Local development

- A single `make dev` runs the server with a locally-trusted cert via `mkcert`
  on `app.localtest.me`, so TLS termination (and thus Layer 3 capture) works
  locally exactly as in prod.
- Drive it with real Chrome and with headless Playwright (Chromium is at
  `/opt/pw-browsers/chromium`) to see both ends of the score.
- `Makefile` targets: `make dev`, `make test`, `make build`, `make deploy`
  (rsync/scp the binary + `systemctl restart`), `make capture` (dump raw
  fixtures for the reference DB — see [docs/11 §3](11-testing.md#3-capturing-fixtures-how-to-build-the-golden-set)).

---

## Appendix — Serverless fallback (split deployment)

Retained only for the case where someone is later *forced* onto a managed
serverless platform (Cloud Run / Cloud Functions) and still wants Layer 3. It is
**not** the chosen design.

The problem: a managed platform terminates TLS at the GFE (see
[docs/01 §2](01-architecture-and-hosting.md#2-why-we-do-not-deploy-on-a-google-cloud-function)),
so the function can't see Layer 3. The workaround: keep the app on the managed
platform and add **one small raw-socket "edge probe"** on a separate subdomain
(`tls.example.com`) that terminates its own TLS. The browser makes an extra
cross-origin `fetch` to the probe; the probe captures JA3/JA4 + H2 + header order
of *that* connection and returns them keyed by a single-use, 60-second
**correlation nonce** the app minted. The app fetches the probe's result
server-to-server and merges it.

Trade-offs versus self-hosting:

- adds a second host, a nonce store, CORS, and same-client verification (compare
  probe IP/UA to the app's) — all of which self-hosting eliminates;
- the transport signals describe a `fetch` connection, not the navigation, so
  their Layer-2 context differs and must be labeled;
- if the probe is blocked/unreachable, Layer 3 degrades to unavailable.

If you must build this, the mechanics (nonce lifecycle, store options, CORS,
failure modes) are straightforward re-additions, but every one of them exists
*only* to compensate for not owning the socket. The recommendation stands: own
the socket instead.
