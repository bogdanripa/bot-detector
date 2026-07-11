# 02 — Deployment Topology (concrete)

This document turns the three topologies from [docs/01](01-architecture-and-hosting.md)
into concrete infrastructure, config, and the correlation protocol that joins the
main app to the edge probe in Topology B.

---

## 1. Main app on Cloud Run / Cloud Functions (gen2)

### 1.1 Runtime shape

Deploy the Go app as a **Cloud Run service** (recommended) or a **gen2 Cloud
Function** — gen2 functions *are* Cloud Run under the hood, so the container is
the same. A single binary serves both the static UI and the API:

```
GET  /                → index.html
GET  /app.js, /app.css, /static/*   → static assets (embedded via Go embed.FS)
POST /api/analyze     → accepts Layer-1 JSON, reads Layer-2 from its own headers, returns report
GET  /api/health      → liveness
GET  /api/reference   → (optional) serves the reference fingerprint DB for the UI's "compare" view
```

Serving assets from the same origin as `/api/analyze` keeps `Sec-Fetch-Site:
same-origin` on the analyze POST, which is itself a signal we want to observe.

### 1.2 Cloud Run configuration

| Setting | Value | Reason |
|---------|-------|--------|
| CPU | 1 vCPU | Scoring is cheap; no ML. |
| Memory | 128–256 MiB | Go binary + reference tables are small. |
| Concurrency | 80 | Requests are short and I/O-light. |
| Min instances | 0 (or 1 if cold starts hurt UX) | Serverless-cheap; Go cold start is sub-second. |
| Ingress | All | Public diagnostic tool. |
| HTTP/2 | Optional — irrelevant to capture, since the GFE fronts it either way. | |
| Custom domain | `app.example.com` | Cleaner than the run.app URL; note it still terminates at the GFE. |

### 1.3 `CAPTURE_MODE` env var

The one switch that makes a single codebase serve all topologies:

| `CAPTURE_MODE` | Meaning | Layer 3 in report |
|----------------|---------|-------------------|
| `a` | Plain function, no probe | `unavailable` (labeled) |
| `b` | Split; call the edge probe | `captured via probe` |
| `c` | Self-managed TLS; local capture | `captured locally` |

Also read `EDGE_PROBE_ORIGIN` (e.g. `https://tls.example.com`) and
`NONCE_STORE_URL` (Firestore/Redis) when `CAPTURE_MODE=b`.

### 1.4 Header hygiene (filter GFE injections)

Before analysis, partition incoming headers into `client` vs `infrastructure`.
Deny-list (never scored as client signal), non-exhaustive:

```
X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host, X-Cloud-Trace-Context,
Forwarded, Via, X-Appengine-*, Function-Execution-Id, X-Serverless-Authorization,
Traceparent, X-Request-Id (when GFE-set), Alt-Svc
```

Keep an allow-list of the headers we actually analyze (see
[docs/05](05-layer2-http.md)) and treat everything else as "other (unscored)" so
the report can still *show* it without letting it move the score.

---

## 2. Edge probe host (Topology B)

### 2.1 Purpose

A minimal Go server on a raw socket whose *only* job is to capture, for the
connection that reaches it:

- the **TLS ClientHello** → JA3 + JA4;
- the **HTTP/2 SETTINGS / WINDOW_UPDATE / header-table size / pseudo-header
  order** (if the client negotiated H2 via ALPN);
- the **raw header order** of the HTTP request;
- the **real socket IP** (`RemoteAddr`).

It stores `{ nonce → transportReport }` for 60 seconds and exposes the result to
the main backend.

### 2.2 Hosting requirements (must terminate its own TLS)

- A host with a **static public IP** and **inbound 443** where **your process
  binds the socket** — Compute Engine VM (e2-micro is plenty), Fly.io, a VPS, or
  bare metal.
- **Certificate:** Let's Encrypt via `golang.org/x/crypto/acme/autocert`, or a
  cert you manage. The point is *your* Go `tls.Config` runs the handshake.
- **No proxy, CDN, or managed LB in front.** If you put Cloudflare, a Google
  HTTP(S) LB, or App Engine in front, TLS re-terminates and you're back to
  fingerprinting the intermediary. (A pure L4/TCP passthrough LB is acceptable
  because it doesn't terminate TLS, but it's simpler to point DNS straight at the
  VM.)
- **DNS:** `tls.example.com` → the probe's static IP (A/AAAA). No proxying.

### 2.3 Probe server sketch (Go)

```go
// The ClientHello is captured in GetConfigForClient, stashed per-connection,
// then joined to the HTTP request in ConnContext.
type connInfo struct {
    ja3, ja4     string
    tlsVersion   uint16
    alpn         []string
    remoteIP     string
    h2           *h2Fingerprint // nil if HTTP/1.1
    headerOrder  []string
}

func main() {
    m := &autocert.Manager{ /* Let's Encrypt for tls.example.com */ }
    store := newConnStore() // keyed by conn remote addr + t0

    tlsCfg := &tls.Config{
        GetCertificate: m.GetCertificate,
        NextProtos:     []string{"h2", "http/1.1"},
        GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
            // hello has CipherSuites, SupportedCurves, SupportedPoints,
            // SignatureSchemes, SupportedProtos (ALPN), SupportedVersions, ServerName.
            // For full extension ORDER (needed by JA4), read raw bytes via utls
            // or a wrapping net.Listener that tees the ClientHello.
            store.putHandshake(hello.Conn.RemoteAddr(), computeJA3JA4(hello))
            return nil, nil
        },
    }

    srv := &http.Server{
        Addr:      ":443",
        TLSConfig: tlsCfg,
        ConnContext: func(ctx context.Context, c net.Conn) context.Context {
            return context.WithValue(ctx, connKey, c.RemoteAddr())
        },
        Handler: probeHandler(store),
    }
    log.Fatal(srv.ListenAndServeTLS("", "")) // certs come from autocert
}
```

> **Capturing extension order for JA4.** `tls.ClientHelloInfo` does not expose the
> raw extension list in order. Two ways to get it:
> 1. Wrap the `net.Listener` so you tee the first flight of bytes off the socket
>    before Go's TLS stack consumes them, and parse the ClientHello yourself
>    (extension type list is straightforward TLV parsing).
> 2. Use `utls`' lower-level parsing to read the ClientHello structure including
>    extension order.
> JA3 only needs the *values* (which `ClientHelloInfo` gives); JA4 needs the
> *sorted* extension/cipher lists plus counts and the ALPN — see
> [docs/06](06-layer3-transport.md#2-ja3--ja4).

### 2.4 HTTP/2 fingerprint capture

If ALPN negotiated `h2`, run the connection through Go's `golang.org/x/net/http2`
server **with a hook that records the client's SETTINGS frame** before serving.
The distinctive values:

- `SETTINGS_HEADER_TABLE_SIZE`, `SETTINGS_ENABLE_PUSH`,
  `SETTINGS_MAX_CONCURRENT_STREAMS`, `SETTINGS_INITIAL_WINDOW_SIZE`,
  `SETTINGS_MAX_FRAME_SIZE`, `SETTINGS_MAX_HEADER_LIST_SIZE`, in the **order the
  client sent them**;
- the initial `WINDOW_UPDATE` increment;
- the **pseudo-header order** (`:method`, `:authority`, `:scheme`, `:path`) — real
  browsers have a stable, distinctive order that differs from Go/Python/curl H2
  clients;
- the Akamai-style HTTP/2 fingerprint string
  (`SETTINGS;WINDOW_UPDATE;PRIORITY;PSEUDO_HEADER_ORDER`).

Go's default `http2.Server` hides some of this; you'll likely read frames from a
raw `h2c`-style loop or patch in a frame observer. Document the exact approach in
code comments.

### 2.5 CORS on the probe

The browser reaches the probe with a **cross-origin** `fetch`. The probe must
return permissive CORS **for the diagnostic endpoint only**:

```
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, OPTIONS
Access-Control-Allow-Headers: (none needed; keep the request simple to avoid preflight)
Vary: Origin
```

Keep the probe request a **simple request** (GET, no custom headers, no
non-simple content type) so the browser does **not** send a CORS preflight —
otherwise you fingerprint the `OPTIONS` preflight connection instead of the real
one, and the preflight may reuse or differ from the GET connection.

---

## 3. Correlation protocol (Topology B)

The main app and the edge probe are two different origins. We stitch their two
observations of the same client together with a **single-use nonce**.

### 3.1 Nonce lifecycle

```
1. Browser loads app.example.com/. The main backend mints nonce = UUIDv4,
   embeds it in the page (a <script type="application/json" id="bootstrap"> island),
   and — in CAPTURE_MODE=b — pre-registers it as "pending" in the nonce store
   with a 60s TTL.
2. app.js calls  GET https://tls.example.com/probe?nonce=NONCE  (simple CORS GET).
3. The probe captures the transport report for that connection and does:
       store.set("txp:" + nonce, transportReport, ttl=60s)
   then returns 204 (or the report JSON if we want to show "your JA4" live).
4. app.js POSTs app.example.com/api/analyze { nonce, layer1, ... }.
5. The main backend reads txp:NONCE from the store (or calls the probe's
   GET /result?nonce=NONCE server-to-server with a shared secret), merges it,
   deletes the nonce, and scores.
```

### 3.2 Nonce store options

| Store | Fit |
|-------|-----|
| **Firestore** (native mode, TTL policy on a field) | Best for pure-GCP, serverless, no server to run. ~1 write + 1 read per session. |
| **Redis / Memorystore** | Fastest, but adds an always-on component; overkill for MVP. |
| **Probe-owned in-memory map + server-to-server `/result` call** | Simplest: no external store at all. The main backend calls the probe's `/result?nonce` with a shared bearer token; the probe holds the map in memory with a 60s sweeper. Works because there's one probe instance. Scale the probe horizontally and you'd need a shared store — but one probe is fine for a diagnostic tool. |

**MVP recommendation:** probe-owned in-memory map + authenticated `/result` call.
Zero extra infrastructure, and the probe is a single small instance anyway.

### 3.3 Same-client verification

The nonce proves the two requests are *related*, but we should also check they're
the *same client* and record any mismatch (a mismatch is itself interesting):

- Compare the probe connection's `RemoteAddr` IP to the analyze request's
  `X-Forwarded-For` client IP. Equal → good. Different → the client used a
  different egress for the two requests (proxy rotation, split tunnel) — **record
  as a signal, don't fail.**
- Compare the `User-Agent` seen by the probe to the one seen by the main app.
  They should be byte-identical for a genuine browser. A difference is a strong
  tell (different HTTP client for the two requests).

### 3.4 Failure modes (all degrade, none error)

| Failure | Cause | Behavior |
|---------|-------|----------|
| Probe fetch blocked | Corporate firewall, adblock, or the client refuses cross-origin | Report renders Layer 3 as `probe unreachable — transport signals unavailable`; score over L1+L2. |
| Nonce expired | User idled >60s before submitting | `/api/analyze` treats L3 as absent, notes "transport capture timed out". |
| Nonce not found | Probe never got the request, or store miss | Same as expired. |
| IP/UA mismatch | Proxy rotation / different client | L3 captured but flagged with a "captured from a different egress" caveat and down-weighted. |
| Probe down / not deployed | `CAPTURE_MODE=b` but host offline | Backend catches the timeout, logs it, degrades to A-mode scoring for that request. |

The invariant from [docs/01 §6](01-architecture-and-hosting.md): **probe problems
reduce coverage; they never break the report.**

---

## 4. DNS, certs, and CORS summary

```
app.example.com   →  Cloud Run custom domain (managed cert at GFE)   [main app]
tls.example.com   →  A/AAAA to edge-probe static IP (autocert/LE)    [edge probe, raw TLS]
```

- Two subdomains → two origins → the probe `fetch` is cross-origin by design;
  that's what lets us observe a *fresh* connection's transport.
- Both on HTTPS. The probe's cert is issued to `tls.example.com` and served by the
  probe's own Go TLS stack (this is the whole point).
- CORS on the probe restricted to the app origin (§2.5).

---

## 5. Local development

- `docker-compose` with two services: `app` (Cloud Run image) and `probe`.
- Use `mkcert` for locally-trusted certs so the probe terminates real TLS on
  `localhost` / `tls.localtest.me`.
- A `CAPTURE_MODE=c` "all-in-one" binary is handy for local testing of the full
  pipeline without running two processes — it terminates TLS locally and captures
  all layers from one connection.
- Provide a `Makefile`: `make dev` (compose up), `make probe`, `make test`,
  `make deploy-app`, `make deploy-probe`.
