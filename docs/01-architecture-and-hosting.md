# 01 — Architecture & Hosting

This document reconciles the original three-layer design with the deployment
target the project actually has: **a Google Cloud Function (or a similar managed
serverless platform)**. That target is not a detail — it removes the ability to
see the highest-value signals unless we adapt the topology. Read this before
writing any code.

---

## 1. The three layers (recap)

Detection splits into three layers by *where the signal physically exists on the
wire and in the runtime*:

| Layer | What it sees | Where it must be captured |
|-------|--------------|---------------------------|
| **1. Browser environment** | `navigator`, WebGL, canvas, audio, screen, permissions, fonts, behavior | Frontend JS, then POSTed to the backend |
| **2. HTTP** | Header **values**, header **order**, `Sec-Fetch-*`, client hints, cookies | Backend, from the raw request |
| **3. Transport** | TLS ClientHello (→ JA3/JA4), HTTP/2 SETTINGS & pseudo-header order, IP/ASN | Backend, but **only if that backend terminates TLS itself** |

The critical dependency is the last column of the transport row: **you can only
fingerprint the transport if your own code is the TLS endpoint.** If anything
terminates TLS in front of you — a CDN, a load balancer, or a managed serverless
front end — the fingerprint you compute is *that intermediary's*, not the
client's.

---

## 2. Why Google Cloud Functions changes the plan

Google Cloud Functions (both generations; gen2 runs on Cloud Run) sit behind the
**Google Front End (GFE)** and Google's HTTP(S) load-balancing tier. Every
inbound request is terminated, inspected, normalized, and re-emitted by Google
infrastructure before your function's handler is invoked. Concretely:

### 2.1 TLS is terminated at the GFE (Layer 3 TLS is gone)

The client's TLS handshake completes against Google's edge, hundreds of
milliseconds and several network hops before your code runs. Your handler
receives a plain `http.Request` (Go) / `Request` object (Node) with **no access
to the ClientHello**. There is no API, header, or environment variable that
surfaces the client's cipher suites, extensions, or curve list. **JA3 and JA4 are
uncomputable inside a Cloud Function.** Any JA3/JA4 you managed to compute would
fingerprint the GFE, which is identical for every visitor and therefore useless.

### 2.2 HTTP is normalized (Layer 3 HTTP/2 gone, Layer 2 order unreliable)

The client speaks HTTP/2 (or /3) to the GFE. The GFE speaks a *fresh* HTTP
connection to your container. In that translation:

- The client's **HTTP/2 SETTINGS frame, WINDOW_UPDATE, header-table size, and
  pseudo-header order are consumed by the GFE and never forwarded.** The HTTP/2
  fingerprint is uncomputable in the function.
- **Header order is not preserved.** HTTP/2 carries headers in HPACK; converting
  to what your handler sees involves re-serialization, and Google's stack imposes
  its own canonicalization. The order your Go/Node handler observes is an
  artifact of Google's proxy, not the client's emission order. The single
  highest-value Layer 2 signal in the original plan is therefore **not reliable
  on a Cloud Function.**
- Google **injects and rewrites headers**: `X-Forwarded-For`,
  `X-Forwarded-Proto`, `X-Cloud-Trace-Context`, `Forwarded`, `Via`,
  `Function-Execution-Id`, and others. Their presence is expected and must be
  filtered out before analysis so they aren't mistaken for client signals.

### 2.3 What *does* survive to the function

- **Header values** (User-Agent, Accept, Accept-Language, Accept-Encoding,
  client hints `Sec-CH-UA*`, `Sec-Fetch-*`, `Upgrade-Insecure-Requests`, `DNT`,
  cookies). Values pass through intact even though order does not.
- **Client IP**, via the right-most trustworthy entry of `X-Forwarded-For` (see
  [§5.4](#54-getting-the-real-client-ip-behind-the-gfe)).
- Everything in **Layer 1**, because that is collected by JavaScript in the
  client and POSTed to you as a normal request body — the GFE doesn't touch it.

### 2.4 The direct contradiction with the original plan

The original plan says, three times, "**No CDN/proxy in front** during TLS
capture, or you fingerprint the CDN," and "serve directly (no CDN in front)."
**A Google Cloud Function is, architecturally, exactly the CDN/proxy the plan
warns against.** You cannot both deploy to a plain Cloud Function *and* capture
Layer 3. This is not a limitation to engineer around inside the function — it is
physically upstream of your code. The rest of this document is how we resolve
that.

### 2.5 Coverage summary by deployment

| Signal group | Plain Cloud Function | Split deployment (recommended) | Self-managed TLS host |
|--------------|:-------------------:|:------------------------------:|:---------------------:|
| Layer 1 (all browser signals) | ✅ full | ✅ full | ✅ full |
| Layer 2 header **values** | ✅ full | ✅ full | ✅ full |
| Layer 2 header **order** | ❌ normalized | ✅ (via edge probe) | ✅ full |
| Layer 3 TLS JA3/JA4 | ❌ impossible | ✅ (via edge probe) | ✅ full |
| Layer 3 HTTP/2 fingerprint | ❌ impossible | ✅ (via edge probe) | ✅ full |
| Layer 3 IP / ASN | ✅ (XFF) | ✅ | ✅ |
| Cross-layer coherence | ⚠️ partial (L1↔L2 only) | ✅ full | ✅ full |

---

## 3. Three deployment topologies

Pick one. They differ only in *where TLS is terminated* and therefore *how much
of Layer 2/3 you can capture*. The application code is largely shared; a single
config flag (`CAPTURE_MODE`) tells the backend which layers are live so the UI
can label the rest as "unavailable on this deployment" rather than "ok".

### Topology A — Plain Cloud Function (simplest, weakest)

```
Browser ──HTTPS──▶ GFE (terminates TLS) ──▶ Cloud Function (app + UI + scoring)
```

- **Captures:** Layer 1 (full), Layer 2 values, IP/ASN. Scores on L1↔L2 coherence.
- **Cannot capture:** TLS/JA4, HTTP/2, header order.
- **When to choose:** fastest path to something useful; you accept that the
  strongest anti-bot signals are absent and the UI says so honestly.
- **Honesty requirement:** the report must render the Layer 3 section as
  `unavailable — this deployment terminates TLS at a managed front end` and the
  coherence score must be computed over only the live signals, with a visible
  "coverage: layers 1–2" caption. **Never fabricate a JA3.**

### Topology B — Split deployment (recommended)

Keep the main app on Cloud Run / Cloud Functions (great DX, autoscaling, static
hosting, cheap), and add **one small raw-socket "edge probe" host** on a
separate subdomain that terminates its own TLS and therefore *can* see Layer 2
order + Layer 3.

```
                         app.example.com
Browser ──HTTPS──▶ GFE ──────────────▶ Cloud Run  (Layer 1 + L2 values + UI + scoring)
   │
   │   tls.example.com   (no managed TLS in front — YOUR code is the endpoint)
   └────HTTPS──────────▶ Edge probe (Go, utls-capable)  (L2 order + L3 TLS/H2/IP)
```

- The browser fetches the main app normally, **and** makes one extra
  cross-origin `fetch('https://tls.example.com/probe', {credentials:'omit'})`.
- The edge probe captures JA3/JA4, the HTTP/2 fingerprint, and the raw header
  order **of that second connection**, and returns them keyed by a correlation
  nonce the main app minted.
- The main backend merges the probe result into the report.
- **Caveat that must be surfaced in the report:** the transport signals describe
  the *probe connection*, which is a `fetch()` (Layer 2 `Sec-Fetch-Mode: cors`,
  no navigation). That's fine for TLS/H2 (same client stack) but means the
  probe's *own* header set differs from a navigation. The report labels it
  accordingly. See [docs/02](02-deployment-topology.md) for the correlation
  protocol and the CORS setup.
- **Where to host the probe:** anywhere that gives you a raw TCP socket and lets
  you present your own certificate without a proxy in front:
  - a **Compute Engine VM** with a static external IP and Go serving TLS directly
    (cheapest reliable option inside GCP; ~e2-micro is enough);
  - **Fly.io**, a **Hetzner/DigitalOcean/OVH VPS**, or bare metal — all give raw
    sockets;
  - **not** Cloud Functions, **not** Cloud Run behind the default URL, **not**
    App Engine standard, **not** anything behind Cloudflare/Google LB with
    managed certs — those all re-terminate TLS.

### Topology C — Single self-managed TLS host (strongest, most ops)

Run the *entire* app on a host where your process is the TLS endpoint (Compute
Engine VM, VPS, or a container on Cloud Run **with a custom domain but no CDN**,
which is subtle and still terminates at the GFE — so in practice a plain VM).

```
Browser ──HTTPS──▶ Your Go server (terminates TLS) — Layer 1 + 2 + 3 in one place
```

- **Captures:** everything, from one connection, no correlation nonce needed.
- **Cost:** you own TLS certs (Let's Encrypt / autocert), OS patching, scaling,
  and uptime. No serverless autoscale.
- **When to choose:** you want maximum signal fidelity and don't mind running a VM.

### Recommendation

Ship **Topology A first** (fast, demonstrates the product, honest about gaps),
then add the **edge probe to reach Topology B** as the immediate next milestone.
Topology C is a fallback for people who want a single-box deploy. The code is
structured so the edge probe is an optional module, not a rewrite. See
[docs/12](12-roadmap.md) for the milestone ordering.

---

## 4. Recommended stack

| Concern | Choice | Why |
|---------|--------|-----|
| Main app runtime | **Go** on Cloud Run (gen2 function via the Functions Framework, or a plain container) | Same language as the edge probe; fast cold start; good stdlib HTTP. Node is acceptable for the main app since it only needs Layer 1/2 values, but sharing Go avoids two toolchains. |
| Edge probe runtime | **Go**, with `crypto/tls` + `github.com/refraction-networking/utls` (for inspection) and manual HTTP/2 handling | Go gives raw `net.Listener` access, a `GetConfigForClient` / `GetCertificate` hook that exposes the `ClientHelloInfo`, and mature JA3/JA4 community libs. |
| Frontend | **Vanilla JS + a tiny CSS file**, no framework, no build step (or esbuild only) | Every added library changes the fingerprint the tool is trying to measure. Keep the payload small and dependency-free. |
| Data store (optional) | None for MVP; the tool is stateless per request. Add a short-TTL store (Firestore / in-memory / Redis) only for the correlation nonce in Topology B. | Statelessness keeps it privacy-clean and serverless-friendly. The nonce store holds a UUID for ~60s, nothing else. |
| Config | Single `CAPTURE_MODE` env var (`a` \| `b` \| `c`) + `EDGE_PROBE_ORIGIN` | Lets one codebase serve all three topologies and label coverage correctly. |

**Why Go for TLS inspection specifically:** in Go's `tls.Config` you can set
`GetConfigForClient(hello *tls.ClientHelloInfo)`. That callback receives the
parsed ClientHello — cipher suites, `SupportedCurves`, `SupportedPoints`,
`SignatureSchemes`, ALPN protocols, server name, and the raw supported versions —
which is exactly the input to a JA3/JA4 hash. `utls` additionally exposes the raw
extension list and their order, which JA4 needs. This is not possible in a
managed serverless runtime because the callback runs *in the GFE's TLS stack*,
not yours.

---

## 5. Data flow & correlation

### 5.1 Topology A (single request)

```
1. Browser GET app.example.com/            → Cloud Function serves index.html + app.js
2. app.js collects Layer 1 over ~3s (incl. behavior)
3. app.js POST /api/analyze  { layer1, clientMeta }
4. Function reads Layer 2 values from its own request headers (filtering GFE-injected ones)
5. Function runs the coherence engine over L1 + L2
6. Function returns the scored report; app.js renders it
```

### 5.2 Topology B (two requests, correlated)

```
1. Browser GET app.example.com/            → serves index.html + app.js, sets a fresh nonce
                                             (returned in the HTML as a <meta> / JSON island)
2. app.js, in parallel:
     a. collects Layer 1 over ~3s
     b. fetch('https://tls.example.com/probe?nonce=NONCE', {credentials:'omit', mode:'cors'})
          → edge probe captures JA3/JA4 + H2 + header order of THIS connection,
            stores { nonce → transportReport } for 60s, returns 204 (or the report as JSON for display)
3. app.js POST app.example.com/api/analyze  { nonce, layer1, clientMeta }
4. Function reads its own Layer 2 values, then fetches the transportReport for `nonce`
   from the shared nonce store (written by the edge probe) — or calls the probe's
   /result?nonce endpoint server-to-server.
5. Function runs the FULL coherence engine over L1 + L2 + L3
6. Returns the scored report; app.js renders it, including a "transport captured on
   a separate probe connection" disclosure.
```

The nonce is a single-use, 60-second-TTL UUID. See
[docs/02 §Correlation protocol](02-deployment-topology.md#3-correlation-protocol)
for the exact store schema, the same-client verification (compare probe IP/UA to
the analyze request's), and the failure modes (probe blocked by a firewall,
nonce expired, cross-origin blocked → degrade gracefully to Topology-A scoring).

### 5.3 Topology C (single request, everything local)

Like A, but the same server also holds the `ClientHelloInfo` from the TLS
handshake and the raw header bytes, so no nonce or second request is needed. The
handshake info is stashed per-connection (keyed by `net.Conn` remote addr +
handshake time) and joined to the HTTP request in a `ConnContext` hook.

### 5.4 Getting the real client IP behind the GFE

On Cloud Functions/Run, **do not trust `RemoteAddr`** — it's Google's internal
proxy IP. Use `X-Forwarded-For`. Google appends the client IP as the
**second-to-last** entry (the last is the GLB); more robustly, Google also sets a
trustworthy `X-Forwarded-For` where the client IP is the first hop *that you
didn't add*. The safe rule on GCP:

- Split `X-Forwarded-For` by comma.
- The client IP is the **left-most** entry **only if** you have a fixed number of
  trusted proxies to strip from the right; on GCP HTTP LB the client IP is the
  first value. Validate it parses as an IP and is not private/reserved.
- Cross-check against the edge probe's `RemoteAddr` in Topology B/C, where you
  *do* see the real socket IP — if the two disagree, that itself is a signal
  (proxy/VPN chain) and is recorded, not discarded.

---

## 6. Architectural principles that constrain every later decision

1. **Never claim a signal you didn't capture.** Coverage is part of the output.
   The score is always accompanied by which layers fed it.
2. **The frontend must not pollute its own measurement.** No React, no jQuery, no
   analytics SDKs, no web-font CDN. Inline critical CSS; ship one small JS bundle.
3. **The edge probe is optional and isolated.** The main app must run and produce
   a useful (layers 1–2) report even if the probe is down, blocked, or not
   deployed. Probe failure degrades coverage; it never errors the report.
4. **Filter infrastructure headers before analysis.** Maintain an explicit
   allow/deny list of GFE-injected headers so Google's own additions are never
   scored as client behavior.
5. **Statelessness by default.** The only server state is the 60-second
   correlation nonce (Topology B). Everything else is computed per request and
   discarded. This is both a privacy stance and an operational simplification.
6. **Deterministic scoring.** Given the same captured inputs, the engine returns
   the same score. Behavioral signals (which are noisy) are weighted and bounded
   so they can nudge but not dominate a verdict.
