# 01 — Architecture & Hosting

**Decision:** we self-host on a server that terminates its own TLS, so we can see
all three detection layers on one connection. This document explains the layers,
why that hosting choice is forced (and specifically why *not* a Google Cloud
Function), and the two-phase detection flow the app uses.

---

## 1. The three layers

Detection splits by *where the signal physically exists on the wire and in the
runtime*:

| Layer | What it sees | Where it must be captured |
|-------|--------------|---------------------------|
| **1. Browser environment** | `navigator`, WebGL, canvas, audio, screen, permissions, fonts, and **behavior / form dynamics** | Frontend JS, POSTed to the backend |
| **2. HTTP** | Header **values**, header **order**, `Sec-Fetch-*`, client hints, cookies | Backend, from the raw request |
| **3. Transport** | TLS ClientHello (→ JA3/JA4), HTTP/2 SETTINGS & pseudo-header order, IP/ASN | Backend — **only if that backend terminates TLS itself** |

The load-bearing constraint is the last column of the transport row: **you can
only fingerprint the transport if your own code is the TLS endpoint.** If anything
terminates TLS in front of you — a CDN, a load balancer, or a managed serverless
front end — the fingerprint you compute is *that intermediary's*, identical for
every visitor, and useless.

### 1.1 Layers are libraries; the honeypot is a consumer

Each layer is implemented as an **independently importable library**, and the
honeypot is just one app that composes them. This matters for hosting because the
libraries are built to be **flexible**: whichever layers a given deployment can
capture, it captures; the rest report `unavailable` and the scoring engine works
around them. The honeypot happens to own its socket and so captures all three;
another consumer (server-only, client-only, or behind a proxy) uses the same
libraries with a smaller capability set. Package boundaries, public APIs, and the
capability model are in [docs/13](13-libraries-and-packaging.md). The rest of this
document is about the *honeypot's* hosting — the deployment that maximizes what the
libraries can see.

---

## 2. Why we do **not** deploy on a Google Cloud Function

We evaluated a plain Cloud Function and rejected it, because it structurally
blinds the two strongest layers. This section is the rationale, not the plan.

A Cloud Function (both generations; gen2 runs on Cloud Run) sits behind the
**Google Front End (GFE)** and Google's HTTP(S) load balancer. Every request is
terminated, normalized, and re-emitted by Google infrastructure before your
handler runs:

- **TLS terminates at the GFE.** The client's handshake completes against
  Google's edge; your handler gets a plain request with **no access to the
  ClientHello**. JA3/JA4 are uncomputable — any value you produced would
  fingerprint the GFE, which is the same for everyone.
- **HTTP is normalized.** The client speaks HTTP/2 to the GFE; the GFE opens a
  fresh connection to your container. The client's **HTTP/2 SETTINGS and
  pseudo-header order are consumed by the GFE and never forwarded**, and **header
  order is not preserved** (HPACK → re-serialization + canonicalization). The two
  highest-value non-JS signals are gone.
- Only **header values**, the **client IP** (via `X-Forwarded-For`), and all of
  **Layer 1** survive to the function.

In short, a Cloud Function *is* exactly the "CDN/proxy in front" that the original
plan warned against three times. That is why the deployment target moved.

---

## 3. What we deploy instead: a single self-hosted TLS-terminating server

```
Browser ──HTTPS──▶ Your Go server (terminates TLS) ── Layer 1 + Layer 2 + Layer 3
                   app.example.com, on a VM/VPS you control
```

One process owns the socket, so a single connection yields:

- the client's **TLS ClientHello** → JA3 + JA4 (Layer 3);
- the **HTTP/2 SETTINGS / WINDOW_UPDATE / pseudo-header order** (Layer 3);
- the **raw header order** and all header values (Layer 2);
- the real client **IP** from the socket (`RemoteAddr`) — no `X-Forwarded-For`
  guessing (Layer 3 IP/ASN);
- and it serves the page + API, receiving Layer-1 JSON like any backend.

**No edge probe. No cross-origin fetch. No correlation nonce.** Those existed only
to work around the serverless front end; owning the socket removes the entire
mechanism. This is a large simplification versus the previous split design.

### 3.1 Where to host

Anywhere you get a **raw TCP socket on :443 and can present your own
certificate**, with **nothing that re-terminates TLS in front**:

- a **Compute Engine VM** (e2-small is plenty) with a static external IP;
- a **VPS** — Hetzner, DigitalOcean, OVH, Linode, Vultr;
- **Fly.io** (raw TCP) or bare metal.

**Not** Cloud Functions, **not** Cloud Run behind its managed URL, **not** App
Engine, **not** anything behind Cloudflare/Google LB with managed TLS — all
re-terminate TLS. A pure L4/TCP passthrough load balancer is acceptable (it
doesn't terminate TLS), but pointing DNS straight at the box is simpler.

### 3.2 TLS

Terminate TLS in your Go process with `golang.org/x/crypto/acme/autocert`
(Let's Encrypt) or a managed cert file. The point is that your `tls.Config`'s
`GetConfigForClient` callback runs the handshake, so it receives the client's
`ClientHelloInfo` — the input to JA3/JA4. See
[docs/06](06-layer3-transport.md#23-capturing-the-clienthello-in-go).

---

## 4. The two-phase detection flow

The homepage is **an instrumented form** — a deliberate interaction surface. The
app detects in two phases so it can report immediately and then refine as the
visitor actually uses the form.

```
1. GET /  (a real top-level navigation)
     Server captures, for THIS connection: TLS/JA4, HTTP2 fingerprint,
     header values + order, IP/ASN. Stores them keyed to a fresh sessionId,
     which it embeds in the page. (Sec-Fetch-Mode: navigate here — the honest
     navigation semantics we want for Layer 2.)

2. PHASE 1 — on load (passive):
     Client collects passive Layer-1 signals (navigator, WebGL, canvas, audio,
     screen, fonts, locale, automation flags) and POSTs
     /api/analyze { sessionId, phase: 1, layer1 }.
     Server joins them with the stored connection signals, runs the scoring
     engine, and returns the INITIAL report: automation probability + banner +
     full checklist. The UI renders the green/red banner right away.

3. PHASE 2 — after the user fills the form (behavioral):
     The client instruments the form and streams interaction dynamics — typing
     cadence & variance, mouse path into each field, focus/tab order, paste vs
     type, backspace/correction rate, per-field dwell time, and fill→submit
     latency. On submit it POSTs /api/analyze { sessionId, phase: 2, behavior }.
     Server merges the behavioral signals, RE-SCORES, and returns the refined
     report. The banner, probability, and checklist update in place.
```

### 4.1 Why two phases

- **Instant feedback:** the visitor sees a verdict on load, before touching
  anything — the strongest tells (TLS≠UA, `webdriver`, headless) don't need
  interaction.
- **Behavioral lift:** *how* a form is filled is a large, hard-to-fake signal
  class. A script that fills every field in 40ms with zero mouse movement, tab
  order it never used, and no corrections looks nothing like a human. This can
  only be measured *after* interaction, so it's a second phase that tightens the
  estimate and raises confidence.
- **Confidence, not just score:** Phase 1 yields a probability at "passive"
  confidence; Phase 2 raises confidence because we now have behavioral
  corroboration (or contradiction).

### 4.2 Session correlation (same origin, no nonce)

Because everything is one origin on one server, correlation is trivial: a
`sessionId` (also mirrored in a `Secure; HttpOnly; SameSite=Strict` cookie) ties
the page-load connection capture to the phase-1 and phase-2 POSTs. Connection
signals are captured at `GET /` (the real navigation) and stored server-side with
a short TTL (e.g. 10 min). No cross-origin machinery.

---

## 5. Getting the client IP (and why datacenter IPs matter)

On a self-hosted server the socket `RemoteAddr` **is** the client's egress IP — no
`X-Forwarded-For` trust problem (unless you deliberately put an L4 proxy in
front, in which case honor `PROXY protocol` or a single trusted XFF hop). We
resolve it to an ASN and organization and flag **datacenter/cloud/hosting** ASNs.

A datacenter-owned IP **is a meaningful red flag** — genuine end users are
overwhelmingly on residential/mobile ASNs, while scrapers and bots run on AWS/GCP/
Azure/OVH/Hetzner/DigitalOcean. But it is **not proof**: developers browse from
cloud shells, and privacy-conscious users route through VPNs and hosting ASNs. So
it's weighted as a solid contributor, strongest **in combination** — the classic
automation cluster is *datacenter IP + `UTC`/mismatched timezone + `en-US` +
a scripting-stack TLS fingerprint*. Details and the ASN list are in
[docs/06 §4](06-layer3-transport.md#4-ip-reputation--asn) and
[docs/09 §5](09-reference-data.md#5-datacenter--cloud-asn-seed-list).

---

## 6. Recommended stack

| Concern | Choice | Why |
|---------|--------|-----|
| Server runtime | **Go**, single binary, terminates TLS | Raw `net.Listener` + `GetConfigForClient` expose the ClientHello; mature JA3/JA4 and HTTP/2 frame libraries; one language for the whole capture path. |
| Static assets | Served by the same Go binary via `embed.FS` | Same origin as the API → honest `Sec-Fetch-Site` on the analyze POSTs, no extra origin. |
| Frontend | **Vanilla JS + one small CSS file**, no framework, no CDN | Every added library changes the fingerprint we measure; keep the page dependency-free. |
| Session store | Short-TTL in-memory map (single instance) or Redis if you scale out | Holds `sessionId → connectionSignals` for ~10 min. No fingerprint persistence. |
| TLS | `autocert` (Let's Encrypt) in-process | Your process runs the handshake — the whole point. |
| ASN/geo | Static datacenter-ASN list offline; optional MaxMind/IPinfo behind an interface | Works with zero external deps; upgradeable. |

---

## 7. Architectural principles

1. **Own the socket.** TLS terminates in our process; that's what makes Layer 3
   real. Never put a TLS-terminating proxy in front.
2. **The frontend must not pollute its own measurement.** No React, no jQuery, no
   web-font CDN, no analytics. One small same-origin JS bundle.
3. **Report early, refine later.** Phase 1 gives an immediate probability; Phase 2
   tightens it with behavioral evidence. The UI updates in place.
4. **Never claim a signal you didn't capture.** On the self-hosted server all
   layers are available, but a specific probe can still fail (WebGL disabled,
   canvas blocked) — those render as captured-but-`unavailable`, excluded from
   scoring, never fabricated.
5. **Statelessness beyond the session.** The only server state is the short-TTL
   `sessionId → connectionSignals` map. No fingerprint is persisted past the
   session. This is a privacy stance and an ops simplification.
6. **Deterministic scoring.** Identical captured inputs → identical probability.
   Behavioral inputs are bounded so their noise refines but never solely creates a
   verdict.
