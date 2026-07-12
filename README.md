# Bot / Automation Detection Web App

A diagnostic web app that inspects the visiting client and reports the
**probability that the visitor is automated**. Think
[`bot.sannysoft.com`](https://bot.sannysoft.com) +
[`browserleaks.com`](https://browserleaks.com), reorganized as a single report
with one headline number — an **automation-probability score** — a big
green/red pass-or-fail banner, and a checklist of every individual test.

> **Purpose & scope.** This is a *diagnostic / testing* tool. It runs entirely on
> the visitor's own request, shows them what their own client leaks, and helps
> developers verify that legitimate automation (or a hardened browser) behaves
> consistently. It does **not** solve CAPTCHAs, bypass protections, evade
> detection, or attack third parties. Every signal it computes is about the
> caller inspecting themselves.

## The project is two parts

1. **Detection libraries** — small, composable, independently importable packages
   that do the actual detection: a browser client lib (Layer 1 + form behavior),
   server libs (Layer 2 HTTP capture, Layer 3 TLS/JA4/HTTP2 capture, IP/ASN), and a
   scoring engine, all speaking a shared, versioned wire schema. They're
   **flexible**: take all of them, or just the client-side piece, or just the
   server-side piece, or everything except Layer 3. Any layer can be absent — the
   engine scores whatever it gets and reports its coverage. They're **drop-in**:
   adding them to an existing app is ~1–3 lines (a script tag + a middleware wrap),
   after which detection runs **automatically in the background** and the host
   reads a verdict whenever it wants — or never ([docs/15](docs/15-drop-in-integration.md)).
   The server libs are offered per language — **Go first** (the only one where
   Layer-3 TLS capture is clean), with [`node/`](node/) and [`python/`](python/) as
   "to be implemented" stubs. See [docs/13](docs/13-libraries-and-packaging.md).
2. **The honeypot** — the deployable diagnostic app (the 3-step funnel + the
   report UI). It's **one consumer** of the libraries, wiring them together into
   the full three-layer experience. It has no detection logic of its own. See
   [docs/02](docs/02-deployment-topology.md) + [docs/08](docs/08-frontend-ui.md).

**Source layout:** [`go/`](go/) ✅ (reference impl) · [`node/`](node/) 🚧 ·
[`python/`](python/) 🚧 · `packages/` (browser client + JS engine + schema) ·
`config/` (shared scoring + reference data) · `honeypot/` (the app) · `docs/`.

## Quickstart — add detection to your own app

Detection is **two halves**: a tiny **client library** that watches the visitor
and a **server engine** that scores what it sends. You can adopt one or both.
The honeypot's **`/test`** mode is the complete, deployed reference — study
[`honeypot/server/main.go`](honeypot/server/main.go) and try it live:
**<https://35.202.101.31.sslip.io/test>** (blocks bots) ·
**[`/debug`](https://35.202.101.31.sslip.io/debug)** (shows every check).

### 1. Client — one script tag

Serve [`packages/client/botdetect.js`](packages/client/botdetect.js) and drop it
into your pages. `autostart()` attaches passive + behavioral collectors globally,
watches your existing forms/links, and posts batches to your endpoint. It never
calls `preventDefault`, adds no dependency, and is fully `try/catch`-isolated —
if it or the endpoint fails, your app is unaffected.

```html
<script src="/botdetect.js" defer></script>
<script>
  addEventListener("DOMContentLoaded", function () {
    // sessionId is issued by YOUR server (a cookie or a rendered value) so the
    // backend can tie these posts to the request it captured.
    window.botdetect.autostart({ endpoint: "/api/analyze", sessionId: window.__BD_SID });
  });
</script>
```

The collector watches **everything, continuously, across page loads** (behavioral
state persists in `sessionStorage`), so signals keep accumulating as the visitor
moves through a multi-page (non-SPA) app.

### 2. Server — score what arrives (Go)

Compose the libraries. Any layer can be absent — the engine scores whatever it
gets and reports its coverage. Minimal shape (see `main.go` for the full wiring):

```go
eng, _   := engine.New(botdetector.ScoringJSON)  // the scoring config
capt      := tlscapture.New()                    // Layer 3: JA3/JA4 + header order
classify := ipasn.New()                          // Layer 3: IP → ASN / datacenter

// Own the socket so the ClientHello reaches us (no proxy/CDN in front):
ln := capt.InstrumentListener(rawListener, tlsCfg)

// Per request, capture Layer 2/3 from the connection:
l2 := httpcapture.FromRequest(r, capt.HeaderOrderFor(r.RemoteAddr))
l3 := /* classify.Classify(r.RemoteAddr) + capt.TLSFor(r.RemoteAddr) */

// POST /api/analyze — the browser posts Layer 1 + behavior; you score the union:
var p schema.ClientPayload
json.NewDecoder(r.Body).Decode(&p)
report := eng.Score(schema.SignalSet{
    Layer1: p.Layer1, Layer2: l2, Layer3: l3,
    ScrollToLink: p.ScrollToLink, LinkClick: p.LinkClick,
    Behavior: p.Behavior, ClickPattern: p.ClickPattern, Typing: p.Typing,
})
// report.Score.Band ∈ {human, suspicious, automated}; report.Checks is the full list.
```

> **Layer 3 needs the socket.** JA3/JA4 and raw header order require terminating
> your own TLS — never put a TLS-terminating load balancer, CDN, or Cloudflare
> (proxied) in front, or Layer 3 is lost. Layers 1–2 work behind anything.

### 3. Enforce, or just observe

The verdict is yours to act on. The honeypot shows both modes off the same code:

- **`/test`** — enforces: it 403s a request whose server-only signals are
  conclusively a bot, and blocks at the end if the full verdict crosses the
  `BD_ENFORCE_BAND` threshold. Legit crawlers pass (see the allowlist below).
- **`/debug`** — never blocks; renders the live, growing checklist + score.

**Allowlist.** Verified good bots (Googlebot/Bingbot via reverse-DNS, OpenAI
crawlers via published IP ranges, Web Bot Auth signatures) and trusted
User-Agents (`BD_UA_ALLOWLIST`) bypass enforcement, so your content still gets
indexed. Real-time AI *fetchers* (ChatGPT-User, Perplexity-User) are treated as
automation.

**Lighter tiers** (client-only, or middleware without owning the socket) and the
non-interference guarantees are in
[docs/15 — Drop-in integration](docs/15-drop-in-integration.md).

## Two decisions that shape the honeypot

1. **We self-host on a server that terminates its own TLS.** Not a Google Cloud
   Function, not any managed serverless platform — those sit behind the Google
   Front End, which terminates TLS and normalizes HTTP before our code runs, so
   the ClientHello (JA3/JA4), the HTTP/2 fingerprint, and the real header order
   are gone. Owning the socket lets the honeypot capture **all three detection
   layers from a single connection**. (A consumer that *can't* own the socket
   still uses the same libraries — Layer 3 just reports `unavailable`.) See
   [docs/01](docs/01-architecture-and-hosting.md).
2. **The headline is an automation probability (0–100%), not a pass/fail flag.**
   Weighted evidence from every available layer is run through a calibrated
   logistic so the output reads as "≈93% likely automated," bucketed into a
   green/amber/red banner. See [docs/07](docs/07-coherence-engine.md).

## How a visit works (a 3-step funnel)

The honeypot is a three-page funnel; each page is a real navigation the server
re-captures, and each transition between pages is itself a detection signal.

```
PAGE 1  GET /test        Landing: some text + a link placed BELOW THE FOLD.
   │   server captures Layer 2 (headers, order) + Layer 3 (TLS/JA4, HTTP2, IP/ASN);
   │   client collects passive Layer 1 + instruments the SCROLL + the LINK click.
   │        ↓  the user SCROLLS to the link, then CLICKS it (real gesture + real click)
PAGE 2  GET /test/form    Form: name/email/topic/message + submit (+ hidden honeypot traps).
   │   server re-captures Layer 2/3 and VERIFIES the transition (real scroll + click?);
   │   client collects passive Layer 1 again + form behavior + trap outcomes.
   │        ↓  the user FILLS + SUBMITS the form
PAGE 3  GET /test/result  Report: the green/amber/red verdict, automationType, and
        the full checklist — aggregated across all three steps.
```

(Same three routes under **`/debug`** show the live checklist instead of enforcing.)

Three natural interactions — a **scroll** (the link is below the fold, so you must
scroll to reach it), a **link click**, then a **form fill** — instead of an
artificial "interact here" box. The funnel turns the **transitions** into signals:
did a *real scroll gesture* bring the link into view, or an automated
`scrollIntoView()` teleport? Did a real click produce Page 2, or did the client
deep-link to the form URL? Is it the **same JA4/IP** across all three navigations?
We record interaction *dynamics* and funnel *integrity*, never the field
*contents*. See [docs/02](docs/02-deployment-topology.md).

## Documentation

| # | Document | What it covers |
|---|----------|----------------|
| 00 | [Overview & scope](docs/00-overview.md) | Goals, non-goals, threat model, glossary |
| 01 | [Architecture & hosting](docs/01-architecture-and-hosting.md) | The three layers, why we self-host (and why *not* a Cloud Function), the two-phase flow |
| 02 | [Deployment](docs/02-deployment-topology.md) | The single self-hosted server, TLS/autocert, session capture, two-phase endpoints, serverless fallback |
| 03 | [API contract](docs/03-api-contract.md) | Endpoints, phase-1/phase-2 request & response JSON schemas, versioning |
| 04 | [Layer 1 — browser environment](docs/04-layer1-browser.md) | Every frontend collector + the form-behavior collector, with code sketches and thresholds |
| 05 | [Layer 2 — HTTP](docs/05-layer2-http.md) | Header values, client hints, `Sec-Fetch-*`, header order |
| 06 | [Layer 3 — transport](docs/06-layer3-transport.md) | TLS JA3/JA4, HTTP/2 fingerprint, IP/ASN & datacenter detection |
| 07 | [Scoring engine](docs/07-coherence-engine.md) | The automation-probability model, weights, contradiction rules, calibration, worked examples |
| 08 | [Frontend / report UI](docs/08-frontend-ui.md) | The form, the pass/fail banner, the live-updating checklist, "copy JSON" |
| 09 | [Reference fingerprints](docs/09-reference-data.md) | Known header orders, JA3/JA4, H2 settings, datacenter ASNs |
| 10 | [Privacy, security & abuse](docs/10-privacy-security.md) | Data handling, rate limiting, legal posture |
| 11 | [Testing & CI](docs/11-testing.md) | The validation matrix, automated harness, CI |
| 12 | [Roadmap & milestones](docs/12-roadmap.md) | Ordered build steps: libraries first, honeypot second |
| 13 | [Libraries & packaging](docs/13-libraries-and-packaging.md) | The two-part split: package boundaries, public APIs, the capability model, distribution |
| 14 | [Agentic & CDP detection](docs/14-agentic-and-cdp-detection.md) | Catching real-browser AI agents (Comet, Atlas, Claude computer-use, Operator, CDP stealth): input provenance, screenshot cadence, behavioral biometrics, CDP leaks, Web Bot Auth |
| 15 | [Drop-in integration](docs/15-drop-in-integration.md) | Adding the libraries to an existing app with ~1–3 lines; auto-instrumentation, background detection, the effort tiers, non-interference guarantees |

The honeypot self-hosts on a single server that terminates its own TLS. The split
app-plus-edge-probe design is retained only as a
[serverless fallback appendix](docs/02-deployment-topology.md#appendix--serverless-fallback-split-deployment)
for a consumer later forced onto a managed platform.
