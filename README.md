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

## The two decisions that shape everything

1. **We self-host on a server that terminates its own TLS.** Not a Google Cloud
   Function, not any managed serverless platform — those sit behind the Google
   Front End, which terminates TLS and normalizes HTTP before our code runs, so
   the ClientHello (JA3/JA4), the HTTP/2 fingerprint, and the real header order
   are gone. Owning the socket means we capture **all three detection layers from
   a single connection**, with no edge probe and no correlation nonce. See
   [docs/01](docs/01-architecture-and-hosting.md).

2. **The headline is an automation probability (0–100%), not a pass/fail flag.**
   Weighted evidence from every layer is run through a calibrated logistic so the
   output reads as "≈93% likely automated," bucketed into a green/amber/red
   banner. See [docs/07](docs/07-coherence-engine.md).

## How a visit works (two-phase detection)

```
GET /  (page load, real navigation)
   │  server captures Layer 2 (headers, order) + Layer 3 (TLS/JA4, HTTP2, IP/ASN)
   │  for THIS connection, keyed to a session
   ▼
Phase 1 — on load:  client collects passive Layer-1 signals (navigator, WebGL,
   canvas, screen, fonts…) and POSTs them. Server merges with the connection
   signals and returns an INITIAL automation probability + full checklist.
   The page renders the green/red banner immediately.
   ▼
Phase 2 — after the user fills in the on-page form:  the client streams
   behavioral dynamics (typing cadence, mouse path to fields, focus order,
   paste, corrections, submit timing) and POSTs them. The server refines the
   probability and the banner/checklist update live.
```

The homepage is **a real, instrumented form** — that's the deliberate interaction
surface that lets us watch *how* the visitor operates the app, which is a rich
extra source of human-vs-scripted signal. We record interaction *dynamics*, never
the field *contents*.

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
| 12 | [Roadmap & milestones](docs/12-roadmap.md) | Ordered build steps with acceptance criteria |

Deployment target is now the single self-hosted server ("Topology C" in the
architecture doc). The split app-plus-edge-probe design is retained only as a
[serverless fallback appendix](docs/02-deployment-topology.md#appendix--serverless-fallback-split-deployment)
for anyone later forced onto a managed platform.
