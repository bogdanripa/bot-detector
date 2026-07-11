# Bot / Automation Detection Web App

A diagnostic web app that inspects the visiting client and reports every signal
a real anti-bot system would use to suspect automation. Think
[`bot.sannysoft.com`](https://bot.sannysoft.com) +
[`browserleaks.com`](https://browserleaks.com), reorganized as a single coherent
report with a cross-layer **coherence / consistency score**.

> **Purpose & scope.** This is a *diagnostic / testing* tool. It runs entirely on
> the visitor's own request, shows them what their own browser leaks, and helps
> developers verify that legitimate automation (or a hardened browser) behaves
> consistently. It does **not** solve CAPTCHAs, bypass protections, evade
> detection, or attack third parties. Every signal it computes is about the
> caller inspecting themselves.

## Documentation

The full build plan lives in [`docs/`](docs/). Read it in order:

| # | Document | What it covers |
|---|----------|----------------|
| 00 | [Overview & scope](docs/00-overview.md) | Goals, non-goals, threat model, glossary |
| 01 | [Architecture & hosting](docs/01-architecture-and-hosting.md) | The three layers, **why Google Cloud Functions changes everything**, recommended deployment topologies |
| 02 | [Deployment topology](docs/02-deployment-topology.md) | Cloud Run / GCF config, the separate "edge probe" host, DNS, CORS, correlation protocol |
| 03 | [API contract](docs/03-api-contract.md) | Endpoints, request/response JSON schemas, versioning |
| 04 | [Layer 1 — browser environment](docs/04-layer1-browser.md) | Every frontend collector, with code sketches, thresholds, verdict logic |
| 05 | [Layer 2 — HTTP](docs/05-layer2-http.md) | Header values, client hints, `Sec-Fetch-*`, header order (and its GCF caveats) |
| 06 | [Layer 3 — transport](docs/06-layer3-transport.md) | TLS JA3/JA4, HTTP/2 fingerprint, IP/ASN — captured on the edge probe |
| 07 | [Coherence engine](docs/07-coherence-engine.md) | The scoring model, weights, contradiction rules, worked examples |
| 08 | [Frontend / report UI](docs/08-frontend-ui.md) | Page structure, rendering, "copy JSON", accessibility |
| 09 | [Reference fingerprints](docs/09-reference-data.md) | Known-good header orders, JA3/JA4, H2 settings, datacenter ASNs |
| 10 | [Privacy, security & abuse](docs/10-privacy-security.md) | Data handling, rate limiting, legal posture |
| 11 | [Testing & CI](docs/11-testing.md) | The validation matrix, automated harness, CI |
| 12 | [Roadmap & milestones](docs/12-roadmap.md) | Ordered build steps with acceptance criteria |

## TL;DR of the most important decision

Detection has three layers. A JS-only app cannot see layers 2–3 correctly, so a
backend is required — **but a plain Google Cloud Function cannot see layer 3 at
all**, and sees layer 2 only partially. The Google Front End (GFE) terminates
TLS and normalizes HTTP before your code runs, so the ClientHello, the HTTP/2
fingerprint, and the original header order are gone by the time your function
executes.

The recommended architecture is therefore a **split deployment**:

```
                            ┌──────────────────────────────────────┐
   Browser  ───────────────▶│  App  (Cloud Run / GCF gen2)         │  Layer 1 + Layer 2 (values) + UI + scoring
      │                     │  app.example.com                     │
      │                     └──────────────────────────────────────┘
      │
      │  cross-origin fetch  ┌──────────────────────────────────────┐
      └────────────────────▶ │  Edge probe (raw-socket host)        │  Layer 2 (order) + Layer 3 (TLS/H2/IP)
                             │  tls.example.com  — YOU terminate TLS │
                             └──────────────────────────────────────┘
```

The two responses are correlated by a nonce and merged by the coherence engine.
If you deploy **only** the Cloud Function, the app still works — it just labels
the transport signals as "unavailable on this deployment" and scores on layers
1–2. See [docs/01](docs/01-architecture-and-hosting.md) for the full reasoning
and fallbacks.
