# 12 — Roadmap & Milestones

Ordered build steps, each with a concrete acceptance criterion. The ordering
front-loads the highest-signal, verify-early work (header capture, then TLS) so
you find out immediately whether the hard parts work on your infrastructure —
exactly the risk the Google-Cloud-Function target introduces.

The single most important sequencing decision: **prove the edge-probe transport
capture works early (Milestone 3)**, because if it doesn't, the whole Layer-3
value proposition is gone and you'd rather know before building the UI on top of
it.

---

## Milestone 0 — Scaffold & decision lock

**Goal:** repo skeleton, topology chosen, config plumbing.

- Go module for the main app; `embed.FS` for static assets; `/`, `/api/health`,
  `/api/analyze` (stub returning `{}`).
- `CAPTURE_MODE` env plumbing (`a`/`b`/`c`) so coverage labeling exists from day
  one.
- Dockerfile + Cloud Run deploy of the stub.
- **Accept:** stub deploys to Cloud Run behind `app.example.com`; `/api/health`
  returns 200; a request logs the *filtered* client headers (GFE injections
  removed).

## Milestone 1 — Layer 2 header capture + hygiene

**Goal:** read and analyze header **values**, prove header **order** is lost on
Cloud Function.

- Header value analysis ([docs/05 §1–2](05-layer2-http.md)).
- Infrastructure-header deny-list ([docs/02 §1.4](02-deployment-topology.md#14-header-hygiene-filter-gfe-injections)).
- **Verify the GFE problem empirically:** hit the Cloud Function with curl and a
  real browser; confirm the header *order* your handler sees does **not** match
  the client's emission order (it's been normalized). Document the finding.
- **Accept:** report shows Layer-2 values; header-order signal is correctly
  marked `unavailable/normalized` on Topology A. curl vs. browser produce
  different *value* signals.

## Milestone 2 — Layer 1 collectors + end-to-end report (Topology A)

**Goal:** a working, honest, layers-1–2 diagnostic on a plain Cloud Function.

- Build each Layer-1 collector as an independent module
  ([docs/04](04-layer1-browser.md)), each testable in isolation.
- Add the behavioral collector (buffer ~3s, then submit).
- Implement the coherence engine for L1+L2 ([docs/07](07-coherence-engine.md)),
  with weights/thresholds in config.
- Build the report UI ([docs/08](08-frontend-ui.md)) + "copy JSON".
- **Accept:** deployed Topology-A tool correctly scores real Chrome
  `likely_human` and vanilla Puppeteer `likely_automated`; `curl + Chrome UA` is
  caught on Layer-2 values; Layer-3 section honestly says "unavailable."

> At this point you have a **shippable, useful product** — just without the
> strongest transport signals. Everything after this is raising the ceiling.

## Milestone 3 — Edge probe: TLS/JA4 capture (Topology B) ⭐ critical-path

**Goal:** prove you can capture the real client ClientHello on a raw-socket host.

- Stand up the edge probe on a VM/VPS with a static IP and `tls.example.com`
  (autocert). Terminate TLS in Go.
- Capture the ClientHello via `GetConfigForClient` + a raw-ClientHello tee for
  extension order; compute JA3 + JA4 ([docs/06 §2](06-layer3-transport.md#2-ja3--ja4)).
- **Verify curl and Chrome produce different JA4** against the probe — the core
  proof the whole layer works.
- **Accept:** hitting `tls.example.com` from Chrome yields a browser JA4; from
  curl/Go yields a library JA4; the two are clearly different.

## Milestone 4 — Correlation + merge (Topology B end-to-end)

**Goal:** stitch the probe's transport report into the app's report.

- Nonce mint → embed → probe fetch → store → `/api/analyze` merge
  ([docs/02 §3](02-deployment-topology.md#3-correlation-protocol)); in-memory
  probe map + authenticated `/result` for MVP.
- CORS on the probe locked to the app origin; keep the probe fetch a simple GET
  (no preflight).
- Same-client verification (probe IP/UA vs. app) + all failure-mode degradations.
- Wire `tls_ua_vendor_mismatch` and friends into the engine.
- **Accept:** the report now shows Layer 3; `curl + Chrome UA` trips
  `tls_ua_vendor_mismatch`; killing the probe degrades cleanly to Topology-A
  scoring with the "probe unreachable" label.

## Milestone 5 — HTTP/2 fingerprint + header order on the probe

**Goal:** the remaining Layer-2/3 transport signals.

- Read the H2 preface/frames on the probe; compute the Akamai-style H2 fingerprint
  and pseudo-header order ([docs/06 §3](06-layer3-transport.md#3-http2-fingerprint)).
- Capture true header **order** on the probe connection
  ([docs/05 §3](05-layer2-http.md#3-header-order)).
- Wire `h2_ua_vendor_mismatch` and `header_order_is_library`.
- **Accept:** H2 and header-order signals populate for probe-captured
  connections; scripting H2 clients are distinguishable from browsers.

## Milestone 6 — IP/ASN + locale/timezone coherence

**Goal:** the geo/network cross-checks.

- IP extraction (XFF on app, socket on probe), static datacenter-ASN list,
  optional provider behind an interface ([docs/06 §4](06-layer3-transport.md#4-ip-reputation--asn-works-on-all-topologies)).
- Timezone/locale joins: `Intl` tz vs. IP-geo tz; `Accept-Language` vs.
  `navigator.languages`; the datacenter+UTC+en-US cluster rule.
- **Accept:** a datacenter-hosted client with mismatched locale trips
  `lang_tz_ip_cluster`; residential real browser does not.

## Milestone 7 — Reference data + golden tests

**Goal:** turn illustrative references into captured real data and pin the matrix.

- Capture real fixtures for every matrix row ([docs/11 §3](11-testing.md#3-capturing-fixtures-how-to-build-the-golden-set)).
- Replace the illustrative header-order/JA4/H2 tables with captured values
  ([docs/09](09-reference-data.md)).
- Golden report tests assert verdict buckets for all rows.
- **Accept:** the full matrix ([docs/11 §1](11-testing.md#1-the-validation-matrix))
  passes its acceptance criteria; golden tests gate CI.

## Milestone 8 — Anti-tamper, hardening, polish

**Goal:** catch the stealth patches and finish the product.

- Anti-tamper sub-module ([docs/04 §4](04-layer1-browser.md#4-anti-tamper-notes-measuring-the-measurers))
  — patched-getter/`toString`/descriptor detection, iframe re-read.
- Rate limiting, body caps, CSP, privacy note, `PRIVACY.md`
  ([docs/10](10-privacy-security.md)).
- Observability: metrics (verdict distribution, probe reachability, nonce
  hit/miss), alerts.
- Accessibility pass on the UI; light/dark; reduced-motion.
- **Accept:** stealth-headless-on-CI (matrix row 15) is caught as ≥`suspicious`
  via a contradiction; privacy note live; probe-down alerting works.

## Milestone 9 — Optional: Topology C single-box + docs

**Goal:** a one-command self-hosted deploy for people who want max fidelity
without the split.

- `CAPTURE_MODE=c` all-in-one binary: terminates TLS, captures all layers from one
  connection, no nonce.
- Deploy guide for VM/VPS with autocert.
- **Accept:** the all-in-one binary produces a full three-layer report from a
  single connection.

---

## Dependency graph (what blocks what)

```
M0 ─▶ M1 ─▶ M2 (shippable Topology A)
                │
                ▼
M3 (edge probe TLS ⭐) ─▶ M4 (correlation) ─▶ M5 (H2 + order) ─▶ M6 (IP/locale)
                                                                      │
                                                                      ▼
                                                        M7 (references + golden)
                                                                      │
                                                                      ▼
                                                        M8 (anti-tamper + hardening)
                                                                      │
                                                                      ▼
                                                        M9 (optional single-box)
```

- **M2 is the first shippable release** — an honest layers-1–2 tool.
- **M3 is the critical-path risk** — if raw TLS capture doesn't work on your host,
  you learn it here, before building M4–M8 on top.
- M7 (real reference data) can begin in parallel once M3–M5 give you a capture
  mechanism to generate fixtures with.

---

## Definition of done (v1)

1. Deployed in Topology B: app on Cloud Run, probe on a raw-socket host.
2. Full three-layer report with the coherence engine and contradiction list.
3. The validation matrix passes its acceptance criteria, pinned by golden tests
   in CI.
4. Graceful degradation to Topology A when the probe is unavailable, always
   honestly labeled.
5. Privacy note, rate limiting, CSP, and metrics in place.
6. The stealth-headless case is caught by a **contradiction**, not a single flag —
   the thesis, demonstrated.
