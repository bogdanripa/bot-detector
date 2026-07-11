# 12 — Roadmap & Milestones

Ordered build steps, each with a concrete acceptance criterion. The ordering
front-loads the highest-risk, highest-signal work — **proving raw TLS capture on
the self-hosted box (Milestone 1)** — because if owning the socket doesn't yield a
real ClientHello on your host, the whole Layer-3 thesis is gone and you want to
know that before building anything on top of it.

Target deployment: the **single self-hosted TLS-terminating server** with the
**two-phase** flow and an **automation-probability** headline.

---

## Milestone 0 — Scaffold

**Goal:** repo skeleton and a TLS-terminating server that serves a page.

- Go module; `embed.FS` for static assets; `GET /`, `GET /api/health`,
  `POST /api/analyze` (stub returning `{}`).
- In-process TLS via `autocert` (prod) and `mkcert` (local `app.localtest.me`).
- `sessionId` minting at `GET /` + `Secure;HttpOnly;SameSite=Strict` cookie +
  bootstrap island.
- **Accept:** server terminates its own TLS locally and in prod; `/api/health`
  200; a page load mints a session and logs the client's socket IP.

## Milestone 1 — TLS / JA4 capture ⭐ critical-path

**Goal:** prove we capture the real client ClientHello on our own socket.

- Capture the ClientHello via `GetConfigForClient` + a raw-ClientHello tee for
  extension order; compute JA3 + JA4 ([docs/06 §2](06-layer3-transport.md#2-ja3--ja4)).
- Bind the per-connection fingerprint to the session created at `GET /`.
- **Verify Chrome vs. curl produce different JA4** against the server — the core
  proof the layer works.
- **Accept:** a page load from Chrome yields a browser JA4; from curl/Go a library
  JA4; the two clearly differ and are attached to the session.

## Milestone 2 — Layer 2 capture (values + true order) + hygiene

**Goal:** header values and real order from the navigation.

- Read header **values** and true **order** from the `GET /` navigation
  ([docs/05](05-layer2-http.md)); store on the session.
- Hop-by-hop / proxy header hygiene ([docs/02 §1.3](02-deployment-topology.md#13-header-hygiene)).
- **Accept:** curl vs. Chrome differ on both header values *and* order; the order
  matches known browser/library reference shapes.

## Milestone 3 — Layer 1 passive collectors + phase-1 report

**Goal:** a working phase-1 report (passive server + client) with a pass/fail
banner.

- Each Layer-1 passive collector as an independent module
  ([docs/04 §2.1–2.7](04-layer1-browser.md)).
- `POST /api/analyze {phase:1}` merges connection signals + passive Layer 1.
- **Accept:** phase-1 report renders for real Chrome (clean) and vanilla Puppeteer
  (multiple `fail`s), joining all three layers on one connection.

## Milestone 4 — Scoring engine v1 (automation probability)

**Goal:** the calibrated-logistic headline + banner + checklist.

- Signal weights, `b0`, caps, and thresholds in one config
  ([docs/07 §2–4](07-coherence-engine.md)).
- Contradiction rules registry, incl. `tls_ua_vendor_mismatch`,
  `header_order_is_library`, `os_triangulation_mismatch`.
- Logistic → probability → band; `critical floor`; confidence.
- **Accept:** real Chrome ≈5% (`human`/PASS); `curl+Chrome UA` ≈99%
  (`automated`/FAIL) via `tls_ua_vendor_mismatch`; the report exposes a
  `scoreTrace` in debug mode.

## Milestone 5 — The form + phase-2 behavior

**Goal:** the instrumented homepage form and the behavioral refinement pass.

- Build the form ([docs/08 §3](08-frontend-ui.md#3-the-form-interaction-surface))
  and the form-behavior collector
  ([docs/04 §2.8](04-layer1-browser.md#28-form-behavior-signals-phase-2)) —
  dynamics only, never contents.
- `POST /api/analyze {phase:2}` delta re-scores; bounded/gated behavior group;
  `phaseDelta` in the response.
- UI updates the banner + checklist in place, highlighting changes.
- **Accept:** a human filling the form naturally keeps `human` with rising
  confidence; a scripted sub-100ms zero-variance fill adds behavioral `fail`s;
  autofill is not penalized; behavior never flips a clean human to `automated`.

## Milestone 6 — Report UI polish

**Goal:** the finished report surface.

- Big green/amber/red banner with probability + confidence; grouped, collapsible
  checklist with `pass/warn/fail/unavailable` badges; contradictions on top;
  "copy JSON"; "re-run" ([docs/08](08-frontend-ui.md)).
- Accessibility (aria-live banner, text+shape+color badges, keyboard form),
  light/dark, reduced-motion, strict CSP, dependency-free frontend.
- **Accept:** the full report renders and updates across both phases; passes an
  a11y check; the page makes zero third-party requests.

## Milestone 7 — HTTP/2 fingerprint + IP/ASN + locale coherence

**Goal:** the remaining transport and network cross-checks.

- H2 preface/frames → Akamai-style fingerprint + pseudo-header order
  ([docs/06 §3](06-layer3-transport.md#3-http2-fingerprint)); wire
  `h2_ua_vendor_mismatch`.
- Socket IP → ASN; static datacenter list + optional provider behind an interface;
  wire `ip_datacenter` (warn) and `lang_tz_ip_cluster`
  ([docs/06 §4](06-layer3-transport.md#4-ip-reputation--asn)).
- Timezone/locale joins (`Intl` tz vs. IP-geo; `Accept-Language` vs.
  `navigator.languages`).
- **Accept:** scripting H2 clients are distinguishable from browsers; a
  datacenter-hosted client with mismatched locale trips `lang_tz_ip_cluster`; a
  residential real browser does not; a developer on a cloud shell stays `human`
  with an amber network warning.

## Milestone 8 — Reference data + golden tests + calibration

**Goal:** real reference data, a pinned matrix, a calibrated probability.

- Capture real fixtures for every matrix row
  ([docs/11 §3](11-testing.md#3-capturing-fixtures-how-to-build-the-golden-set));
  replace the illustrative reference tables with captured values
  ([docs/09](09-reference-data.md)).
- Fit `b0`/scale so the probability separates the labeled classes; pin bands (and
  P within tolerance) with golden tests.
- **Accept:** the full matrix ([docs/11 §1](11-testing.md#1-the-validation-matrix))
  passes its acceptance criteria; golden + schema + unit tests gate CI.

## Milestone 9 — Anti-tamper, hardening, observability

**Goal:** catch the stealth patches and finish for production.

- Anti-tamper sub-module
  ([docs/04 §4](04-layer1-browser.md#4-anti-tamper-notes-measuring-the-measurers)).
- Rate limiting, body caps, session binding, `PRIVACY.md` + in-UI privacy note
  ([docs/10](10-privacy-security.md)).
- Metrics (band distribution, phase-2 completion rate, session hit/miss, cert
  renewal) + alerts.
- **Accept:** stealth-headless-on-CI (matrix row 15) is caught as ≥`suspicious`
  via a contradiction; privacy note live; alerting on a Layer-3 capture collapse
  (would mean a proxy crept in front of TLS).

---

## Dependency graph

```
M0 ─▶ M1 (TLS/JA4 ⭐) ─▶ M2 (L2 values+order) ─▶ M3 (L1 passive, phase-1 report)
                                                     │
                                                     ▼
                              M4 (scoring engine: automation probability)
                                                     │
                                                     ▼
                              M5 (form + phase-2 behavior) ─▶ M6 (report UI polish)
                                                     │
                                                     ▼
                              M7 (H2 + IP/ASN + locale) ─▶ M8 (references + golden + calibration)
                                                     │
                                                     ▼
                              M9 (anti-tamper + hardening + observability)
```

- **M1 is the critical-path risk** — prove raw TLS capture on your host first.
- **M3+M4 is the first shippable release** — a phase-1 automation-probability
  report across all three layers, before the form even exists.
- **M5 adds the behavioral phase**; M7 completes the transport/network signals;
  M8 makes the probability trustworthy with real data and calibration.

---

## Definition of done (v1)

1. Single self-hosted server terminating its own TLS, capturing all three layers on
   the page-navigation connection.
2. Two-phase flow: an immediate phase-1 automation probability + banner +
   checklist, refined by phase-2 form behavior.
3. Calibrated automation-probability headline with a green/amber/red banner and a
   per-check list; contradictions surfaced separately.
4. The validation matrix passes its acceptance criteria, pinned by golden tests in
   CI; the probability is calibrated across the labeled classes.
5. Privacy note, rate limiting, strict CSP, and metrics in place; field contents
   never leave the browser.
6. The stealth-headless case is caught by a **contradiction**, not a single flag —
   the thesis, demonstrated.
