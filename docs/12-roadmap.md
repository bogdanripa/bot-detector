# 12 — Roadmap & Milestones

Ordered build steps, each with a concrete acceptance criterion. The project is
**two parts** ([docs/13](13-libraries-and-packaging.md)) — detection **libraries**
and the **honeypot** that consumes them — so the roadmap builds the libraries
first (each independently testable) and assembles the honeypot from them.

The ordering front-loads the highest-risk work — **proving raw TLS capture in the
`tlscapture` library (M2)** — because if owning the socket doesn't yield a real
ClientHello, the whole Layer-3 thesis is gone and you want to know before building
on it.

---

## Part A — the detection libraries

### M0 — Repo scaffold & the shared schema

- Monorepo layout ([docs/13 §2](13-libraries-and-packaging.md#2-repository-layout-monorepo)):
  `packages/*` (npm), `go/*` (Go modules), `config/`, `honeypot/`.
- **`@botdetect/schema` / `go/schema`**: define the wire types
  ([docs/03](03-api-contract.md)) as JSON Schema; code-gen TS + Go.
- **`config/scoring.json`** skeleton + loader.
- **Accept:** `schema` builds in both languages from one source; a trivial
  round-trip test (encode in TS → decode in Go) passes.

### M1 — `@botdetect/client` (Layer 1 collectors)

- Each passive collector as an independent module
  ([docs/04 §2.1–2.7](04-layer1-browser.md)); `collectPassive()` never throws,
  failed probes report `unavailable`; `include`/`exclude` selection.
- **Accept:** in real Chrome returns clean signals; in headless Playwright lights
  up `webdriver`/headless tells; unit-tested in jsdom + a headless browser.

### M2 — `go/tlscapture` (Layer 3 TLS/JA4) ⭐ critical-path

- Capture the ClientHello via `GetConfigForClient` + a raw-ClientHello tee for
  extension order; compute JA3 + JA4 ([docs/06 §2](06-layer3-transport.md#2-ja3--ja4)).
- Public API: `InstrumentConfig` / `InstrumentListener` / `ForConn`
  ([docs/13 §3.4](13-libraries-and-packaging.md#34-gotlscapture-go--layer-3-transport)).
- **Verify Chrome vs. curl produce different JA4** through the library — the core
  proof. Behind a proxy, `ForConn` returns nil (tested).
- **Accept:** a browser connection yields a browser JA4, curl a library JA4, in a
  standalone test harness that terminates TLS.

### M3 — `go/httpcapture` (Layer 2) + `go/ipasn` (Layer 3 IP)

- `httpcapture`: header values from any request; header order from a
  socket-owning listener (via `tlscapture`); `unavailable` order otherwise
  ([docs/05](05-layer2-http.md)).
- `ipasn`: IP → ASN, static datacenter list, provider interface
  ([docs/06 §4](06-layer3-transport.md#4-ip-reputation--asn)).
- **Accept:** curl vs. Chrome differ on header values *and* order; a datacenter IP
  classifies as such; both usable standalone in a plain `net/http` server.

### M4 — the scoring engine (`go/engine` + `@botdetect/engine`)

- Pure `SignalSet -> Report` over `config/scoring.json`: weights, contradiction
  rules, logistic → probability, bands, confidence, `critical floor`
  ([docs/07](07-coherence-engine.md)).
- **Capability/degradation is a first-class feature:** feed a `SignalSet` with any
  layer nil → correct `coverage`, adjusted `confidence`, no crash
  ([docs/13 §4](13-libraries-and-packaging.md#4-the-capability-model-flexibility)).
- JS engine interprets the same config; cross-checked against the Go engine.
- **Accept:** real Chrome ≈5% (`human`); `curl+Chrome UA` ≈99% (`automated`) via
  `tls_ua_vendor_mismatch`; a Layer-1-only `SignalSet` still scores with reduced
  confidence and correct coverage; Go and JS engines agree within tolerance on
  shared fixtures.

### M5 — form-behavior collection in `@botdetect/client`

- `instrumentForm()` capturing dynamics only ([docs/04 §2.8](04-layer1-browser.md#28-form-behavior-signals-phase-2));
  the bounded/gated behavior group in the engine
  ([docs/07 §2.6](07-coherence-engine.md#26-form-behavior-layer-1-phase-2-bounded)).
- **Accept:** natural fills keep `human` with rising confidence; scripted
  sub-100ms zero-variance fills add behavioral `fail`s; autofill isn't penalized;
  behavior alone never flips a clean human to `automated`.

---

## Part B — the honeypot (assembling the libraries)

### M6 — honeypot server: the 3-step funnel (compose the Go libs)

- `honeypot/server`: TLS-terminating Go server that wires `tlscapture` +
  `httpcapture` + `ipasn` + `engine`; the three routes `GET /`, `GET /step-2`,
  `GET /result` + `POST /api/analyze` (per step) + `POST /api/submit`; per-page
  connSignals capture and session/funnel state; the click-gated funnel token; the
  funnel-integrity checks (`funnel_bypass`, `cross_nav_inconsistency`)
  ([docs/02](02-deployment-topology.md)); `autocert`.
- **Accept:** traversing `/` → `/step-2` → `/result` captures all three layers on
  each navigation; a deep-link straight to `/step-2` trips `funnel_bypass`; a JA4
  change between pages trips `cross_nav_inconsistency`; `/api/health` green;
  deploys to a VM.

### M7 — honeypot web app: the three pages (compose the client lib) + report UI

- `honeypot/web`: one small `app.js` (branches on `bootstrap.step`) imports
  `@botdetect/client`; **Page 1** landing with an instrumented link; **Page 2** the
  form + honeypot traps; **Page 3** the report — green/amber/red banner +
  `automationType` + checklist + contradictions + "copy JSON" + "re-run"
  ([docs/08](08-frontend-ui.md)).
- Accessibility, light/dark, reduced-motion, strict CSP, dependency-free frontend.
- **Accept:** the full funnel runs; Page 3 renders the aggregated report; a real
  click on Page 1 activates the funnel token; a11y check passes (traps don't catch
  assistive tech); zero third-party requests.

### M8 — HTTP/2 fingerprint + locale coherence

- H2 fingerprint in `tlscapture` ([docs/06 §3](06-layer3-transport.md#3-http2-fingerprint));
  `h2_ua_vendor_mismatch`; timezone/locale joins and `lang_tz_ip_cluster` in the
  engine.
- **Accept:** scripting H2 clients distinguishable from browsers; a
  datacenter+mismatched-locale client trips `lang_tz_ip_cluster`; a dev on a cloud
  shell stays `human` with an amber warning.

### M9 — agentic & CDP detection ([docs/14](14-agentic-and-cdp-detection.md))

The modern frontier: catching real-browser AI agents (Comet, Atlas, Claude
computer-use, Operator, CDP stealth) that pass every passive check. Depends on the
client lib (M1/M5) and engine (M4); can be pulled earlier if agents are the
priority.

- **`@botdetect/client`:** `cdpLeaks` (Runtime.enable + the rebrowser leak set),
  `inputProvenance` (teleport / no-coalesced / exact-center clicks), `cadence`
  (perceive→think→act timing), expanded `biometrics`.
- **`go/httpcapture`:** Web Bot Auth (RFC 9421) signature parsing/verification +
  server-side product tells (`Atlas`/`Comet`/`PerplexityBot` UA, `CFNetwork`/`Darwin`).
- **`engine`:** the `clean_env_agentic_behavior` contradiction, the new signal
  groups, and `automationType` inference.
- **Accept:** a CDP-driven agent trips `runtimeEnableLeak`; a computer-use/Operator
  agent (OS-level input, clean environment) is caught via input provenance +
  cadence and labeled `agentic-os`; a valid Web-Bot-Auth request is `agentic-declared`;
  **a human merely reading in Comet/Atlas is not penalized** (the false-positive
  guard, [docs/14 §11](14-agentic-and-cdp-detection.md#11-testing-additions-agent-matrix)).

### M10 — reference data, golden tests & calibration

- Capture real fixtures for every matrix row (incl. the agentic rows)
  ([docs/11 §3](11-testing.md#3-capturing-fixtures-how-to-build-the-golden-set));
  replace illustrative reference tables ([docs/09](09-reference-data.md)); fit
  `config/scoring.json` so the probability calibrates.
- **Accept:** the matrix ([docs/11 §1](11-testing.md#1-the-validation-matrix))
  passes; golden + schema + unit tests (per library) gate CI; Go/JS engines agree.

### M11 — anti-tamper, hardening, observability, distribution

- Anti-tamper in `@botdetect/client`
  ([docs/04 §4](04-layer1-browser.md#4-anti-tamper-notes-measuring-the-measurers)).
- Honeypot hardening: rate limiting, body caps, session binding, `PRIVACY.md` +
  in-UI note ([docs/10](10-privacy-security.md)); metrics + alerts.
- **Publish the libraries** — npm for `packages/*`, tagged Go modules for `go/*` —
  with READMEs and the integration recipes
  ([docs/13 §5](13-libraries-and-packaging.md#5-integration-recipes)).
- **Accept:** stealth-headless-on-CI (matrix row 15) caught ≥`suspicious` via a
  contradiction; libraries install and run in a fresh external project per each
  recipe (server-only, client-only, full).

---

## Dependency graph

```
Part A (libraries)
  M0 (schema) ─▶ M1 (client L1)
             └─▶ M2 (tlscapture ⭐) ─▶ M3 (httpcapture + ipasn)
                                          │
             ┌────────────────────────────┘
             ▼
  M4 (engine, degradation-aware) ─▶ M5 (client form behavior)

Part B (honeypot, consumes A)
  M6 (server compose) ─▶ M7 (web + UI) ─▶ M8 (H2 + locale)
                                              │
                                              ▼
  M9 (agentic & CDP detection) ─▶ M10 (references + calibration) ─▶ M11 (harden + publish)
```

- **M2 is the critical-path risk** — prove raw TLS capture first.
- **M4 is the first independently useful artifact** — a degradation-aware engine
  that a server-only or client-only consumer can use *before the honeypot exists*.
- **M6+M7 is the first shippable honeypot** — the reference integration proving the
  libraries compose into the full three-layer, three-step-funnel experience.
- **M9 is the frontier** — on-device agentic-browser detection; pull it earlier if
  catching Comet/Atlas/computer-use is the priority rather than a later hardening
  step.

---

## Definition of done (v1)

1. Detection **libraries** published and independently usable per the integration
   recipes: client-only, server-only, full stack, and Layer-3-absent — the engine
   scores each honestly with correct coverage/confidence.
2. Shared, versioned wire schema; Go and JS engines agree on shared fixtures.
3. The **honeypot** self-hosts, terminates its own TLS, and delivers the 3-step
   funnel's automation-probability report (banner + checklist + contradictions +
   funnel integrity) by composing
   the libraries with no detection logic of its own.
4. The validation matrix passes, pinned by golden tests in CI; the probability is
   calibrated across the labeled classes.
5. Privacy note, rate limiting, strict CSP, metrics in place; field contents never
   leave the browser.
6. The stealth-headless case is caught by a **contradiction**, not a single flag —
   the thesis, demonstrated.
7. **On-device agentic browsers** (Comet, Atlas, Claude computer-use, Operator) are
   caught via input provenance + cadence + CDP leaks and labeled with an
   `automationType`, while a human *using* an AI browser is not penalized —
   [docs/14](14-agentic-and-cdp-detection.md).
