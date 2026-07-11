# 11 — Testing & CI

The tool's credibility rests on it scoring the right clients the right way. That
requires a **validation matrix** of real clients plus automated regression tests
that pin known cases so weight-tuning can't silently break them.

---

## 1. The validation matrix

Run each client against a deployed instance of the self-hosted server (all layers
are live) and record the verdict. The expected column is the acceptance criterion.
The `likely_human`/`likely_automated` labels below map to the `human`/`automated`
bands in [docs/07 §4.1](07-coherence-engine.md#41-from-probability-to-band).

| # | Client | Expected verdict | Which signals should fire |
|---|--------|------------------|---------------------------|
| 1 | Real Chrome desktop (Win/mac/Linux) | `likely_human` | none / clean |
| 2 | Real Firefox desktop | `likely_human` | none (note: no client hints — must NOT be penalized) |
| 3 | Real Safari desktop | `likely_human` | none (no client hints, distinct TLS) |
| 4 | Real Chrome Android | `likely_human` | mobile hints consistent |
| 5 | Real Safari iOS | `likely_human` | mobile consistent |
| 6 | `curl` (default) | `likely_automated` | header values, header order, JA4=library |
| 7 | `curl` + spoofed Chrome UA | `likely_automated` | `tls_ua_vendor_mismatch`, `header_order_is_library` |
| 8 | Python `requests` (spoofed UA) | `likely_automated` | same as 7, requests JA4 |
| 9 | Go `http.Client` (spoofed UA) | `likely_automated` | Go JA4 + Go header order |
| 10 | Node `undici`/`fetch` (spoofed UA) | `likely_automated` | undici JA4/H2 |
| 11 | Puppeteer headless (vanilla) | `likely_automated` | `webdriver`, `HeadlessChrome`, permissions, software WebGL |
| 12 | Puppeteer headed (vanilla) | `suspicious`–`likely_automated` | `webdriver`, flat behavior |
| 13 | Playwright headless (vanilla) | `likely_automated` | webdriver/automation globals, headless tells |
| 14 | Playwright headed (vanilla) | `suspicious`–`likely_automated` | webdriver, behavior |
| 15 | `puppeteer-extra-plugin-stealth` headless on Linux CI | `suspicious` | `os_triangulation_mismatch` (Linux WebGL/fonts vs spoofed Win UA), anti-tamper, behavior |
| 16 | Stealth, headed, real Windows host, human-driven | `likely_human` | correctly clean — the honest limit of detection |
| 17 | Selenium + ChromeDriver | `likely_automated` | `cdc_` artifacts, webdriver |
| 18 | Anti-detect browser (Multilogin/GoLogin) | `suspicious` | internal inconsistency in spoofed values / TLS-vs-UA |
| 19 | Real browser via CDP, no stealth | `suspicious` | subtle automation globals, behavior |
| 20 | Hardened privacy browser (Tor/Brave resistFingerprinting) | `suspicious` (expected FP) | canvas blocked, spoofed values — **documented as an accepted false positive** |

**Agentic rows (21–28)** — the on-device AI-agent clients (CDP stealth,
`browser-use`, Perplexity Comet, ChatGPT Atlas, Claude computer-use, Operator,
Operator+Web-Bot-Auth, and the false-positive guard "human reading in an AI
browser"). These have their own expected `automationType` and are specified in
**[docs/14 §11](14-agentic-and-cdp-detection.md#11-testing-additions-agent-matrix)**.
They are the modern frontier and the reason for the input-provenance / cadence /
CDP-leak collectors.

**Funnel rows** — for a subset, traverse the full **3-step funnel** (docs/02) and
assert: the passive signals land the right band early; a real click on Page 1
activates the funnel token; the form-behavior step either raises confidence (natural
human fill) or adds a behavioral `fail` (scripted fill); a clean human is *not*
flipped to `automated` by behavior alone (the bounded/gated group,
[docs/07 §2.6](07-coherence-engine.md#26-form-behavior-layer-1-phase-2-bounded));
and autofill/password-manager fills are not penalized. Add explicit
**funnel-integrity** cases: a client that **deep-links to `/step-2`** trips
`funnel_bypass`; a run whose **JA4/UA/IP changes between navigations** trips
`cross_nav_inconsistency`; a Page-2 navigation with **no trusted click** (no
`Sec-Fetch-User`/token) is flagged.

### Acceptance criteria (bands map to the probability, [docs/07 §4.1](07-coherence-engine.md#41-from-probability-to-band))

- Rows 1–5: `human` (probability < 0.30), no `fail`-status check fires.
- Rows 6–14, 17: `automated` (probability > 0.70).
- Rows 15, 18, 19: at least `suspicious` (the "hard but catchable" band).
- Row 16: `human` — and the report explicitly states the detection limit.
- Row 20: `suspicious`, and the report notes it's a likely false positive from
  fingerprint hardening (this is a *feature* for that user).
- **Calibration:** across the whole matrix, the automation probability separates
  the labeled human/automated classes cleanly (humans cluster low, bots high),
  verified as part of the calibration procedure
  ([docs/07 §7](07-coherence-engine.md#7-implementation-notes)).

---

## 2. Automated test layers

### 2.1 Unit tests (per library, in isolation)

The two-part split ([docs/13 §8](13-libraries-and-packaging.md#8-testing-implications))
means most coverage lives in the libraries; the honeypot gets only a thin e2e.

- **`@botdetect/client` collectors:** run in a headless browser (Playwright) and in
  jsdom; assert each returns the right shape and doesn't throw when an API is
  missing.
- **Engine rules (`go/engine`):** pure functions — table-driven Go tests. Each rule
  has fixtures that fire it and fixtures that don't; rules must be individually
  pinned.
- **Engine degradation:** feed `SignalSet`s with layers set to nil and assert the
  `coverage`, `confidence`, and verdict behave — the capability model
  ([docs/13 §4](13-libraries-and-packaging.md#4-the-capability-model-flexibility))
  is tested directly, not just via the honeypot.
- **Go ↔ JS engine agreement:** run both engines over the same `SignalSet` fixtures
  and assert the probability matches within tolerance (same `scoring.json`).
- **`go/tlscapture` JA3/JA4/H2:** feed captured raw ClientHello / H2 preface bytes;
  assert the computed fingerprint matches the expected string/hash; assert
  `ForConn` returns nil when TLS wasn't terminated locally.
- **`go/httpcapture` header-order:** table tests over reference vs. captured
  sequences; assert order is `unavailable` without a socket-owning listener.
- **`go/ipasn`:** IP fixtures → expected ASN/datacenter classification.

### 2.2 Golden report tests (the regression backbone)

- Capture a **real fixture** for each matrix row: the exact Layer-1 JSON, Layer-2
  headers, and Layer-3 raw bytes that client produced.
- Store as `testdata/golden/<case>.json`.
- A test feeds each fixture through the full engine and asserts the **verdict
  bucket** (and optionally the score within a tolerance band).
- Weight/threshold changes re-run these; a regression that moves case 7 out of
  `likely_automated` fails CI. This lets you tune weights confidently.

### 2.3 Integration / e2e

- Run the self-hosted server locally with a `mkcert` cert (`make dev`), drive real
  Chrome and headless Playwright through the **full funnel** (`/` → click →
  `/step-2` → fill → `/result`) with Playwright, and assert the Page-3 verdict.
- Test the **funnel and degradation paths**: a real click on Page 1 activates the
  token and reaches Page 2 cleanly; a Playwright run that **`goto('/step-2')`
  directly** trips `funnel_bypass`; expire the session → assert `session_expired`
  handling; disable WebGL → assert that check renders `unavailable` without
  breaking the score.

### 2.4 Contract tests

- Validate every response against the [docs/03](03-api-contract.md) JSON schema.
- Validate `data/reference/*.json` against their schemas (the "reference sanity"
  check from [docs/09 §8](09-reference-data.md)).

---

## 3. Capturing fixtures (how to build the golden set)

The reference data and golden fixtures both need **real captures**:

1. Deploy a scratch instance of the self-hosted server (or run it locally with
   `mkcert`) so one connection yields all three layers.
2. Add a `?capture=1` debug mode (`make capture`) that dumps the full raw report
   (all layers, including raw ClientHello bytes and H2 frames) to a file.
3. Drive each matrix client at it once, save the dumps as fixtures.
4. Derive the reference tables ([docs/09](09-reference-data.md)) from the
   browser/library captures; derive golden verdicts from all of them.
5. Re-capture on the quarterly refresh cadence.

Document the capture host, browser versions, and dates alongside the fixtures so
refreshes are reproducible.

---

## 4. CI pipeline

```
on: [push, pull_request]
jobs:
  build:      go build ./... ; esbuild the frontend
  unit:       go test ./...   (rules, fingerprint math, header-order)
  golden:     go test ./engine -run Golden   (all matrix fixtures → verdict buckets)
  schema:     validate API responses + reference JSON against schemas
  frontend:   playwright unit tests for collectors (headless)
  e2e:        docker-compose up ; playwright drives Chrome + headless Playwright ; assert verdicts
  lint:       go vet, staticcheck, eslint (frontend), prettier check
```

- **Golden + schema + unit** gate every PR (fast, deterministic).
- **e2e** runs on merge to main (slower; needs browsers — the environment already
  has Chromium at `/opt/pw-browsers/chromium`, `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1`).
- A **weekly scheduled job** re-runs the matrix against a staging deployment to
  catch fingerprint drift early (browsers auto-update; our references don't).

---

## 5. What "passing" means

The tool is working when:

1. Every real browser (rows 1–5) scores `human` with **no false `fail`**,
   including Firefox/Safari which legitimately lack client hints (a common source
   of naive false positives — explicitly guarded).
2. Every obvious automation (rows 6–14, 17) scores `automated`.
3. The **stealth headless on CI** case (15) is caught as at least `suspicious`
   **by a contradiction**, not by any single flag it patched — this is the whole
   thesis of the tool and the most important test.
4. The **funnel** works end to end: passive signals land the band early, the click
   + form + cross-navigation evidence refine it by Page 3, behavior alone never
   flips a clean human to `automated`, and a deep-link/bypass is caught.
5. The honest-limit case (16) is reported as clean *with the stated caveat*, and
   the headline automation probability is well-calibrated across the matrix.
