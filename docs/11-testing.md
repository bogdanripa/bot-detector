# 11 — Testing & CI

The tool's credibility rests on it scoring the right clients the right way. That
requires a **validation matrix** of real clients plus automated regression tests
that pin known cases so weight-tuning can't silently break them.

---

## 1. The validation matrix

Run each client against a deployed instance (ideally Topology B so all layers are
live) and record the verdict. The expected column is the acceptance criterion.

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

**Coverage rows** — run a subset on **Topology A** (plain Cloud Function) and
assert the report correctly labels Layer 3 `unavailable`, excludes it from
scoring, and reduces confidence. Case 7 (`curl` + Chrome UA) must **still** fail
on Topology A (via Layer-2 values), proving graceful degradation still catches the
obvious cases.

### Acceptance criteria

- Rows 1–5: `likely_human`, no `automation`-severity signal fires.
- Rows 6–14, 17: `likely_automated`.
- Rows 15, 18, 19: at least `suspicious` (the "hard but catchable" band).
- Row 16: `likely_human` — and the report explicitly states the detection limit.
- Row 20: `suspicious`, and the report notes it's a likely false positive from
  fingerprint hardening (this is a *feature* for that user).

---

## 2. Automated test layers

### 2.1 Unit tests (per collector / per rule)

- **Layer-1 collectors:** run in a headless browser (Playwright) and in jsdom; assert
  each returns the right shape and doesn't throw when an API is missing.
- **Coherence rules:** pure functions — table-driven Go tests. Each rule has
  fixtures that fire it and fixtures that don't. This is where most of the value
  is; rules must be individually pinned.
- **JA3/JA4/H2 computation:** feed captured raw ClientHello / H2 preface bytes
  from fixtures; assert the computed fingerprint matches the expected string/hash.
- **Header-order distance:** table tests over reference vs. captured sequences.

### 2.2 Golden report tests (the regression backbone)

- Capture a **real fixture** for each matrix row: the exact Layer-1 JSON, Layer-2
  headers, and Layer-3 raw bytes that client produced.
- Store as `testdata/golden/<case>.json`.
- A test feeds each fixture through the full engine and asserts the **verdict
  bucket** (and optionally the score within a tolerance band).
- Weight/threshold changes re-run these; a regression that moves case 7 out of
  `likely_automated` fails CI. This lets you tune weights confidently.

### 2.3 Integration / e2e

- Spin up the app + probe locally (docker-compose, `CAPTURE_MODE=c` all-in-one for
  simplicity, or both processes for true B-mode), drive real Chrome and headless
  Playwright against it with Playwright, and assert the rendered verdict.
- Test the **degradation paths**: kill the probe → assert the report renders on
  L1–2 with the "probe unreachable" label; expire the nonce → assert the timeout
  label.

### 2.4 Contract tests

- Validate every response against the [docs/03](03-api-contract.md) JSON schema.
- Validate `data/reference/*.json` against their schemas (the "reference sanity"
  check from [docs/09 §8](09-reference-data.md)).

---

## 3. Capturing fixtures (how to build the golden set)

The reference data and golden fixtures both need **real captures**:

1. Deploy a scratch instance in Topology C (single self-managed host) so one
   connection yields all three layers.
2. Add a `?capture=1` debug mode that dumps the full raw report (all layers,
   including raw ClientHello bytes and H2 frames) to a file.
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

1. Every real browser (rows 1–5) scores `likely_human` with **no false
   `automation` signal**, including Firefox/Safari which legitimately lack client
   hints (a common source of naive false positives — explicitly guarded).
2. Every obvious automation (rows 6–14, 17) scores `likely_automated`.
3. The **stealth headless on CI** case (15) is caught as at least `suspicious`
   **by a contradiction**, not by any single flag it patched — this is the whole
   thesis of the tool and the most important test.
4. The **degraded (Topology A)** runs correctly label missing layers and still
   catch the obvious cases, never fabricating a Layer-3 verdict.
5. The honest-limit case (16) is reported as clean *with the stated caveat*.
