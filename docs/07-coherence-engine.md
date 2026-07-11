# 07 — Cross-Layer Coherence Engine

This is where the tool earns its keep. Single flags are weak; **contradictions
between layers** are what real detectors weight, because a client can patch any
one tell but struggles to keep *all layers telling the same story*. The engine
takes the captured signals from all three layers and produces the headline score,
verdict, and contradiction list.

---

## 1. Model overview

The engine runs three passes:

1. **Per-signal scoring.** Each captured signal contributes a **penalty** (0 =
   fine, higher = more automation-like) times a **weight**. Unavailable signals
   contribute nothing and reduce coverage.
2. **Contradiction detection.** Explicit rules look for pairs/sets of signals that
   cannot co-occur in a genuine client. Contradictions carry the highest weights
   and are surfaced separately.
3. **Aggregation & coverage adjustment.** Penalties are summed, mapped to a 0–100
   **coherence score** (100 = perfectly consistent), a **verdict**, and a
   **confidence** that scales with how many layers were actually captured.

The score is **deterministic**: identical captured inputs → identical output.
Behavioral inputs are bounded so their noise can't flip a verdict alone.

---

## 2. Signal weights

Weights are the design surface you'll tune against the test matrix
([docs/11](11-testing.md)). Starting values (higher = stronger evidence of
automation):

### 2.1 Direct automation flags (Layer 1)

| Signal | Weight | Verdict on hit |
|--------|:------:|----------------|
| `navigator.webdriver === true` | 25 | automation |
| `cdc_` / ChromeDriver artifacts | 30 | automation |
| Selenium DOM attributes | 30 | automation |
| PhantomJS / Nightmare globals | 30 | automation |
| Node globals in browser (`Buffer`, `process`, `require`) | 25 | automation |
| Playwright/Puppeteer bindings | 28 | automation |
| Anti-tamper: patched-getter detected (`toString` not `[native code]`) | 22 | automation |
| `window.chrome.runtime` missing on Chrome UA | 12 | suspicious |

### 2.2 Headless indicators (Layer 1)

| Signal | Weight |
|--------|:------:|
| UA contains `HeadlessChrome` | 30 |
| Permissions/Notification contradiction | 22 |
| `outerWidth/Height === 0` | 20 |
| `screen.width < innerWidth` (impossible geometry) | 20 |
| Empty `navigator.languages` | 12 |
| `plugins.length === 0 && mimeTypes.length === 0` on desktop Chrome | 10 |
| Software WebGL renderer on desktop UA | 12 |

### 2.3 Environment plausibility (Layer 1)

| Signal | Weight |
|--------|:------:|
| Implausible `hardwareConcurrency` (0/1/>128) | 8 |
| Implausible `deviceMemory` | 6 |
| Canvas blocked / zeroed | 10 |
| Audio blocked / zeroed | 8 |
| Canvas/audio hash == known-automation-default | 12 |

### 2.4 HTTP (Layer 2)

| Signal | Weight |
|--------|:------:|
| Missing `Sec-CH-UA` on Chromium UA | 15 |
| Missing `Sec-Fetch-*` on Chromium UA | 15 |
| `Accept`/`Accept-Encoding` minimal (curl/requests default) | 15 |
| Header order matches a known HTTP library | 30 |
| Header order matches a browser ≠ claimed | 15 |
| Illegal-on-H2 header present (`Connection` over h2) | 12 |

### 2.5 Transport (Layer 3)

| Signal | Weight |
|--------|:------:|
| JA4 matches a scripting stack (Go/Python/curl/okhttp) | 35 |
| H2 fingerprint matches a scripting stack | 25 |
| Datacenter/cloud ASN | 10 |
| TLS unavailable where a browser would negotiate it | — (coverage, not penalty) |

### 2.6 Behavioral (Layer 1, bounded)

The **entire** behavior group is capped at a combined **18** penalty, and can
only *reinforce*, never solely *create*, an automated verdict.

| Signal | Weight (pre-cap) |
|--------|:------:|
| Perfectly linear mouse paths (high straight-segment ratio) | 10 |
| Zero-variance inter-keystroke timing | 10 |
| Clicks at exact element-center pixels | 6 |
| Sub-100ms form fill→submit | 8 |
| No interaction at all in 3s | 0 (→ `inconclusive`, never penalized) |

---

## 3. Contradiction rules (the high-weight core)

Each rule fires only when **both sides were actually captured** (otherwise it's
`inconclusive`, not a contradiction). Contradictions are additive on top of
per-signal penalties and are listed separately in the report.

| ID | Rule | Weight | Why it's decisive |
|----|------|:------:|-------------------|
| `tls_ua_vendor_mismatch` | JA4/JA3 stack ≠ UA vendor (TLS=Go/Python/curl, UA=Chrome) | **40** | A real Chrome cannot emit a Go ClientHello. The strongest single contradiction. |
| `h2_ua_vendor_mismatch` | H2 fingerprint stack ≠ UA vendor | 28 | Corroborates the TLS mismatch; independent evidence. |
| `header_order_is_library` | Header order matches curl/requests/Go under a browser UA | 30 | The client is an HTTP library wearing a browser UA. |
| `os_triangulation_mismatch` | ≥2 of {`Sec-CH-UA-Platform`, WebGL renderer OS, font-set OS} disagree | 25 | A genuine OS shows one consistent story across all three. |
| `ua_js_vs_header_mismatch` | `navigator.userAgent` (JS) ≠ `User-Agent` header | 25 | Different UA to JS vs. the wire = injected/spoofed UA. |
| `mobile_desktop_contradiction` | UA says mobile but screen/touch/pointer/hints say desktop (or vice versa) | 20 | Anti-detect browsers commonly get this pair wrong. |
| `permissions_contradiction` | Permissions API state impossible vs. `Notification.permission` | 22 | Classic headless artifact. |
| `lang_tz_ip_cluster` | Datacenter IP + `UTC`/mismatched `Intl` timezone + `Accept-Language: en-US` | 18 | The canonical automation locale cluster. |
| `tz_geo_mismatch` | Client `Intl` timezone far from IP-geolocated timezone (and not a plausible VPN story) | 12 | Spoofed timezone or proxied egress. |
| `accept_lang_navigator_mismatch` | `Accept-Language` header ≠ `navigator.languages` | 12 | The HTTP client and the JS runtime disagree about locale. |
| `client_egress_mismatch` | Probe IP ≠ app IP, or probe UA ≠ app UA (Topology B) | 15 | The two requests came from different clients/egresses. |

**Rule composition.** When several transport/HTTP contradictions fire together
(TLS + H2 + header-order all say "library"), they're strongly correlated
evidence; the engine keeps them additive but caps the *transport-contradiction*
contribution so one spoofed library doesn't triple-count beyond ~60. The point is
that a stealth client would have to fix *all* of them, not that we sum to
infinity.

---

## 4. Aggregation

```
rawPenalty      = Σ(per-signal penalties, behavior group pre-capped)
                + Σ(contradiction weights, transport group post-capped)

coherence       = clamp(100 - scale(rawPenalty), 0, 100)     // 100 = perfectly consistent
```

`scale()` is a monotonic mapping (linear with a soft knee, or logistic) tuned so
that:

- a clean real browser lands ~92–100;
- a single moderate flag (e.g. software WebGL on a dev VM) lands ~80–90 (still
  "likely human", just noted);
- one decisive contradiction (TLS≠UA) alone drops below the `likely_automated`
  threshold.

### 4.1 Verdict thresholds

| Coherence | Verdict |
|-----------|---------|
| ≥ 75 | `likely_human` |
| 45–74 | `suspicious` |
| < 45 | `likely_automated` |

Thresholds are config constants, tuned against the matrix. Any **single
critical-severity contradiction** (weight ≥ 30) forces at least `suspicious`
regardless of the numeric score, so a stealth client that's otherwise pristine but
has a Go TLS stack cannot land in `likely_human`.

### 4.2 Confidence & coverage adjustment

```
confidence = base * coverageFactor
coverageFactor = weightedFractionOfLayersCaptured
```

- Topology A (no Layer 3): `coverageFactor` is reduced (e.g. ×0.6), because the
  strongest discriminators are absent. A "clean" verdict on Topology A is
  explicitly lower-confidence and the report says so: *"scored on layers 1–2 only;
  transport signals unavailable on this deployment."*
- Topology B/C (all layers): full confidence.
- Confidence is reported alongside the verdict and is **not** the same as the
  coherence score — a client can be confidently-automated (high confidence, low
  coherence) or uncertain (low confidence because coverage was thin).

---

## 5. Worked examples

### 5.1 Real Chrome on Windows, residential IP (Topology B)

- Layer 1: no flags, populated `chrome.runtime`, hardware plausible, D3D11 WebGL
  renderer, Windows fonts, natural behavior.
- Layer 2: full `Sec-CH-UA`/`Sec-Fetch-*`, browser header order.
- Layer 3: JA4 matches `chrome-124-windows`, H2 matches Chrome, residential ASN.
- No contradictions fire. `rawPenalty ≈ 0`. **coherence ≈ 98, verdict
  `likely_human`, confidence 0.95.**

### 5.2 `curl` with a spoofed Chrome UA (Topology B)

- Layer 1: **no JS runs** — the analyze POST never arrives, or arrives empty. (If
  someone scripts the POST, `layer1` is absent/degenerate.)
- Layer 2: minimal `Accept`, no `Sec-CH-UA`, no `Sec-Fetch-*`, header order ==
  curl.
- Layer 3: JA4 == curl, H2 absent or == curl.
- Contradictions: `tls_ua_vendor_mismatch` (40) + `header_order_is_library` (30) +
  `missing client hints/sec-fetch` (30) → transport group capped, still
  **coherence < 20, verdict `likely_automated`, confidence 0.9.** Caught before
  Layer 1 even matters.

### 5.3 Vanilla Puppeteer headless (Topology B)

- Layer 1: `navigator.webdriver=true` (25), `HeadlessChrome` in UA (30),
  permissions contradiction (22), software WebGL (12), flat behavior (capped 18).
- Layer 2/3: browser-like (Puppeteer uses real Chromium's TLS/H2).
- No cross-layer contradiction needed — Layer 1 alone gives `rawPenalty ≈ 85+`.
  **coherence ≈ 15, `likely_automated`, confidence 0.9.**

### 5.4 `puppeteer-extra-plugin-stealth`, headed (Topology B) — the hard case

- Layer 1: `webdriver` patched to `false`; `HeadlessChrome` removed; permissions
  fixed; `chrome.runtime` faked. **Most single flags patched.** *But:* anti-tamper
  may catch a patched getter (22); behavior is flat if driven programmatically
  (capped 18).
- Layer 2: browser-like (it *is* Chromium).
- Layer 3: browser-like (real Chromium TLS/H2) — **so the strongest contradiction
  does NOT fire.**
- Where it's caught: if the stealth is imperfect, `os_triangulation_mismatch`
  (running headless Chromium on a Linux CI box while spoofing a Windows UA →
  Linux fonts + `llvmpipe`/SwiftShader WebGL vs. Windows `Sec-CH-UA-Platform`)
  fires at **25**, plus anti-tamper + behavior. Combined ≈ 65 → **`suspicious`**.
  If the stealth is *perfect* (real Windows host, headed, human-driven) the tool
  correctly reports `likely_human` — because at that point it genuinely is a real
  browser a human is using. **That's the honest boundary of detection, and the
  report says so** rather than pretending certainty.

### 5.5 Same client, plain Cloud Function (Topology A)

Every example above loses its Layer-3 evidence. §5.2 (`curl`) still fails on
Layer 2 values + missing JS. §5.4 (stealth) becomes *harder* to catch (no TLS
contradiction available) and the report is explicit: **"transport unavailable;
scored on layers 1–2; confidence reduced."** This is precisely why the roadmap
prioritizes standing up the edge probe.

---

## 6. Implementation notes

- Implement rules as **pure functions** `(signals) -> Contradiction | null` in a
  registry, so adding a rule is one file and one test.
- Keep **weights and thresholds in a single config struct** (or JSON) so tuning
  against the matrix doesn't require code changes.
- Every rule and signal carries a stable `id`, a human `title`, an `explanation`,
  and the `evidence` it fired on — the UI renders these verbatim, so the tool is
  self-documenting.
- Emit a machine-readable `scoreTrace` (the list of `{id, weight, applied}`) in a
  debug mode so you can see exactly why a score landed where it did during tuning.
- **Golden tests:** capture real fixtures for each matrix row (see
  [docs/11](11-testing.md)) and assert the verdict bucket, so weight tuning can't
  silently regress a known case.
