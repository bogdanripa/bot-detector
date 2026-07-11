# 07 — Scoring Engine (Automation Probability)

This is where the tool earns its keep. It takes every captured signal — Layer 1
(passive + form behavior), Layer 2, Layer 3 — and produces the headline output:
an **automation probability** (0–100%), a green/amber/red band, and a checklist of
every individual check. Single flags are weak; **contradictions between layers**
are what a real detector weights, because a client can patch any one tell but
struggles to keep all layers telling the same story.

---

## 1. Why a probability (and how it's honest)

The previous framing was a "coherence score" (100 = consistent). The headline is
now an **automation probability**: "≈93% likely automated." It's more intuitive
for a pass/fail tool and maps directly onto the green/red banner.

A raw weighted sum of hand-set weights is **not** a probability. To legitimately
call it one, we run the weighted evidence through a **logistic (sigmoid)** and
**calibrate** it against the labeled test matrix ([docs/11](11-testing.md)):

```
L (log-odds) = b0 + Σ wᵢ · firedᵢ          // each signal contributes to the log-odds of "automated"
P(automated) = 1 / (1 + e^(−L))            // sigmoid → a value in (0,1)
```

- `wᵢ` is a signal's **contribution to the log-odds** (its "weight" below).
- `b0` is a negative **bias** so that a client with nothing firing sits at a low
  baseline probability.
- The weights, `b0`, and an overall scale are **tuned so the labeled matrix
  calibrates**: real browsers cluster below ~15%, obvious automation above ~85%,
  with the hard/stealth cases landing in the ambiguous middle.

We are explicit in the UI and docs that this is an **estimated probability under
our evidence model**, not a ground-truth classifier. That honesty is the point —
the tool shows its work (every contributing check and weight is in the report).

The scoring is **deterministic**: identical captured inputs → identical
probability. Behavioral inputs are bounded so their noise refines but never alone
creates a verdict.

---

## 2. Signal weights (log-odds contributions)

Positive = evidence *for* automation. These are starting values to tune against
the matrix; keep them in a single config so tuning needs no code change. Baseline
bias `b0 = −3.0` (⇒ nothing firing ≈ 4.7% automated).

### 2.1 Direct automation flags (Layer 1, phase 1)

| Signal | Weight (Δlog-odds) | Check status |
|--------|:------:|--------------|
| `cdc_` / ChromeDriver artifacts | +3.2 | fail |
| Selenium DOM attributes | +3.2 | fail |
| PhantomJS / Nightmare globals | +3.2 | fail |
| Playwright/Puppeteer bindings | +3.0 | fail |
| `navigator.webdriver === true` | +2.6 | fail |
| Node globals in browser (`Buffer`,`process`,`require`) | +2.6 | fail |
| Anti-tamper: patched getter (`toString` ≠ `[native code]`) | +2.4 | fail |
| `window.chrome.runtime` missing on Chrome UA | +1.0 | warn |

### 2.2 Headless indicators (Layer 1, phase 1)

| Signal | Weight |
|--------|:------:|
| UA contains `HeadlessChrome` | +3.0 |
| Permissions/Notification contradiction | +2.2 |
| `outerWidth/Height === 0` | +2.0 |
| `screen.width < innerWidth` (impossible geometry) | +2.0 |
| Empty `navigator.languages` | +1.2 |
| `plugins.length === 0 && mimeTypes.length === 0` on desktop Chrome | +1.0 |
| Software WebGL renderer on desktop UA | +0.9 |

### 2.3 Environment plausibility (Layer 1, phase 1)

| Signal | Weight |
|--------|:------:|
| Canvas/audio hash == known-automation-default | +1.2 |
| Canvas blocked / zeroed | +1.0 |
| Audio blocked / zeroed | +0.8 |
| Implausible `hardwareConcurrency` (0/1/>128) | +0.8 |
| Implausible `deviceMemory` | +0.6 |

### 2.4 HTTP (Layer 2)

| Signal | Weight |
|--------|:------:|
| Header order matches a known HTTP library | +3.0 |
| Missing `Sec-CH-UA` on Chromium UA | +1.5 |
| Missing `Sec-Fetch-*` on Chromium UA | +1.5 |
| `Accept`/`Accept-Encoding` minimal (curl/requests default) | +1.5 |
| Header order matches a browser ≠ claimed | +1.5 |
| Illegal-on-H2 header present (`Connection` over h2) | +1.2 |

### 2.5 Transport (Layer 3)

| Signal | Weight |
|--------|:------:|
| JA4 matches a scripting stack (Go/Python/curl/okhttp) | +3.5 |
| H2 fingerprint matches a scripting stack | +2.5 |
| **IP is datacenter/cloud-owned** | +0.9 |
| IP on a known VPN/hosting range | +0.5 |

> **On datacenter IPs.** A datacenter ASN is a real contributor (+0.9) but
> deliberately *not* decisive: developers use cloud shells and users use VPNs. Its
> power is in combination — see the `lang_tz_ip_cluster` contradiction below.

### 2.6 Form behavior (Layer 1, phase 2, bounded)

The **entire** behavior group is **capped at +1.5 log-odds combined**, and is
**gated**: if all non-behavioral evidence is clean (passive `P < 0.30`), behavior
can push at most into `suspicious`, never `automated`. Behavior *reinforces*; it
does not *convict* on its own.

| Signal | Weight (pre-cap) |
|--------|:------:|
| All fields filled sub-100ms / fill→submit < 100ms | +1.2 |
| Zero-variance inter-keystroke timing across the form | +1.0 |
| Programmatic focus (no pointer movement into any field) | +1.0 |
| `filledWithoutKeys` across the whole form (no paste, no keys) | +1.0 |
| Perfectly linear mouse paths (high straight-segment ratio) | +0.8 |
| Focus/tab order never matches visual order | +0.6 |
| Clicks at exact element-center pixels | +0.5 |
| No interaction at all | 0 (→ `inconclusive`, never penalized) |
| Single autofilled field (password manager) | 0 (explicitly neutral) |

---

## 3. Contradiction rules (the high-weight core)

Each fires only when **both sides were actually captured**. Contradictions are the
heaviest weights because a stealth client would have to fix *all* layers at once.
They're surfaced separately in the report and also feed the log-odds sum.

| ID | Rule | Weight | Why it's decisive |
|----|------|:------:|-------------------|
| `tls_ua_vendor_mismatch` | JA4/JA3 stack ≠ UA vendor (TLS=Go/Python/curl, UA=Chrome) | **+5.5** | A real Chrome cannot emit a Go ClientHello. The strongest single contradiction. |
| `header_order_is_library` | Header order matches curl/requests/Go under a browser UA | +3.0 | The client is an HTTP library wearing a browser UA. |
| `h2_ua_vendor_mismatch` | H2 fingerprint stack ≠ UA vendor | +2.8 | Independent corroboration of the TLS mismatch. |
| `os_triangulation_mismatch` | ≥2 of {`Sec-CH-UA-Platform`, WebGL renderer OS, font-set OS} disagree | +2.4 | A genuine OS tells one consistent story across all three. |
| `ua_js_vs_header_mismatch` | `navigator.userAgent` (JS) ≠ `User-Agent` header | +2.4 | Different UA to JS vs. the wire = injected/spoofed UA. |
| `permissions_contradiction` | Permissions API state impossible vs. `Notification.permission` | +2.2 | Classic headless artifact. |
| `mobile_desktop_contradiction` | UA says mobile but screen/touch/pointer/hints say desktop (or vice versa) | +2.0 | Anti-detect browsers commonly get this pair wrong. |
| `lang_tz_ip_cluster` | Datacenter IP + `UTC`/mismatched `Intl` timezone + `Accept-Language: en-US` | +2.0 | The canonical automation cluster — where the datacenter IP becomes powerful. |
| `client_egress_or_session_anomaly` | Phase-2 UA ≠ phase-1 UA, or session replayed off-page (`Sec-Fetch-Site` wrong on analyze) | +1.8 | The phases came from different clients, or the payload was replayed outside the browser. |
| `tz_geo_mismatch` | Client `Intl` timezone far from IP-geolocated timezone (not a plausible VPN story) | +1.2 | Spoofed timezone or proxied egress. |
| `accept_lang_navigator_mismatch` | `Accept-Language` header ≠ `navigator.languages` | +1.2 | HTTP client and JS runtime disagree about locale. |

**Correlated-evidence cap.** When several transport/HTTP contradictions fire
together (TLS + H2 + header-order all say "library"), they're correlated. The
engine caps the *combined transport-contradiction* contribution at **+7.0
log-odds** so one spoofed library can't triple-count to absurdity — it's already
past 99% by then. The point is that a stealth client must fix *all* layers, not
that the number races to infinity.

**Critical floor.** Any single `severity: critical` contradiction (weight ≥ 4.5)
forces the band to at least `automated` (red) regardless of the arithmetic, so a
client that's otherwise pristine but has a Go TLS stack can never show green.

---

## 4. Bands, banner & confidence

### 4.1 From probability to band

| Automation probability | Band | Banner |
|------------------------|------|--------|
| `< 0.30` | `human` | 🟢 **PASS** |
| `0.30 – 0.70` | `suspicious` | 🟡 **SUSPICIOUS** |
| `> 0.70` | `automated` | 🔴 **FAIL** |

Thresholds are config constants tuned on the matrix. The `critical floor` (§3)
overrides them upward.

### 4.2 Confidence (separate from the probability)

`confidence ∈ (0,1)` expresses *how much evidence backs the estimate*, distinct
from the probability itself:

```
confidence = f(number of independent signals captured, phase, decisiveness)
```

- **Phase 1** yields a probability at passive confidence.
- **Phase 2** raises confidence because behavioral evidence either corroborates or
  contradicts the passive read.
- A single decisive contradiction (TLS≠UA) yields **high** confidence even at phase
  1 — the evidence is strong regardless of how much else we saw.
- A verdict resting only on weak/circumstantial signals (e.g. just a datacenter
  IP) is **low** confidence, and the UI says so ("weak evidence — mostly network
  reputation").

A client can therefore be *confidently automated* (high P, high confidence) or
*uncertain* (mid P, low confidence). Both are reported.

---

## 5. Phased scoring

```
report@phase1 = score(connectionSignals + passiveLayer1)
report@phase2 = score(connectionSignals + passiveLayer1 + formBehavior)   // delta re-score
```

- Phase 1 lands the banner immediately from the strongest, interaction-free
  evidence.
- Phase 2 adds the bounded behavior group (§2.6) and any phase-2 contradiction
  (`client_egress_or_session_anomaly`), then recomputes P and confidence.
- The response carries `phaseDelta` (§[docs/03](03-api-contract.md#5-response--the-report))
  so the UI can highlight which checks changed and whether the probability moved.

---

## 6. Worked examples

### 6.1 Real Chrome on Windows, residential IP

Nothing fires. `L = −3.0` → **P ≈ 5%**, band `human` 🟢, and after a natural form
fill (jittery mouse, variable cadence, corrections) confidence rises with P still
~5%. **PASS**, high confidence.

### 6.2 `curl` with a spoofed Chrome UA

`tls_ua_vendor_mismatch` (+5.5) + `header_order_is_library` (+3.0) + missing
client-hints/sec-fetch (+3.0) → transport cap applies, `L` well past +4 →
**P ≈ 99%**, `automated` 🔴, high confidence. Caught at phase 1, before the form
matters (and a scripted client usually never reaches phase 2).

### 6.3 Vanilla Puppeteer headless

`HeadlessChrome` (+3.0) + `webdriver` (+2.6) + permissions contradiction (+2.2) +
software WebGL (+0.9). `L = −3.0 + 8.7 = 5.7` → **P ≈ 99.7%**, `automated` 🔴.
Layer 1 alone convicts; no cross-layer contradiction needed.

### 6.4 `puppeteer-extra-plugin-stealth`, headless on Linux CI — the hard case

`webdriver`/`HeadlessChrome`/permissions patched. *But* it's headless Chromium on
a Linux box spoofing a Windows UA: `os_triangulation_mismatch` fires (+2.4, Linux
`llvmpipe`/SwiftShader WebGL + Linux fonts vs. `Sec-CH-UA-Platform: Windows`),
anti-tamper may catch a patched getter (+2.4), and phase-2 behavior is flat if
scripted (+1.5 capped). `L ≈ −3.0 + 6.3 = 3.3` → **P ≈ 96%**, `automated` 🔴 — and
crucially it's caught **by a contradiction**, not by any single flag it patched.
If the stealth is *perfect* (real Windows host, headed, human-driven), it
genuinely is a real browser and the tool reports `human` — the honest limit of
detection, stated in the report.

### 6.5 Real dev on a GCP cloud workstation

Real Chrome, but datacenter IP (+0.9) and maybe a VM software WebGL (+0.9).
`L = −3.0 + 1.8 = −1.2` → **P ≈ 23%**, band `human` 🟢 but the checklist shows the
two amber `warn`s, and confidence is noted as moderate. The tool correctly does
*not* convict a developer for their egress IP.

### 6.6 Human on a VPN

Residential-looking behavior, but a hosting-ASN VPN IP (+0.5) and possibly a
`tz_geo_mismatch` (+1.2) if the VPN exit is in another country.
`L = −3.0 + 1.7 = −1.3` → **P ≈ 21%**, `human` 🟢 with amber network warnings.
Behavior at phase 2 (natural typing) keeps it green with high confidence.

---

## 7. Implementation notes

- Implement rules and signals as **pure functions** `(signals) -> Contribution`
  in a registry; adding one is a file + a test.
- Keep **weights, `b0`, thresholds, and caps in one config struct/JSON** so
  calibration against the matrix needs no code change.
- Every check/contradiction carries a stable `id`, `title`, `explanation`, and the
  `evidence` it fired on — the UI renders these verbatim, so the tool is
  self-documenting.
- Emit a `scoreTrace` in debug mode: the ordered list of `{id, weight, applied}`
  plus the running `L` and final `P`, so you can see exactly why a probability
  landed where it did during tuning.
- **Calibration procedure:** capture fixtures for every matrix row, fit `b0` and a
  global scale (and optionally Platt-scale the output) so the bands separate the
  labeled classes cleanly; pin the result with golden tests
  ([docs/11 §2.2](11-testing.md#22-golden-report-tests-the-regression-backbone)).
- **Golden tests** assert the band (and P within a tolerance) for each fixture, so
  weight tuning can't silently regress a known case.
