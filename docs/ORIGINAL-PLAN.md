# Build Plan: Automation / Bot Detection Web App

A diagnostic web app that inspects the visiting client and reports every signal
that would lead a real anti-bot system to suspect automation. Think
`bot.sannysoft.com` + `browserleaks.com`, but organized as one coherent report
with a coherence/consistency score.

> **Purpose & scope:** This is a *diagnostic/testing* tool. It runs entirely on
> the visitor's own request, shows them what their browser leaks, and helps
> developers verify that legitimate automation (or a hardened browser) behaves
> consistently. It does not solve CAPTCHAs, bypass protections, or attack third
> parties.

---

## 1. Architecture

Detection splits into three layers. A JS-only app **cannot** see layers 2–3
correctly, so a backend is required.

| Layer | What it sees | Where it must run |
|-------|--------------|-------------------|
| **1. Browser environment** | `navigator`, WebGL, canvas, screen, permissions, behavior | Frontend JS |
| **2. HTTP** | Header values, **header order**, `Sec-Fetch-*`, client hints | Backend (raw request) |
| **3. Transport** | TLS ClientHello (JA3/JA4), HTTP/2 fingerprint | Backend / reverse proxy with raw socket access |

**Recommended stack**
- **Backend:** Go (best raw access to TLS ClientHello + preserved header order via `net/http` with a custom listener, or the `fp` / `ja3`/`ja4` libraries). Node is fine for layers 1–2 but weaker for TLS.
- **Frontend:** Vanilla JS or a light framework. No heavy dependencies — every added lib changes the fingerprint.
- **Transport:** Serve directly (no CDN in front) so the TLS handshake you inspect is the client's real one, not the CDN's.

**Data flow**
1. Browser loads page → frontend collects Layer-1 signals.
2. Frontend POSTs collected signals to `/api/analyze`.
3. Backend has already captured Layer-2/3 signals from that same connection (correlate by connection/session).
4. Backend runs coherence checks *across* layers and returns a scored report.
5. Frontend renders the report.

---

## 2. Layer 1 — Browser environment (Frontend JS)

Each module returns `{ value, verdict, note }` where verdict ∈ `ok | suspicious | automation`.

### 2.1 Explicit automation flags
- `navigator.webdriver` → `true` is a direct automation flag.
- Probe injected globals: `window._phantom`, `window.__phantom`, `window.callPhantom`, `window.__nightmare`, `window.domAutomation`, `window.domAutomationController`, `window.Buffer`, `window.emit`, `window.spawn`.
- Scan `document` and `window` keys for the `cdc_` prefix (ChromeDriver) and `$cdc_asdjflasutopfhvcZLmcfl_`.
- Detect Selenium attributes on `document`: `__selenium_unwrapped`, `__webdriver_evaluate`, `__driver_evaluate`, `__webdriver_script_fn`.
- Check for `window.chrome` presence/shape (real Chrome has a populated `chrome.runtime`; some headless/stealth setups fake it poorly).

### 2.2 Headless indicators
- UA contains `HeadlessChrome`.
- `navigator.plugins.length === 0` and `navigator.mimeTypes.length === 0` on a desktop Chrome UA.
- `navigator.languages` empty or missing.
- **Permissions contradiction:** compare `navigator.permissions.query({name:'notifications'})` state against `Notification.permission`. A classic headless tell is `denied` vs `default` mismatch.
- Missing `chrome.runtime` where UA claims Chrome.

### 2.3 WebGL
- Read `WEBGL_debug_renderer_info` → `UNMASKED_VENDOR_WEBGL` and `UNMASKED_RENDERER_WEBGL`.
- Flag software renderers: `SwiftShader`, `llvmpipe`, `Google SwiftShader`, `Mesa OffScreen`, `ANGLE (Google, Vulkan 1.x.0 (SwiftShader...`.
- Flag renderer/vendor that contradicts the claimed OS (e.g. Apple GPU string on a Windows UA).
- Flag `null` when WebGL should be available.

### 2.4 Canvas & Audio fingerprint
- Render text + shapes to a canvas, hash the pixel data. Store the hash. (Value on its own isn't automation — but identical hashes across "different" users, or blocked/zeroed output, is suspicious.)
- Build an `OfflineAudioContext`, render an oscillator, hash the output buffer. Same reasoning.

### 2.5 Hardware / screen plausibility
- `navigator.hardwareConcurrency` — 0, 1, or absurdly high on a "consumer" UA.
- `navigator.deviceMemory` — implausible values.
- `screen.width/height`, `availWidth/Height`, `window.outerWidth/outerHeight`. Headless often reports `outerWidth/Height === 0`.
- `devicePixelRatio` inconsistent with screen size.
- `screen.width < window.innerWidth` (impossible on real devices).

### 2.6 Fonts
- Enumerate available fonts (measure text width across a fallback list, or use the Font Access API where available).
- Flag when the font set doesn't match the claimed OS (e.g. no macOS system fonts on a macOS UA; Linux-only fonts on a Windows UA).

### 2.7 Timezone / locale coherence (client side)
- `Intl.DateTimeFormat().resolvedOptions().timeZone`
- `navigator.language` / `navigator.languages`
- `new Date().getTimezoneOffset()`
- Send these to backend for cross-check against IP geolocation and `Accept-Language`.

### 2.8 Behavioral signals (collect over a few seconds, then submit)
- Mouse: movement present? path linearity (perfectly straight = scripted)? clicks at exact element-center pixels?
- Keyboard: inter-keystroke timing variance; paste events vs. real typing.
- Scroll and focus/blur events fired at all.
- Time-to-first-interaction and form-fill-to-submit duration (sub-100ms = scripted).
- Provide a small interactive test area (a button, an input) so there's something to measure.

---

## 3. Layer 2 — HTTP (Backend)

### 3.1 Header values
- `User-Agent` present and well-formed.
- `Accept`, `Accept-Language`, `Accept-Encoding` present with browser-typical values (many HTTP libraries send minimal or different sets).
- Client hints: `Sec-CH-UA`, `Sec-CH-UA-Platform`, `Sec-CH-UA-Mobile` — present on modern Chromium and **internally consistent** with the UA.
- `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, `Sec-Fetch-User` — real browsers send these in predictable patterns for navigations vs. fetches. Missing/malformed = suspicious.
- `Upgrade-Insecure-Requests`, `DNT` where expected.

### 3.2 Header ORDER (high value — capture raw)
- Browsers emit headers in a characteristic order. `requests`, `axios`, Go's default client, curl each produce a *different* order.
- **Implementation note:** Go's `http.Header` is a map and loses order. To capture true order, read the raw request line-by-line (custom `net.Listener` wrapping, or `httputil.DumpRequest` won't preserve original order either — use a raw connection hijack or a proxy that logs the raw bytes).
- Compare captured order against known-good Chrome/Firefox/Safari orderings.

### 3.3 UA ↔ header consistency
- UA claims Chrome → expect `Sec-CH-UA` + `Sec-Fetch-*`. Absence is a strong flag.
- UA platform string vs. `Sec-CH-UA-Platform`.

---

## 4. Layer 3 — Transport fingerprinting (Backend / proxy)

### 4.1 TLS (JA3 / JA4)
- Capture the TLS ClientHello: cipher suites, extensions, elliptic curves, and their **order**.
- Compute JA3 (legacy) and JA4 (current) fingerprints.
- Maintain a small lookup of known browser fingerprints. Flag when the TLS fingerprint says "Go/Python/curl" but the UA says "Chrome" — the single strongest cross-layer contradiction.
- **Go libraries:** `github.com/refraction-networking/utls` for inspection, or community `ja3`/`ja4` packages. Requires terminating TLS yourself (no CDN in front).

### 4.2 HTTP/2 fingerprint
- Capture the HTTP/2 SETTINGS frame values, WINDOW_UPDATE, header-table size, and the pseudo-header order (`:method`, `:authority`, `:scheme`, `:path`).
- Browsers have stable, distinctive H2 fingerprints; scripted clients differ.

### 4.3 IP reputation
- Resolve visitor IP → ASN. Flag datacenter/cloud ASNs (AWS, GCP, Azure, OVH, Hetzner, DigitalOcean) vs. residential.
- Optionally integrate a reputation source; otherwise ship a static ASN list for the obvious datacenter ranges.

---

## 5. Cross-layer coherence engine (the actual value)

Single flags are weak; **contradictions between layers** are what real detectors weight. Implement explicit contradiction checks:

- TLS/HTTP2 fingerprint vendor ≠ UA vendor.
- `Sec-CH-UA-Platform` ≠ WebGL renderer OS ≠ font-set OS.
- Client timezone (e.g. `UTC`) + datacenter IP + `Accept-Language: en-US` cluster.
- UA says mobile but screen/pointer/touch capabilities say desktop.
- Header order matches a known HTTP library rather than any browser.
- Permissions/Notification contradiction.

Each check contributes a weighted score. Output:
- **Overall verdict:** `likely human browser` / `suspicious` / `likely automated`.
- **Per-signal breakdown** with the raw value and why it matters.
- **Contradiction list** highlighted separately (these matter most).

---

## 6. UI / Report

- Single-page report. Sections mirroring §2–5.
- Each row: signal name, captured value, verdict badge, one-line explanation.
- Top: big overall score + the contradiction highlights.
- "Copy report as JSON" button for sharing/debugging.
- Keep the frontend dependency-light so the tool doesn't pollute its own fingerprint.

---

## 7. Build steps (order for Claude Code)

1. Scaffold backend (Go) with two servers or one server + raw TLS capture. Endpoint `/` serves the page; `/api/analyze` receives Layer-1 JSON and returns the full report.
2. Implement Layer-2 header capture **including raw header order** first — verify with curl vs. real browser.
3. Add Layer-3 TLS/JA4 capture. Verify curl and Chrome produce different fingerprints.
4. Build the frontend Layer-1 collectors as independent modules, each testable in isolation.
5. Add the behavioral collector (buffer events for ~3s, then submit).
6. Implement the coherence/scoring engine on the backend.
7. Build the report UI.
8. Add "copy JSON."

---

## 8. Testing

Validate against a matrix:
- Real Chrome, Firefox, Safari (desktop + mobile) → should score clean.
- Puppeteer / Playwright (headed and headless) → should light up webdriver, TLS, and behavior signals.
- `puppeteer-extra-plugin-stealth` → tests whether your cross-layer coherence catches what single-flag checks miss.
- `curl`, Python `requests`, Go `http.Client` → should fail on header order + TLS immediately.

The goal: a stealthed headless browser should still be caught by **contradictions**, not by any one flag it patched.

---

## 9. Notes / gotchas

- **No CDN/proxy in front** during TLS capture, or you fingerprint the CDN.
- Header order is easy to lose in most frameworks — solve it early or the highest-value signal is gone.
- Fingerprint *values* (canvas/audio/WebGL hashes) are for **consistency** checks, not automation-in-themselves. Don't over-weight them.
- Keep everything privacy-respecting: the tool reports to the visitor about themselves; don't silently persist fingerprints beyond the session unless that's an intended, disclosed feature.
