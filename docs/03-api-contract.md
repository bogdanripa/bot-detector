# 03 — API Contract

> **This is the spec for the `@botdetect/schema` / `go/schema` library**
> ([docs/13 §3.6](13-libraries-and-packaging.md#36-botdetectschema--goschema--the-wire-contract)).
> The shapes below are defined once as JSON Schema and code-generated into TS types
> and Go structs, so the client lib and the engine can't drift. The three-step
> funnel described here is the **honeypot's** integration; a different consumer may
> move these same payloads over its own transport — the schema is the contract, the
> endpoints and page flow are the honeypot's choice.

Stable, versioned contract between the client library and the engine. All bodies
are JSON, UTF-8. The report schema is versioned via `reportVersion` so the "copy
JSON" output stays parseable as checks evolve.

The flow is a **three-step funnel** on one origin (see
[docs/02](02-deployment-topology.md)): the server captures connection-level Layer
2/3 at **each** page navigation (`/`, `/step-2`, `/result`), and the client calls
`/api/analyze` once **per step** (`landing`, `form`, `result`). The engine
aggregates across steps; `/result` renders the final report.

---

## 1. Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/` | **Page 1** (landing: text + link); capture connSignals #1; mint `sessionId` + funnel token |
| `GET` | `/step-2` | **Page 2** (the form); capture connSignals #2; verify the funnel transition |
| `GET` | `/result` | **Page 3** (the report); capture connSignals #3; final aggregate score |
| `POST` | `/api/analyze` | Per-step client signals (`landing`/`form`/`result`); merges with session + funnel state; returns the running report |
| `POST` | `/api/submit` | Form submission checkpoint; 303 → `/result` |
| `GET` | `/app.js`, `/app.css` | Static assets |
| `GET` | `/api/health` | Liveness |
| `GET` | `/api/reference` | (optional) reference fingerprint DB for the UI |

The connection-level Layer 2/3 signals and the funnel-integrity signals are
captured **server-side at each navigation** and joined to the session by step. The
client never sends them (it can't see them).

---

## 2. Bootstrap (in each page's HTML)

```html
<script type="application/json" id="bootstrap">
{ "reportVersion": "1", "sessionId": "6f1c…-uuid", "step": "landing",
  "funnelToken": "…inert until a trusted click activates it…", "captureMode": "self-hosted" }
</script>
```

A matching `sessionId` is also set as a `Secure; HttpOnly; SameSite=Strict` cookie.
Each page carries its own `step`; Page 1 also carries the click-gated `funnelToken`
([docs/02 §4](02-deployment-topology.md#4-the-click-gated-funnel-token)).

---

## 3. `POST /api/analyze` — step `landing` (Page 1: passive + link click)

```jsonc
{
  "reportVersion": "1",
  "sessionId": "6f1c…-uuid",
  "step": "landing",
  "collectedAtMs": 1731000000000,     // client clock; display-only, never trusted
  "linkClick": {                      // input-provenance of the Page-1 link click (docs/14 §4)
    "occurred": true, "isTrusted": true, "approachPoints": 37, "coalescedNearby": 21,
    "atExactIntegerCenter": false, "dwellBeforeClickMs": 2400, "sourceCapabilitiesPresent": true
  },
  "layer1": {
    "automationFlags": {
      "navigatorWebdriver": false,
      "injectedGlobals": ["_phantom","callPhantom"],
      "cdcArtifacts": ["cdc_adoQpoasnfa76pfcZLmcfl_Array"],
      "seleniumAttributes": [],
      "playwrightBindings": [],
      "chromeObject": { "present": true, "runtimePresent": true, "shape": "populated" },
      "webdriverDescriptor": "native"    // "native" | "patched-getter" | "instance-override"
    },
    "headless": {
      "uaHasHeadlessChrome": false, "pluginsLength": 3, "mimeTypesLength": 2,
      "languagesEmpty": false,
      "permissionsNotificationState": "prompt", "notificationPermission": "default",
      "permissionsContradiction": false
    },
    "webgl": { "supported": true, "unmaskedVendor": "Google Inc. (NVIDIA)",
      "unmaskedRenderer": "ANGLE (NVIDIA … Direct3D11 …)", "isSoftware": false, "paramsHash": "…" },
    "canvas": { "supported": true, "hash": "a1b2…", "blocked": false, "zeroed": false },
    "audio": { "supported": true, "hash": "c3d4…", "sampleSum": 123.456, "blocked": false },
    "hardware": { "hardwareConcurrency": 8, "deviceMemory": 8, "maxTouchPoints": 0 },
    "screen": { "width": 2560, "height": 1440, "availWidth": 2560, "availHeight": 1400,
      "innerWidth": 1280, "innerHeight": 720, "outerWidth": 1280, "outerHeight": 800,
      "devicePixelRatio": 1.5, "colorDepth": 24 },
    "fonts": { "method": "measurement", "detected": ["Segoe UI","Calibri","…"], "count": 42 },
    "locale": { "intlTimeZone": "America/New_York", "timezoneOffsetMin": 300,
      "language": "en-US", "languages": ["en-US","en"] },
    "environment": { "userAgent": "Mozilla/5.0 …",
      "userAgentData": { "brands": [{"brand":"Chromium","version":"124"}], "mobile": false, "platform": "Windows" },
      "cookieEnabled": true, "vendor": "Google Inc.", "platform": "Win32", "productSub": "20030107" }
  }
}
```

All `layer1` fields are **client-asserted claims**, checked against each other and
against the server-captured Layer 2/3 — never trusted as ground truth.

---

## 4. `POST /api/analyze` — step `form` (Page 2: form behavior + traps)

Sent from Page 2 on form submit (or after a threshold of interaction). Carries only
interaction **dynamics** — never field **contents** — plus the honeypot-trap
outcomes.

```jsonc
{
  "reportVersion": "1",
  "sessionId": "6f1c…-uuid",
  "step": "form",
  "traps": {                          // active honeypot outcomes (docs/14 §8B)
    "domHoneypotFilled": false,       // a hidden-in-DOM field got a value ⇒ DOM/CDP agent
    "visionTrapTripped": false,       // clicked a visual-only affordance ⇒ vision agent
    "smoothPursuitTracked": true,     // followed a continuously-moving target (human/real cursor)
    "gestureTokenActivated": true,    // a trusted gesture produced the token
    "fillFasterThanHumanlyPossible": false
  },
  "behavior": {
    "durationMs": 8400,
    "form": {
      "fields": [
        { "name": "email",  "focusOrderIndex": 0, "dwellMs": 3200, "keydowns": 22,
          "interKeyMsMean": 138, "interKeyMsStdev": 61, "backspaces": 2, "pasteEvents": 0,
          "filledWithoutKeys": false, "corrections": 1 },
        { "name": "name",   "focusOrderIndex": 1, "dwellMs": 1500, "keydowns": 9,
          "interKeyMsMean": 150, "interKeyMsStdev": 52, "backspaces": 0, "pasteEvents": 0,
          "filledWithoutKeys": false, "corrections": 0 }
      ],
      "focusOrder": ["email","name","message"],
      "tabKeyUsed": true,
      "fillToSubmitMs": 8100,
      "submitLatencyAfterLastFieldMs": 900
    },
    "mouse": { "moveEvents": 143, "pathPoints": 143, "straightSegmentsRatio": 0.06,
      "avgSpeedPxPerMs": 0.42, "speedVariance": 0.19, "enteredEachFieldByMouse": true,
      "clickCount": 3, "clicksAtElementCenter": 0 },
    "keyboard": { "totalKeydowns": 31, "globalInterKeyMsStdev": 58, "totalPasteEvents": 0 },
    "scroll": { "events": 5, "distancePx": 640 },
    "focusBlur": { "focusEvents": 4, "blurEvents": 3 },
    "timeToFirstInteractionMs": 812
  }
}
```

> **Privacy invariant.** The `form.fields[].name` is the field *identifier*
> (`email`, `name`), not its value. No typed text, no field contents, ever leave
> the browser — only counts, timings, and variances. This is enforced client-side
> and stated in the UI.

---

## 5. Response — the report (returned from each step)

```jsonc
{
  "reportVersion": "1",
  "step": "form",                      // which step produced this report
  "generatedAtMs": 1731000000900,
  "funnel": {                          // funnel-integrity state (docs/02 §3)
    "stepsSeen": ["landing","form"],   // order completed; a gap ⇒ deep-link/bypass
    "reachedInOrder": true,
    "linkClickWasTrusted": true,       // Page-2 nav produced by a real click (Sec-Fetch-User + token)
    "crossNavConsistent": true,        // same JA4/UA/IP across navigations
    "totalFunnelMs": 11200
  },
  "score": {
    "automationProbability": 0.93,     // 0–1; P(client is automated) under our evidence model
    "percent": 93,                     // convenience: round(probability * 100)
    "band": "automated",               // "human" | "suspicious" | "automated"
    "automationType": "agentic-os",    // none|scripted|headless|agentic-cdp|agentic-os|agentic-ext|agentic-declared
    "pass": false,                     // banner: true = green (human), false = red/amber
    "confidence": 0.9,                 // how much evidence backs the estimate (rises across steps)
    "weightedEvidence": 4.1,           // logit input (sum of weighted signal contributions)
    "stepDelta": { "fromPrevPercent": 88, "changed": ["form_fill_dynamics","funnel_bypass"] }
  },
  "contradictions": [
    { "id": "tls_ua_vendor_mismatch", "severity": "critical",
      "title": "TLS fingerprint says Go/net-http, User-Agent says Chrome",
      "evidence": { "ja4": "t13d…", "matchedStack": "go-nethttp", "uaClaim": "Chrome/124" },
      "weight": 3.5,
      "explanation": "A genuine Chrome browser produces a Chrome TLS ClientHello; a Go client with a Chrome UA means the UA is spoofed." }
  ],
  "checks": [
    { "id": "navigator_webdriver", "layer": 1, "group": "automation_flags",
      "title": "navigator.webdriver", "value": true, "status": "fail", "weight": 2.2,
      "explanation": "Set to true by WebDriver-controlled browsers (Selenium, Puppeteer, Playwright)." },
    { "id": "ip_datacenter", "layer": 3, "group": "network",
      "title": "IP is datacenter-owned", "value": "AS15169 GOOGLE", "status": "warn", "weight": 0.9,
      "explanation": "Datacenter/cloud ASN. Common for bots; also seen with VPNs and cloud dev shells, so it is a contributor rather than proof." }
    // … one entry per check, across all layers …
  ],
  "raw": {
    "layer1": { /* echoed */ },
    "layer2": { "headerValues": { /* … */ }, "headerOrder": ["…"], "clientHints": { /* … */ } },
    "layer3": { "ja3": "…", "ja4": "…", "http2": { /* … */ },
                "ip": { "addr": "…", "asn": 15169, "org": "GOOGLE", "isDatacenter": true } }
  }
}
```

**Field semantics**

- `score.automationProbability` is the headline: the estimated probability the
  client is automated, produced by the calibrated logistic in
  [docs/07](07-coherence-engine.md). `percent`, `band`, and `pass` are derived from
  it for the UI.
- Per-check `status ∈ pass | warn | fail | unavailable`. `unavailable` (probe
  couldn't run — e.g. WebGL disabled) is excluded from scoring, never shown as a
  pass.
- `confidence` rises across steps (`landing` → `form` → `result`) as behavioral,
  funnel, and multi-navigation evidence lands.
- `stepDelta` lets the UI highlight what changed at each step.
- `automationType` names *what kind* of automation was found (docs/14 §2).
- `funnel` reports the funnel-integrity state (docs/02 §3).
- `contradictions` are the high-weight subset (cross-layer *and* cross-navigation),
  surfaced separately.
- `raw` is the full echo for "copy report as JSON."

---

## 6. Versioning & errors

- `reportVersion` (string) bumps on breaking schema changes; the UI refuses
  unknown majors rather than mis-rendering. New `checks[].id` values are additive;
  consumers ignore unknown ids.

| Status | When | Body |
|--------|------|------|
| `200` | Valid per-step analyze (`landing`/`form`/`result`) | The report |
| `400` | Malformed JSON, wrong `reportVersion` major, bad `step` | `{ "error": "bad_request", "detail": "…" }` |
| `404` | Unknown/expired `sessionId` | `{ "error": "session_expired" }` — client re-loads `GET /` to get a fresh session |
| `413` | Body over cap (e.g. 256 KiB) | `{ "error": "payload_too_large" }` |
| `429` | Rate limit exceeded | `{ "error": "rate_limited", "retryAfterMs": 2000 }` |

`/api/analyze` returns `200` with a complete report whenever the session is valid;
individual failed probes degrade to `unavailable` checks inside the `200`, never a
5xx. It only 5xx's on genuine internal faults.
