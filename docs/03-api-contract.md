# 03 — API Contract

Stable, versioned contract between the frontend, the main backend, and the edge
probe. All bodies are JSON. All responses set
`Content-Type: application/json; charset=utf-8`. The report schema is versioned
via `reportVersion` so the "copy JSON" output stays parseable as checks evolve.

---

## 1. Endpoints

| Method | Path | Host | Purpose |
|--------|------|------|---------|
| `GET` | `/` | app | Serve the SPA shell + bootstrap nonce |
| `GET` | `/app.js`, `/app.css` | app | Static assets |
| `POST` | `/api/analyze` | app | Submit Layer-1 (+ nonce), receive full scored report |
| `GET` | `/api/health` | app | Liveness/readiness |
| `GET` | `/api/reference` | app | (optional) reference fingerprint DB for the UI |
| `GET` | `/probe` | probe | Capture transport for this connection, store by nonce, return 204 or the transport report |
| `GET` | `/result` | probe | Server-to-server: fetch stored transport report by nonce (auth required) |
| `OPTIONS` | `/probe` | probe | CORS preflight (should not fire for simple GET, but handle it) |

---

## 2. `POST /api/analyze` — request

Sent by `app.js` after Layer-1 collection (including ~3s of behavioral sampling).

```jsonc
{
  "reportVersion": "1",
  "nonce": "6f1c...-uuid",          // present in CAPTURE_MODE=b; null otherwise
  "collectedAtMs": 1731000000000,   // client clock; used only for skew display, never trusted
  "layer1": {
    "automationFlags": {
      "navigatorWebdriver": false,
      "injectedGlobals": ["_phantom", "callPhantom"],   // names actually found
      "cdcArtifacts": ["cdc_adoQpoasnfa76pfcZLmcfl_Array"],
      "seleniumAttributes": [],
      "chromeObject": { "present": true, "runtimePresent": true, "shape": "populated" }
    },
    "headless": {
      "uaHasHeadlessChrome": false,
      "pluginsLength": 3,
      "mimeTypesLength": 2,
      "languagesEmpty": false,
      "permissionsNotificationState": "prompt",   // from Permissions API
      "notificationPermission": "default",        // from Notification.permission
      "permissionsContradiction": false
    },
    "webgl": {
      "supported": true,
      "unmaskedVendor": "Google Inc. (NVIDIA)",
      "unmaskedRenderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)",
      "isSoftware": false,
      "vendorHash": "…", "paramsHash": "…"
    },
    "canvas": { "supported": true, "hash": "a1b2…", "blocked": false, "zeroed": false },
    "audio": { "supported": true, "hash": "c3d4…", "sampleSum": 123.456, "blocked": false },
    "hardware": {
      "hardwareConcurrency": 8,
      "deviceMemory": 8,
      "maxTouchPoints": 0
    },
    "screen": {
      "width": 2560, "height": 1440,
      "availWidth": 2560, "availHeight": 1400,
      "innerWidth": 1280, "innerHeight": 720,
      "outerWidth": 1280, "outerHeight": 800,
      "devicePixelRatio": 1.5,
      "colorDepth": 24
    },
    "fonts": {
      "method": "measurement",          // "measurement" | "fontAccessAPI"
      "detected": ["Arial", "Segoe UI", "Calibri", "..."],
      "count": 42
    },
    "locale": {
      "intlTimeZone": "America/New_York",
      "timezoneOffsetMin": 300,
      "language": "en-US",
      "languages": ["en-US", "en"]
    },
    "behavior": {
      "durationMs": 3000,
      "mouse": {
        "moveEvents": 143, "pathPoints": 143,
        "straightSegmentsRatio": 0.06,     // fraction of near-perfectly-linear segments
        "clickCount": 2, "clicksAtElementCenter": 0,
        "avgSpeedPxPerMs": 0.42, "speedVariance": 0.19
      },
      "keyboard": {
        "keydownCount": 11, "pasteEvents": 0,
        "interKeyMsMean": 142, "interKeyMsStdev": 63
      },
      "scroll": { "events": 5, "distancePx": 640 },
      "focusBlur": { "focusEvents": 1, "blurEvents": 0 },
      "timeToFirstInteractionMs": 812,
      "interacted": true
    },
    "environment": {
      "userAgent": "Mozilla/5.0 …",       // as JS sees it (navigator.userAgent)
      "userAgentData": {                   // navigator.userAgentData, if present
        "brands": [{ "brand": "Chromium", "version": "124" }, …],
        "mobile": false, "platform": "Windows"
      },
      "cookieEnabled": true,
      "doNotTrack": null,
      "webdriverKeyPresent": false,
      "productSub": "20030107",
      "vendor": "Google Inc.",
      "platform": "Win32"
    }
  }
}
```

**Notes**

- All Layer-1 fields are **client-asserted** and therefore inherently
  untrustworthy — the backend treats them as *claims to be checked against each
  other and against Layer 2/3*, never as ground truth.
- `layer1.environment.userAgent` (what JS sees) and the Layer-2 `User-Agent`
  header (what the server sees) should match; a mismatch is a signal.
- Hashes (canvas/audio/webgl) are for **consistency** checks, not
  automation-in-themselves (see [docs/07](07-coherence-engine.md)).

---

## 3. `POST /api/analyze` — response (the report)

```jsonc
{
  "reportVersion": "1",
  "generatedAtMs": 1731000000123,
  "coverage": {
    "layer1": "captured",
    "layer2Values": "captured",
    "layer2Order": "captured",        // "captured" | "unavailable" | "normalized"
    "layer3Tls": "captured",          // "captured" | "unavailable"
    "layer3Http2": "captured",
    "layer3Ip": "captured",
    "captureMode": "b",
    "notes": ["Transport captured on a separate probe connection (CORS fetch)."]
  },
  "score": {
    "coherence": 38,                  // 0–100; higher = more internally consistent
    "verdict": "likely_automated",    // "likely_human" | "suspicious" | "likely_automated"
    "confidence": 0.86,               // 0–1; how much captured coverage backs the verdict
    "weightedPenalty": 62,            // sum of penalties applied (see engine doc)
    "coverageAdjusted": true
  },
  "contradictions": [
    {
      "id": "tls_ua_vendor_mismatch",
      "severity": "critical",
      "title": "TLS fingerprint says Go/net-http, User-Agent says Chrome",
      "evidence": { "ja4": "t13d…", "matchedStack": "go-nethttp", "uaClaim": "Chrome/124" },
      "weight": 40,
      "explanation": "A genuine Chrome browser produces a Chrome TLS ClientHello. A Go HTTP client's ClientHello with a Chrome UA means the UA is spoofed."
    }
  ],
  "signals": [
    {
      "id": "navigator_webdriver",
      "layer": 1,
      "group": "automation_flags",
      "title": "navigator.webdriver",
      "value": true,
      "verdict": "automation",        // "ok" | "suspicious" | "automation" | "unavailable"
      "weight": 25,
      "explanation": "Set to true by WebDriver-controlled browsers (Selenium, Puppeteer, Playwright)."
    }
    // … one entry per signal, across all layers …
  ],
  "raw": {
    "layer1": { /* echoed, for the "copy JSON" view */ },
    "layer2": { "headerValues": { /* … */ }, "headerOrder": ["…"], "clientHints": { /* … */ } },
    "layer3": { "ja3": "…", "ja4": "…", "http2": { /* … */ }, "ip": { "addr": "…", "asn": 15169, "org": "GOOGLE", "isDatacenter": true } }
  }
}
```

**Field semantics**

- `verdict` per signal ∈ `ok | suspicious | automation | unavailable`. `unavailable`
  means "not captured on this deployment" and is excluded from scoring.
- `score.verdict` is the headline. `score.confidence` scales with coverage — a
  Topology-A report (no Layer 3) caps confidence lower because the strongest
  discriminators are absent.
- `contradictions` are a curated, high-weight subset surfaced separately in the
  UI; each also appears implicitly in the signal math.
- `raw` is the full echo used by "copy report as JSON."

---

## 4. `GET /probe` (edge probe) — request/response

**Request:** `GET https://tls.example.com/probe?nonce=<uuid>` — a *simple* CORS
GET (no custom headers) so no preflight fires.

**Response (default):** `204 No Content` with CORS headers; the transport report
is stored server-side under the nonce.

**Response (optional live-display mode):** `200` with:

```jsonc
{
  "reportVersion": "1",
  "nonce": "…",
  "tls": {
    "ja3": "769,4865-4866-…,0-23-65281-…,29-23-24,0",
    "ja3Hash": "e7d705a3286e19ea42f587b344ee6865",
    "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
    "version": "TLS 1.3",
    "alpn": ["h2", "http/1.1"],
    "matchedStack": "chrome-124-win",   // best-effort classification, may be "unknown"
    "cipherCount": 15, "extensionCount": 12
  },
  "http2": {
    "settings": [["HEADER_TABLE_SIZE",65536],["ENABLE_PUSH",0],["MAX_CONCURRENT_STREAMS",1000],["INITIAL_WINDOW_SIZE",6291456],["MAX_HEADER_LIST_SIZE",262144]],
    "windowUpdate": 15663105,
    "pseudoHeaderOrder": [":method",":authority",":scheme",":path"],
    "akamaiFingerprint": "1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
    "matchedStack": "chrome"
  },
  "headerOrder": ["host","connection","sec-ch-ua","user-agent","…"],
  "ip": { "addr": "203.0.113.9", "asn": 7922, "org": "COMCAST", "isDatacenter": false }
}
```

**`GET /result?nonce=<uuid>`** (server-to-server, `Authorization: Bearer
<shared-secret>`): returns the same transport JSON for the main backend to merge,
then deletes the nonce.

---

## 5. Versioning & compatibility

- `reportVersion` is a string, bumped on any breaking schema change. The UI reads
  the version and refuses to render unknown majors rather than mis-rendering.
- New **signals** are additive and do not bump the version; consumers must ignore
  unknown `signals[].id`.
- New **verdict values** or a change to `score`'s meaning **do** bump the version.
- The `/api/reference` payload carries its own `referenceVersion` and a
  `generatedAt`, so the "compare to known browsers" view can show data freshness.

---

## 6. Errors

| Status | When | Body |
|--------|------|------|
| `400` | Malformed Layer-1 JSON, wrong `reportVersion` major | `{ "error": "bad_request", "detail": "…" }` |
| `413` | Body over the size cap (guard: e.g. 256 KiB) | `{ "error": "payload_too_large" }` |
| `429` | Rate limit exceeded (see [docs/10](10-privacy-security.md)) | `{ "error": "rate_limited", "retryAfterMs": 2000 }` |
| `200` | Always for a valid analyze, even if Layer 3 is unavailable | The report, with `coverage` reflecting what was captured |

The analyze endpoint **does not** 5xx on probe/nonce problems — those degrade
coverage inside a `200` response. It only 5xx's on genuine internal faults.
