# 05 — Layer 2: HTTP (Backend)

Signals derived from the HTTP request itself: header **values**, header **order**,
client hints, `Sec-Fetch-*`, and their consistency with the User-Agent.

> **We capture this on the page navigation.** Because we self-host and terminate
> our own TLS ([docs/01 §3](01-architecture-and-hosting.md#3-what-we-deploy-instead-a-single-self-hosted-tls-terminating-server)),
> both header **values and true order** are available — captured at `GET /` (the
> real navigation, `Sec-Fetch-Mode: navigate`) and joined to the session. This is
> exactly the signal a managed serverless front end would have destroyed, which is
> why we don't deploy on one. Everything in this doc works on the self-hosted
> server.

---

## 1. Header values

Parse and evaluate these, after filtering any hop-by-hop / proxy headers
(see [docs/02 §1.3](02-deployment-topology.md#13-header-hygiene)).

| Header | Expectation for a real browser | Verdict when violated |
|--------|--------------------------------|-----------------------|
| `User-Agent` | Present, well-formed, matches a known browser grammar | missing/garbled → `automation` |
| `Accept` | Rich browser value (e.g. `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8`) for a navigation | minimal (`*/*`) on a navigation → `suspicious` (curl/requests default) |
| `Accept-Language` | Present, with `q`-values, consistent with `navigator.languages` | absent → `suspicious` |
| `Accept-Encoding` | `gzip, deflate, br` (+ `zstd` on newer Chrome) | `identity` only, or absent → `suspicious` (many HTTP libs) |
| `Sec-CH-UA` | Present on Chromium ≥ 89; brand list internally consistent with UA | absent on a Chrome UA → `suspicious` |
| `Sec-CH-UA-Mobile` | `?0` desktop / `?1` mobile, consistent with UA & Layer 1 | mismatch → contributes to mobile/desktop coherence |
| `Sec-CH-UA-Platform` | `"Windows"`/`"macOS"`/`"Linux"`/`"Android"` — consistent with UA, WebGL, fonts | mismatch → **cross-layer contradiction** |
| `Sec-Fetch-Site` | For a top-level navigation: `none`; for the analyze fetch: `same-origin` | wrong/absent on Chromium → `suspicious` |
| `Sec-Fetch-Mode` | `navigate` for navigations, `cors`/`no-cors` for fetches | absent on Chromium → `suspicious` |
| `Sec-Fetch-Dest` | `document` for navigations, `empty` for fetch | absent on Chromium → `suspicious` |
| `Sec-Fetch-User` | `?1` on user-initiated navigations | absent on a navigation from Chromium → `suspicious` |
| `Upgrade-Insecure-Requests` | `1` on navigations from most browsers | absent where expected → `suspicious` |
| `DNT` / `Sec-GPC` | Optional; presence/absence not itself a tell but recorded | — |
| `Connection` | On HTTP/1.1: `keep-alive`. On HTTP/2 this header is illegal — its presence is a tell (some libs send it over h2). | illegal-on-h2 → `suspicious` |
| `Priority` | Chrome ≥ 104 sends `Priority: u=..., i` on some requests | absent where Chrome would send it → minor |

### Client-hints consistency

Chromium sends `Sec-CH-UA*`. These must be **internally consistent**:

- `Sec-CH-UA` brand/version list must agree with the UA's Chrome major version.
- `Sec-CH-UA-Platform` must agree with the UA's platform token.
- `Sec-CH-UA-Mobile` must agree with the UA's mobile token and Layer-1
  `maxTouchPoints`/screen.
- High-entropy hints (requested via `Accept-CH` and returned as
  `Sec-CH-UA-Full-Version-List`, `Sec-CH-UA-Arch`, `Sec-CH-UA-Model`,
  `Sec-CH-UA-Bitness`, `Sec-CH-UA-Platform-Version`) can be requested on a second
  round-trip; mismatches with the UA are high-value.

### Sketch (Go, value analysis)

```go
func analyzeHeaderValues(r *http.Request) []Signal {
    var sig []Signal
    ua := r.Header.Get("User-Agent")
    isChromium := strings.Contains(ua, "Chrome/") || r.Header.Get("Sec-CH-UA") != ""

    if ua == "" { sig = append(sig, S("ua_missing", "automation", 30, "No User-Agent header.")) }

    if isChromium && r.Header.Get("Sec-CH-UA") == "" {
        sig = append(sig, S("missing_client_hints", "suspicious", 15,
            "UA claims Chromium but no Sec-CH-UA header — real Chromium always sends it."))
    }
    if isChromium && r.Header.Get("Sec-Fetch-Mode") == "" {
        sig = append(sig, S("missing_sec_fetch", "suspicious", 15,
            "Chromium sends Sec-Fetch-* on navigations and fetches; absent here."))
    }
    // Accept-Encoding, Accept, platform consistency, etc.
    return sig
}
```

---

## 2. UA ↔ header consistency

The cheapest strong signal after `webdriver`: a mismatch between what the UA
*claims* and what the header set *implies*.

| Claim (from UA) | Expected corroboration | Contradiction |
|-----------------|------------------------|---------------|
| Chrome/Chromium | `Sec-CH-UA` present, `Sec-Fetch-*` present, `Accept-Encoding` includes `br` | Any absent → the UA is likely spoofed by a non-Chromium client |
| Safari (WebKit) | **No** `Sec-CH-UA` (Safari doesn't send client hints), specific `Accept` value | Presence of `Sec-CH-UA` with a Safari UA → spoof |
| Firefox | No `Sec-CH-UA`, distinctive `Accept`, `TE: trailers` patterns | `Sec-CH-UA` present with a Firefox UA → spoof |
| Mobile UA | `Sec-CH-UA-Mobile: ?1`, small viewport, touch | Desktop hints/viewport → **mobile/desktop contradiction** |

This is the Layer-2 half of the coherence engine. The Layer-3 half (TLS/H2 vendor
vs. UA vendor) is stronger still and lives in [docs/06](06-layer3-transport.md).

---

## 3. Header order

**The single highest-value Layer-2 signal — and the one most easily lost.**
Browsers emit request headers in a characteristic, stable order. `curl`, Python
`requests`, `axios`, and Go's default `http.Client` each produce a *different*
order. Comparing the captured order against known-good browser orderings catches
HTTP libraries wearing a browser UA.

### 3.1 Why it's hard to capture

- **Go's `http.Header` is a `map[string][]string`** — iteration order is
  randomized and the original order is lost. `httputil.DumpRequest` also does not
  faithfully reproduce the client's wire order.
- **Any TLS-terminating proxy in front destroys it** — HTTP/2 HPACK + the proxy's
  re-serialization normalize the order. This is why we self-host and read the raw
  bytes ourselves rather than deploying behind a managed front end.

### 3.2 How to capture it for real

Because we terminate TLS ourselves, we read the **raw request bytes** of the
`GET /` navigation directly:

1. Wrap the `net.Listener` (or hijack the connection) and read the raw HTTP/1.1
   request-line + header block before handing off, or — for HTTP/2 — read the
   HEADERS frame and record the field sequence as HPACK-decoded (the *decoded*
   order is the client's emission order). Store the ordered list of header
   **names** (lower-cased), excluding pseudo-headers, which are handled in the H2
   fingerprint.
2. Normalize to lower-case names, drop hop-by-hop headers, and compare the
   resulting sequence to the reference orderings in
   [docs/09](09-reference-data.md).

```go
// HTTP/1.1 path: tee the header block off the raw conn at the navigation.
func captureHeaderOrder(raw []byte) []string {
    lines := strings.Split(string(raw), "\r\n")
    var order []string
    for _, ln := range lines[1:] { // skip request line
        if ln == "" { break }
        if i := strings.IndexByte(ln, ':'); i > 0 {
            order = append(order, strings.ToLower(strings.TrimSpace(ln[:i])))
        }
    }
    return order
}
```

### 3.3 Scoring the order

- Compute a distance (e.g. Kendall-tau / longest-common-subsequence) between the
  captured order and each reference browser order.
- If the closest match is a **known HTTP library** (curl/requests/Go/axios/okhttp)
  rather than any browser → **strong `automation` signal / contradiction**,
  especially when the UA claims a browser.
- If it matches a browser but **not the one the UA claims** (Firefox order under a
  Chrome UA) → `suspicious`.
- Exact match to the claimed browser → `ok`.

### 3.4 A note on why we self-host

Header order is the signal a managed serverless front end would have normalized
away (HPACK → proxy re-serialization). We capture it faithfully **only because our
own process terminates TLS and reads the navigation's raw header block**. This is
one of the two signals (with TLS/JA4) that drove the decision not to deploy on a
Cloud Function — see [docs/01 §2](01-architecture-and-hosting.md#2-why-we-do-not-deploy-on-a-google-cloud-function).

---

## 4. Cookies & sessions

- Whether the client returns the `sessionId` cookie set at `GET /` (a stateless
  HTTP client often won't send it back on the analyze POST) — a mild signal, and a
  natural by-product of the session mechanism we already have.
- `Sec-Fetch-Site: same-origin` on the analyze POST confirms the fetch came from
  our own page, not a replayed/curled request. A `same-origin` analyze POST with a
  *cross-site* or absent `Sec-Fetch-Site` suggests the payload was replayed
  outside the browser.

---

## 5. Putting Layer 2 together

The Layer-2 analyzer returns a set of `Signal`s plus a `layer2` raw block for the
report's `raw` echo:

```jsonc
"layer2": {
  "headerValues": { "user-agent": "…", "accept": "…", "accept-language": "…", "sec-ch-ua": "…", "sec-fetch-mode": "navigate", … },
  "clientHints": { "brands": ["Chromium","Google Chrome","Not-A.Brand"], "platform": "Windows", "mobile": false },
  "headerOrder": ["host","connection","sec-ch-ua","sec-ch-ua-mobile","user-agent", …],
  "headerOrderSource": "navigation",   // captured at GET / on the self-hosted server
  "infrastructureHeaders": []                                                             // shown, not scored (empty when no proxy fronts us)
}
```

The coherence engine then joins these against Layer 1 (UA-as-JS-sees-it vs.
UA-header; `navigator.languages` vs. `Accept-Language`) and Layer 3 (UA vendor vs.
TLS/H2 vendor). Those joins are the highest-weight checks in the whole system —
see [docs/07](07-coherence-engine.md).
