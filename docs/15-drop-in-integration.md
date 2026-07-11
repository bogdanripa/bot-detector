# 15 — Drop-in Integration & Auto-Instrumentation

**Design requirement:** the libraries must add to almost any existing web app with
minimal effort, and detection must happen **automatically, in the background**,
without the host wiring up individual elements or building our funnel.

Two consumers, one library set:

- **The honeypot** ([docs/02](02-deployment-topology.md)) is our *maximal*
  integration — a bespoke 3-step funnel engineered to elicit the strongest signal.
- **A drop-in consumer** is any existing app that wants background detection over
  *its own* pages, forms, and navigations, with near-zero code.

Both use the same `@botdetect/client` + server libraries. This doc is how the
drop-in case works and the guarantees that make it safe to add anywhere.

---

## 1. Principles

1. **Observe by default, don't enforce.** The library *collects and scores*; it
   never blocks, redirects, challenges, or mutates the host's behavior. The host
   reads a verdict and decides what (if anything) to do. (Our honeypot only
   reports; a consumer WAF could act — their call.)
2. **Automatic & background.** After a one-time install, collection runs on its own
   — passive signals on load, behavioral/input/scroll/CDP-leak collectors attached
   globally, batched and beaconed to an endpoint. No per-element wiring.
3. **Non-interfering.** No `preventDefault`, no swallowed events, no global
   pollution beyond one namespaced handle, no dependency, tiny footprint, fully
   `try/catch`-isolated — if the library or its endpoint fails, the host app is
   unaffected.
4. **Works with what's already there.** It instruments the host's *existing* forms,
   links, inputs, and navigations (including SPA route changes and dynamically
   added DOM). No special markup required.
5. **Degrades to available signal.** Whatever the host's real UX provides is what
   gets measured; missing signal classes just lower confidence
   ([docs/13 §4](13-libraries-and-packaging.md#4-the-capability-model-flexibility)).

---

## 2. The minimal-effort ladder (integration tiers)

Pick the tier that matches how much access you have. Each is a strict superset of
the one before.

| Tier | You add | You get | Effort |
|------|---------|---------|--------|
| **0 — Client only** | one `<script>` tag (or one `import` + `autostart()`) | Layer 1 + behavior/input/scroll/CDP-leak signals; optional in-browser scoring | ~1 line |
| **1 — + Server middleware** | wrap your handler with the middleware | Tier 0 **+** Layer 2 header values + IP/ASN + server-side scoring on the request context | ~2 lines |
| **2 — + Own the socket** | also wrap your `tls.Config`/listener | Tier 1 **+** Layer 3 (TLS JA3/JA4, HTTP/2 fingerprint, raw header order) | ~3 lines |
| **3 — The honeypot funnel** | build the bespoke 3-page funnel | Tier 2 **+** the funnel-integrity signals at full strength (below-fold scroll, click-gated token, dedicated traps) | a small app |

Most consumers live at **Tier 1 or 2**. Tier 3 is our showcase. Crucially, **the
rich signals are not exclusive to Tier 3** — see [§5](#5-how-the-strong-signals-survive-drop-in).

---

## 3. Client: one install, auto-everything

### 3.1 Install

Either a script tag (served from the host's **own** origin ideally):

```html
<script src="/botdetect.js" data-endpoint="/__botdetect" defer></script>
```

…or a module + `autostart()`:

```js
import botdetect from '@botdetect/client';
const bd = botdetect.autostart({ endpoint: '/__botdetect' });   // sensible defaults
// optional: read the current client-side view
bd.onVerdict(v => console.debug(v.automationProbability, v.automationType));
```

That's the whole integration. `autostart()` does everything below.

### 3.2 What `autostart()` auto-instruments

- **Passive Layer 1** on load (navigator, WebGL, canvas, audio, screen, fonts,
  locale, automation flags, CDP leaks) — one shot, sub-150 ms.
- **Global behavioral capture** via **document-level capture-phase listeners**
  (`{ passive: true }` where allowed): pointer move/down/up, click, wheel, scroll,
  keydown, focus/blur, paste, input. Because it's delegation, it covers **every**
  element — including ones added later.
- **Input / scroll / click provenance** ([docs/14 §4–4.2](14-agentic-and-cdp-detection.md#4-signal-class-b--input-provenance-catches-os-level-agents-))
  computed from those global streams — teleport clicks, coalesced-event absence,
  `scrollIntoView` teleports, etc. — on the host's own controls.
- **Form dynamics** for any `<form>`/input on the page, discovered by
  **event delegation + a `MutationObserver`** so dynamically-rendered forms are
  covered with no host changes. **Only dynamics** (timings, counts, variances,
  `inputType`) are read — **never field values**.
- **SPA navigations**: `history.pushState`/`replaceState`/`popstate`/`hashchange`
  are hooked so each client-side route change is treated as a navigation step —
  enabling cross-navigation behavior and consistency even in a single-page app.
- **Batch + beacon**: signals are buffered and flushed on an interval, on
  `visibilitychange`/`pagehide` (via `navigator.sendBeacon`), before an SPA nav,
  and on form submit — using `fetch(..., { keepalive: true })` as fallback. Low,
  bounded network overhead.

### 3.3 Non-interference contract (why it's safe to drop in)

- **Never calls `preventDefault`/`stopPropagation`** and uses capture-phase passive
  listeners, so it cannot alter the host app's event handling.
- **One namespaced handle** (`window.__botdetect`), nothing else on globals; safe
  to include twice (idempotent).
- **Fully isolated**: every collector is `try/catch`-wrapped; a thrown probe
  degrades to `unavailable` and never surfaces to the host page. If the endpoint is
  unreachable, buffered data is dropped silently.
- **No third-party requests**, no framework, no fonts — a single small ES module.
  Serve it same-origin so it adds no new origin to the host.
- **CSP-friendly**: ships as an external file (not inline) so a host with a strict
  CSP just allowlists `'self'` (or a hash); the auto-inject option (§4.4) can add
  the script's hash to an existing CSP header.

### 3.4 Client config (data-attrs or options)

`endpoint`, `sampleRate` (fraction of sessions to instrument), `collect`
(subset/allow-list of collectors), `behavior: true|false`, `respectDNT`,
`respectGPC`, `flushIntervalMs`, `maxBufferBytes`, `scoreClientSide` (Tier-0
in-browser scoring via `@botdetect/engine`).

---

## 4. Server: middleware + own-the-socket, endpoint auto-mounted

### 4.1 The few lines (Go)

```go
bd := botdetect.New(botdetect.Options{ /* defaults load config/scoring.json */ })

srv := &http.Server{
    Addr:        ":443",
    TLSConfig:   bd.InstrumentTLS(baseTLSConfig), // Tier 2: Layer 3 capture
    ConnContext: bd.ConnContext,                  // binds the ClientHello to the conn
    Handler:     bd.Handler(myExistingApp),       // Tier 1: middleware + auto-mounts /__botdetect
}
log.Fatal(srv.ListenAndServeTLS("", ""))
```

- `bd.Handler(next)` is ordinary `http.Handler` middleware: it captures Layer 2
  (values + order) and joins the Layer 3 signals, **auto-mounts the client
  ingest/analyze endpoint** (default `/__botdetect`, configurable), optionally
  serves the client script, scores in the background, and passes the request
  through unchanged.
- Skip `InstrumentTLS`/`ConnContext` for **Tier 1** (no socket ownership): you get
  Layers 1–2 + IP/ASN + scoring; Layer 3 reports `unavailable` and the engine
  scores around it.

### 4.2 Reading the verdict (background, non-blocking)

```go
func anyHandler(w http.ResponseWriter, r *http.Request) {
    v := botdetect.FromContext(r)   // { Probability, AutomationType, Confidence, Coverage, Checks }
    // observe: log it, tag your analytics, expose a header — or ignore it entirely.
    // enforce (optional, host's choice): if v.Probability > 0.9 { … }
}
```

The verdict is computed in the background and attached to the request context; the
host never has to call the scorer or render anything. For fully out-of-band use,
set `Options.OnVerdict(func(r, v))` and never touch the context at all — great for
logging/metrics pipelines.

### 4.3 Framework adapters

Thin wrappers so it's idiomatic everywhere: Go `net/http`/chi/gin/echo; Node
Express/Connect/Fastify (reusing `@botdetect/engine`); Python ASGI/WSGI/FastAPI/
Django. Each is the same `New → wrap handler → FromContext` shape. Layer-3 caveats
per language are in [`node/`](../node/README.md) / [`python/`](../python/README.md).

### 4.4 Optional client-script auto-injection

To avoid the host editing templates at all, the middleware can rewrite HTML
responses to insert `<script src="/__botdetect/c.js" defer>` before `</head>`, and
add the script's hash to the response `Content-Security-Policy`. **Off by default**
(it modifies responses); the explicit `<script>` tag (§3.1) is the recommended,
most transparent path.

---

## 5. How the strong signals survive drop-in

The funnel-integrity and behavioral signals were designed around the honeypot's
bespoke pages, but most work **opportunistically** on a host's existing UX:

| Signal | In drop-in mode |
|--------|-----------------|
| Passive Layer 1, CDP leaks | ✅ fully (page-load, global) |
| Input / click provenance | ✅ on the host's own clickable elements |
| Scroll provenance | ✅ on the host's own scrollable content (no need for a below-fold link) |
| Form behavior + honeypot traps | ✅ on the host's existing forms; DOM/vision *traps* are honeypot-specific (Tier 3) unless the host opts to render them |
| Cross-navigation consistency (JA4/UA/IP) | ✅ across the host's **own** multi-page navigations and SPA route changes |
| Deep-link / step-ordering | ⚠️ only where the host has a natural funnel; not synthesized |
| Below-fold-link scroll gate, click-gated token | Tier-3 only (they *are* the funnel) |

So a plain Tier-2 drop-in already gets: environment fingerprint, all provenance
classes, behavior, and cross-navigation consistency — i.e. the on-device-agent
detection ([docs/14](14-agentic-and-cdp-detection.md)) works on an ordinary app.
The honeypot funnel adds the *engineered* extras (a forced scroll, a gated click,
dedicated traps) that a passive host UX can't guarantee.

---

## 6. Privacy & consent defaults (so it's safe to add anywhere)

- **Dynamics only, never content.** Field values, keystroke characters, and
  clipboard contents never leave the browser — enforced in the collector.
- **No cross-site identity.** Signals are per-session diagnostic inputs, not a
  tracking profile; nothing is persisted beyond the short session TTL
  ([docs/10](10-privacy-security.md)).
- **Consent hooks.** `respectDNT`/`respectGPC` and `sampleRate` let a host stay
  within its own privacy posture; a host can gate `autostart()` behind its consent
  banner. IPs are anonymized in any retained logs.
- **Disclosable.** The library does exactly one thing (score the caller about
  itself); a host can describe it in its privacy notice in one line.

---

## 7. Summary

Adding detection to an existing app is: **one script tag** (Tier 0), **plus a
middleware wrap** (Tier 1), **plus a `tls.Config` wrap** for Layer 3 (Tier 2) —
after which detection runs automatically in the background and the host reads a
verdict off the request context (or a callback) whenever it wants, or never. The
honeypot ([docs/02](02-deployment-topology.md)) is the same libraries turned up to
Tier 3.
