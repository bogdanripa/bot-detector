# 13 — Libraries & Packaging

The project is **two parts**:

1. **Detection libraries** — small, composable, independently importable packages
   that do the actual detection. A consumer can take all of them, or just the
   client-side piece, or just the server-side piece, or everything except Layer 3.
   They degrade gracefully: whatever signals are available get scored, and the
   report says what was and wasn't captured.
2. **The honeypot** — the deployable diagnostic app (the instrumented form + the
   report UI) that is *one consumer* of the libraries, wiring them together into a
   full three-layer experience. It has no detection logic of its own; it imports
   the libraries like anyone else would.

This doc defines the package boundaries, their public APIs, the capability model
that makes them flexible, and how they're distributed. The per-layer detail lives
in [docs/04](04-layer1-browser.md) (Layer 1), [docs/05](05-layer2-http.md)
(Layer 2), [docs/06](06-layer3-transport.md) (Layer 3), and
[docs/07](07-coherence-engine.md) (scoring).

---

## 1. Design goals for the libraries

| Goal | What it means concretely |
|------|--------------------------|
| **Composable** | Each layer is its own package with no hard dependency on the others. Import Layer 1 alone, or Layer 2+3, or just the engine. |
| **Degradable** | Any layer can be absent. The engine accepts a partial `SignalSet` and returns a probability + an explicit `coverage`; missing layers lower `confidence`, never crash. |
| **Embeddable** | Drop the server pieces into an *existing* Go server as `net/http` middleware; drop the client piece into an *existing* web app as one small ES module. No framework, no global state. |
| **Framework-agnostic** | The client lib is vanilla TS with zero runtime deps. The server libs depend only on the Go stdlib + a couple of well-scoped packages. |
| **Language-honest** | Detection that must run in the browser is a JS/TS lib; detection that must run at the socket is a Go lib. The scoring *rules* are language-neutral (a shared JSON config) so both sides agree. |
| **Stable contract** | The wire format between client and server is its own versioned package, imported by both, so they can't drift. |

---

## 2. Repository layout (monorepo)

```
bot-detector/
├── packages/                         # JS/TS libraries (npm)
│   ├── client/                       # @botdetect/client   — Layer 1 collectors + form behavior
│   ├── engine-js/                    # @botdetect/engine   — JS scoring (for client-only deploys)
│   └── schema/                       # @botdetect/schema   — shared wire types (TS) + JSON Schema
│
├── go/            ✅ IMPLEMENTED    # Go server libraries (Go modules) — the reference impl
│   ├── httpcapture/                  # Layer 2: header values + order (net/http middleware)
│   ├── tlscapture/                   # Layer 3: TLS ClientHello → JA3/JA4, HTTP/2 fp
│   ├── ipasn/                        # Layer 3: IP → ASN, datacenter classification
│   ├── engine/                       # scoring engine (authoritative)
│   └── schema/                       # shared wire types (Go), generated from JSON Schema
│
├── node/          🚧 TO BE IMPLEMENTED  # Node server libraries — README stub + capability notes
├── python/        🚧 TO BE IMPLEMENTED  # Python server libraries — README stub + capability notes
│
├── config/
│   ├── scoring.json                  # language-neutral weights/rules/thresholds (single source of truth)
│   └── reference/                    # header-order / JA4 / H2 / ASN reference tables (docs/09)
│
├── honeypot/                         # THE DEPLOYABLE APP — a consumer of the libraries
│   ├── server/                       # composes go/ (httpcapture + tlscapture + ipasn + engine); serves the funnel
│   └── web/                          # TS: composes @botdetect/client; renders the pages + report
│
└── docs/
```

- **`packages/*`** publish to npm; **`go/*`** are Go modules. `node/` and
  `python/` are **placeholders** for now — each ships only a `README.md` describing
  the packages to build, the public API to match (mirroring `go/`), and the
  Layer-3 caveat (see [§2.1](#21-language-support-go-first)).
- **`config/scoring.json`** is the shared source of truth for weights and rules,
  read by every engine port — `go/engine`, `@botdetect/engine` (JS, browser + Node),
  and eventually a Python engine (see [§6](#6-scoring-config-one-source-two-engines)).
- **`honeypot/`** is *just an integration* over `go/` + `@botdetect/client`.
  Deleting it leaves a fully usable set of libraries; that's the test of whether
  the split is real.

### 2.1 Language support (Go first)

The **server** libraries are offered per language — Go, Node, Python — because a
consumer embeds them in *their* backend. We implement **one language fully first,
Go**, and ship `README.md` stubs for the others.

**Why Go first: Layer 3.** Capturing the TLS ClientHello (→ JA3/JA4), the HTTP/2
fingerprint, and raw header order requires owning the socket, and Go is the only
one of the three where that is clean: `crypto/tls`'s `GetConfigForClient` exposes
the parsed `ClientHelloInfo`, `utls` gives extension order, `x/net/http2`'s framer
reads the SETTINGS frame, and mature JA3/JA4 libraries exist. In Node and Python,
`tls`/`ssl` don't surface the ClientHello at all. Everything *else* (Layer 2
values, IP/ASN, the engine) is easy in every language — Layer 3 is what forces the
order.

| Capability | `go/` ✅ | `node/` 🚧 | `python/` 🚧 |
|------------|:-------:|:---------:|:-----------:|
| Layer 2 header **values** (`httpcapture`) | ✅ native | ✅ easy (ASGI/WSGI/`http` middleware) | ✅ easy |
| Layer 2 header **order** | ✅ raw read | ✅ HTTP/1.1 via `req.rawHeaders` (H2 harder) | ⚠️ framework-dependent |
| Layer 3 IP/ASN (`ipasn`) | ✅ | ✅ | ✅ |
| Layer 3 **TLS JA3/JA4 + H2 fp** (`tlscapture`) | ✅ native | ❌ hard — needs raw-TCP ClientHello peek, a native addon, **or a Go sidecar** | ❌ hard — same options |
| Scoring **engine** | ✅ `go/engine` | ✅ **reuses `@botdetect/engine`** (JS) — no port | ⚠️ port needed (reads `scoring.json`) |

The honest consequence: a Node or Python server can deliver Layers 1–2 + IP/ASN +
scoring immediately, but for **Layer 3** it must either front the app with a small
Go `tlscapture` sidecar that terminates TLS, or accept `layer3Tls: unavailable`
(the engine already scores around it — [§4](#4-the-capability-model-flexibility)).
The **browser client** (`@botdetect/client`) is inherently JS/TS and shared by all
three server languages. Each language's stub README records this so an implementer
starts with eyes open.

---

## 3. The packages

### 3.1 `@botdetect/client` (TS, browser) — Layer 1

Collects passive Layer-1 signals and, optionally, form-behavior dynamics. Zero
runtime dependencies.

```ts
import { collectPassive, instrumentForm, type Layer1Signals, type BehaviorSignals }
  from '@botdetect/client';

// Passive collection (phase 1). Never throws; failed probes report `unavailable`.
const passive: Layer1Signals = await collectPassive();

// Optional form-behavior collection (phase 2). Dynamics only — never field contents.
const flush = instrumentForm(document.querySelector('#my-form')!);
myForm.addEventListener('submit', () => {
  const behavior: BehaviorSignals = flush();
  // send `passive` and/or `behavior` wherever you like — the lib doesn't POST for you
});
```

- **You own transport.** The lib returns plain objects; it never assumes an
  endpoint. The honeypot POSTs them to `/api/analyze`; another consumer might send
  them over its own channel.
- **Selectable collectors.** `collectPassive({ include: ['webgl','automationFlags'] })`
  or `{ exclude: ['audio'] }` for consumers that want a subset (e.g. to keep the
  payload tiny or avoid a probe that trips their CSP).
- **Optional in-browser scoring.** Pair with `@botdetect/engine` for a
  client-only deployment with no backend (see [§5.3](#53-client-only-no-backend)).

### 3.2 `@botdetect/engine` (TS) & `go/engine` (Go) — scoring

Both take a `SignalSet` (any subset of layers) and return a `Report`. The Go
engine is authoritative for full server-side deployments; the JS engine exists so
a client-only consumer can score in the browser. Both interpret the same
`config/scoring.json`.

```go
import "github.com/bogdanripa/bot-detector/go/engine"

eng := engine.New(engine.LoadConfig("config/scoring.json"))
report := eng.Score(engine.SignalSet{
    Layer1: &l1,      // *Layer1Signals or nil
    Layer2: &l2,      // *Layer2Signals or nil
    Layer3: &l3,      // *Layer3Signals or nil  (nil ⇒ "unavailable", scored around)
    Behavior: &beh,   // optional phase-2 signals
})
// report.Score.AutomationProbability, report.Score.Confidence,
// report.Score.Coverage, report.Checks, report.Contradictions
```

The engine is **pure**: `SignalSet -> Report`, no I/O, deterministic. This is what
makes the whole thing testable and embeddable. Missing layers are first-class —
see [§4](#4-the-capability-model-flexibility).

### 3.3 `go/httpcapture` (Go) — Layer 2

`net/http` middleware that extracts header values, header order, client hints, and
`Sec-Fetch-*` from a request, into a `Layer2Signals`.

```go
import "github.com/bogdanripa/bot-detector/go/httpcapture"

// As middleware: attaches Layer2Signals to the request context.
mux.Handle("/", httpcapture.Middleware(myHandler))

// Or standalone, from any *http.Request:
l2 := httpcapture.FromRequest(r)   // header values always; order only if the
                                   // request came through a capturing listener (see tlscapture)
```

- Header **values** work from any `*http.Request`.
- Header **order** requires reading raw bytes, which requires owning the socket —
  so `httpcapture` reads it from a context value that `tlscapture`'s listener
  populates. Without that listener, `l2.HeaderOrder == nil` and the corresponding
  check reports `unavailable`. This is the flexibility contract in action: Layer 2
  values are always available; Layer 2 *order* is available only when the deploy
  owns the connection.

### 3.4 `go/tlscapture` (Go) — Layer 3 transport

Wraps a `net.Listener` / `tls.Config` so the server captures the client
ClientHello (→ JA3/JA4) and the HTTP/2 fingerprint on connections **it
terminates**.

```go
import "github.com/bogdanripa/bot-detector/go/tlscapture"

lc := tlscapture.New()                       // holds per-conn fingerprints, short TTL
tlsCfg := lc.InstrumentConfig(baseTLSConfig) // sets GetConfigForClient + ALPN hooks
ln := lc.InstrumentListener(rawListener)     // tees ClientHello bytes for extension order
// later, in a handler:
l3tls := lc.ForConn(r)                        // *TLSFingerprint or nil if not captured
```

- **Only works when your process terminates TLS.** Behind a TLS-terminating proxy
  (CDN, managed serverless front end) it captures nothing useful and reports
  `unavailable` — exactly the situation [docs/01 §2](01-architecture-and-hosting.md#2-why-we-do-not-deploy-on-a-google-cloud-function)
  describes. The library doesn't pretend; the consumer just gets `nil` and the
  engine scores around it.
- Ships the raw-ClientHello tee + the H2 frame reader so the consumer doesn't
  reimplement JA4/H2 parsing.

### 3.5 `go/ipasn` (Go) — Layer 3 IP/ASN

Resolves an IP to ASN/org and classifies datacenter/cloud/VPN ranges.

```go
import "github.com/bogdanripa/bot-detector/go/ipasn"

cls := ipasn.New(ipasn.WithStaticList(embedded))   // offline datacenter list by default
info := cls.Classify(clientIP)                      // { ASN, Org, IsDatacenter, Country, Timezone }
// Optional: ipasn.WithProvider(maxmind) / WithProvider(ipinfo) behind the same interface
```

Independent of `tlscapture` — you can use IP/ASN classification even in a
deployment that can't capture TLS (the IP is available from `RemoteAddr` or a
trusted `X-Forwarded-For`).

### 3.6 `@botdetect/schema` & `go/schema` — the wire contract

The request/response shapes from [docs/03](03-api-contract.md), defined **once**
as JSON Schema in `packages/schema` and code-generated into TS types and Go
structs. Both the client lib and the engine import their generated types, so the
contract can't drift. Versioned by `reportVersion`.

---

## 4. The capability model (flexibility)

The core idea that makes the libraries composable: **a consumer declares which
signals it can provide, and the engine scores whatever it gets.**

```
SignalSet {
  Layer1?    // present if @botdetect/client ran in a browser
  Layer2?    // header values: present on any server; order: only if socket-owned
  Layer3TLS? // only if the deploy terminates TLS (tlscapture)
  Layer3IP?  // present whenever a client IP is known (ipasn)
  Behavior?  // only after the user interacted with a form
}
```

The engine's `Report` always includes an explicit **coverage** block:

```jsonc
"coverage": {
  "layer1": "captured",
  "layer2Values": "captured",
  "layer2Order": "unavailable",   // e.g. server didn't own the socket
  "layer3Tls": "unavailable",     // e.g. behind a TLS-terminating proxy
  "layer3Ip": "captured",
  "behavior": "captured"
}
```

Rules for degradation (already the design from the coverage/confidence work in
[docs/07 §4.2](07-coherence-engine.md#42-confidence--coverage-adjustment)):

- A check whose inputs weren't captured emits `status: "unavailable"` and
  contributes **zero** to the probability.
- A contradiction rule fires **only if both sides were captured**; otherwise it's
  silently `inconclusive`.
- **Confidence scales with coverage.** A Layer-1-only deployment can still say
  "webdriver=true ⇒ automated" with high confidence (that signal is decisive on
  its own), but a *clean* Layer-1-only result is reported at *lower* confidence
  than a clean all-three-layers result, and the UI/report says which layers backed
  the number.
- The probability is always honest about what it's based on — never fabricated
  from a layer that wasn't there.

This is why "sometimes Layer 3 is unavailable, sometimes you want only the server
or only the client piece" is a first-class supported mode, not a degraded hack.

---

## 5. Integration recipes

### 5.1 Full stack, own the socket (what the honeypot does)

```
web:  @botdetect/client  → collectPassive() + instrumentForm()
server (Go, terminates TLS):
        tlscapture.InstrumentListener + InstrumentConfig   (Layer 3 TLS/H2)
        httpcapture.Middleware                              (Layer 2 values + order)
        ipasn.Classify(RemoteAddr)                          (Layer 3 IP)
        engine.Score(all layers)                            (probability)
```
All layers captured; highest confidence. This is [docs/02](02-deployment-topology.md).

### 5.2 Server-side only, embedded in an existing app

A consumer drops `httpcapture` + `ipasn` + `engine` into their existing Go server
to score inbound requests — **no browser JS at all**. They get Layer 2 values +
IP/ASN (+ Layer 3 TLS *if* they terminate their own TLS via `tlscapture`). Great
for scoring API traffic or bare HTTP clients where there's no page to run JS on.
Coverage: Layer 2/3; `layer1: unavailable`; confidence set accordingly.

### 5.3 Client-only, no backend

A consumer imports `@botdetect/client` + `@botdetect/engine` and scores **entirely
in the browser** — useful for a static site with no server to POST to. Coverage:
Layer 1 (+ behavior); `layer2/3: unavailable`. The JS engine reads the same
`scoring.json`. Honest, lower-confidence, but zero backend.

### 5.4 Client collection + your own scoring

A consumer uses only `@botdetect/client` to collect signals and ships them to
their *own* risk pipeline (not our engine at all). The client lib is just a
well-tested signal collector in that case.

### 5.5 Layer 3 unavailable (behind a proxy/CDN)

Full stack but the deploy sits behind a TLS-terminating proxy. `tlscapture`
returns `nil`; the engine scores Layer 1 + Layer 2 values + IP/ASN, marks
`layer3Tls: unavailable`, and lowers confidence. No code change — just a different
capability set.

---

## 6. Scoring config: one source, two engines

Weights, contradiction rules, caps, thresholds, and the logistic `b0`/scale live
in `config/scoring.json` (the tunable surface from
[docs/07 §7](07-coherence-engine.md#7-implementation-notes)). Both `go/engine` and
`packages/engine-js` interpret it, so:

- there is exactly one place to tune;
- the Go and JS engines can't disagree on a verdict for the same inputs;
- calibration ([docs/07 §7](07-coherence-engine.md)) produces a new `scoring.json`,
  versioned alongside the reference tables in `config/reference/`.

The engines are thin interpreters of this config plus a registry of pure
rule-functions; adding a rule is a function + a config entry + a test.

---

## 7. Versioning & distribution

| Artifact | Distribution | Versioning |
|----------|-------------|------------|
| `@botdetect/client`, `@botdetect/engine`, `@botdetect/schema` | npm | semver; `schema` bumps major on wire-breaking changes (`reportVersion`) |
| `go/httpcapture`, `tlscapture`, `ipasn`, `engine`, `schema` ✅ | Go modules | semver tags; `schema` pinned to the same `reportVersion` |
| `node/*` 🚧 (planned) | npm (server pkgs; reuses `@botdetect/engine`) | mirrors Go API + `reportVersion` |
| `python/*` 🚧 (planned) | PyPI | mirrors Go API + `reportVersion` |
| `config/scoring.json`, `config/reference/*` | embedded in the engine builds + published as a versioned data artifact | its own `configVersion` + `generatedAt`, surfaced in the report |

Go ships first ([§2.1](#21-language-support-go-first)); Node and Python are
`README.md` stubs until built, and their engines must agree with Go on the shared
`SignalSet` fixtures before release.

- The **wire contract** (`schema`) is the coupling point; everything else depends
  on it, not on each other. Client `1.x` and server `1.x` interoperate as long as
  `reportVersion` majors match.
- Libraries follow **semver**; a breaking change to a public API is a major bump.
- The scoring config is versioned *separately* from code, so you can recalibrate
  and ship new weights without a library release.

---

## 8. Testing implications

This split makes testing cleaner (and aligns with
[docs/11](11-testing.md)):

- **Each library is unit-tested in isolation** — `httpcapture` against fixture
  requests, `tlscapture` against captured ClientHello bytes, `ipasn` against IP
  fixtures, the engines against `SignalSet` fixtures.
- **The engine's degradation is tested directly**: feed a `SignalSet` with
  `Layer3 == nil` and assert coverage/confidence/verdict behave (the matrix's
  "coverage rows" in [docs/11 §1](11-testing.md#1-the-validation-matrix)).
- **Go and JS engines are cross-checked** against the same `SignalSet` fixtures to
  prove they agree (same `scoring.json` → same probability within tolerance).
- **The honeypot gets a thin e2e test** — it's just an integration, so most
  coverage is in the libraries.

---

## 9. What moves where (from the current docs)

Nothing in the detection design changes — this is a *packaging* reframe:

| Existing doc | Becomes |
|--------------|---------|
| [docs/04](04-layer1-browser.md) Layer 1 | the spec for `@botdetect/client` |
| [docs/05](05-layer2-http.md) Layer 2 | the spec for `go/httpcapture` |
| [docs/06](06-layer3-transport.md) Layer 3 | the spec for `go/tlscapture` + `go/ipasn` |
| [docs/07](07-coherence-engine.md) scoring | the spec for `go/engine` + `@botdetect/engine` + `config/scoring.json` |
| [docs/03](03-api-contract.md) API contract | the spec for `@botdetect/schema` + `go/schema` |
| [docs/02](02-deployment-topology.md) deployment | how the **honeypot** composes the libraries |
| [docs/08](08-frontend-ui.md) UI | the **honeypot** web app (a consumer of `@botdetect/client`) |

The honeypot ([docs/02](02-deployment-topology.md) + [docs/08](08-frontend-ui.md))
is the reference integration that proves the libraries compose into the full
three-layer, three-step-funnel experience.
