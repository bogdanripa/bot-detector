# 02 — The Honeypot (a 3-step funnel)

The honeypot is the deployable app that composes the detection libraries
([docs/13](13-libraries-and-packaging.md)) into a realistic, instrumented
**three-page funnel**. It is a **single self-hosted Go server that terminates its
own TLS** ([docs/01](01-architecture-and-hosting.md)), so every page navigation is
a fresh top-level request whose Layer 2/3 it captures directly.

> The honeypot has **no detection logic of its own.** Its server imports
> `go/tlscapture`, `go/httpcapture`, `go/ipasn`, and `go/engine`; its web pages
> import `@botdetect/client`. This doc specifies the funnel and the infrastructure.
> A different consumer with a smaller capability set uses the same libraries — see
> [docs/13 §5](13-libraries-and-packaging.md#5-integration-recipes).

---

## 1. The funnel

Three pages, each a real navigation, each instrumented server- and client-side:

```
  ┌────────────────────────────────────────────────────────────────────────┐
  │  PAGE 1  —  GET /       "Landing": text, then a link BELOW THE FOLD       │
  │  server: capture connSignals #1 (TLS/JA4, header order, Sec-Fetch, IP)   │
  │  client: @botdetect/client → passive L1 + instrument the SCROLL + LINK   │
  └───────────────┬────────────────────────────────────────────────────────┘
                  │  user SCROLLS to reach the link, then CLICKS it
                  │  (a real scroll gesture + a real, trusted, approached click)
                  ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │  PAGE 2  —  GET /step-2      "Form": name/email/topic/message + submit   │
  │  server: capture connSignals #2  + verify the funnel transition          │
  │  client: passive Layer 1 (again) + form behavior + honeypot traps (§8B)  │
  └───────────────┬────────────────────────────────────────────────────────┘
                  │  user FILLS + SUBMITS the form
                  ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │  PAGE 3  —  GET /result     "Report": verdict + probability + checklist   │
  │  server: capture connSignals #3  + final aggregate score                 │
  │  client: render the report (automationType, contradictions, per-check)   │
  └────────────────────────────────────────────────────────────────────────┘
```

Why a funnel beats a single page: it elicits **three natural interactions** — a
**scroll** (the Page-1 link sits **below the fold**, so you must scroll to reach
it), a **link click**, then a **form fill** — instead of an artificial "interact
here" box, and it turns the **transitions between pages** into first-class
detection signals (§3) that only exist when detection spans multiple navigations.
The below-fold link matters because *how you scroll* is a strong tell: humans emit
a stream of wheel/touch/keyboard gestures with inertia, while automation usually
reaches an element with `scrollIntoView()` — an instant, pixel-aligned jump with no
gesture at all ([docs/14 §4.2](14-agentic-and-cdp-detection.md#42-scroll-provenance--how-the-viewport-got-where-it-is)).

### 1.1 Routes

```
GET  /                serves Page 1; captures connSignals #1; mints sessionId
                      (Secure;HttpOnly;SameSite=Strict cookie + bootstrap island);
                      issues a click-gated funnel token
GET  /step-2          serves Page 2 (the form); captures connSignals #2; VERIFIES
                      the transition (came from Page 1 via a real click, §3)
GET  /result          serves Page 3 (the report); captures connSignals #3
POST /api/analyze     receives per-step client signals { sessionId, step, ... };
                      merges with the session's connSignals + funnel state; returns
                      the running report
POST /api/submit      the form submission (funnel + form-behavior checkpoint);
                      303-redirects to /result
GET  /app.js /app.css /static/*   assets (embed.FS)
GET  /api/health      liveness
```

`step ∈ { landing, form, result }`. Each page's client bundle collects and POSTs
`/api/analyze` for its step; the engine aggregates across steps and `/result`
renders the final report.

---

## 2. What each step captures (library wiring)

Every navigation is captured **server-side** by the Go libraries; every page runs
the **client** library. This is the "uses our libraries server- and client-side"
requirement made concrete.

### Page 1 — Landing (`GET /`)

- **Server** (`tlscapture` + `httpcapture` + `ipasn`): capture `connSignals #1` —
  JA3/JA4, HTTP/2 fingerprint, header **values + order**, `Sec-Fetch-*`
  (`Sec-Fetch-Site: none` for a typed/bookmarked entry, or the referrer's site),
  IP→ASN. Also check Web Bot Auth signature headers ([docs/14 §8](14-agentic-and-cdp-detection.md#8-signal-class-f--positive-agent-identification-web-bot-auth)).
  Mint `sessionId`; store `connSignals #1` under it; issue a **funnel token** the
  link will carry (§4).
- **Client** (`@botdetect/client`): `collectPassive()` (Layer 1); render the link
  **below the fold**; and instrument **both** the scroll and the click —
  - **scroll provenance** ([docs/14 §4.2](14-agentic-and-cdp-detection.md#42-scroll-provenance--how-the-viewport-got-where-it-is)):
    did the link enter view via a real gesture (wheel/touch/key/scrollbar, with
    inertia) or a **teleport** `scrollIntoView`/`scrollTo` (no gesture,
    pixel-aligned landing)?
  - **click provenance** ([docs/14 §4](14-agentic-and-cdp-detection.md#4-signal-class-b--input-provenance-catches-os-level-agents-)):
    approach trail, `isTrusted`, coalesced samples, landing offset, dwell.

  POST `/api/analyze { step: 'landing', layer1, scrollToLink, linkClick }`.

### Page 2 — Form (`GET /step-2`)

- **Server**: capture `connSignals #2` and **verify the transition** (§3): valid
  session, arrived from Page 1 (`Referer: /`, `Sec-Fetch-Site: same-origin`,
  `Sec-Fetch-User: ?1`), and a **click-activated** funnel token. Compare
  `connSignals #2` to `#1` for cross-navigation consistency (§3.4).
- **Client**: `collectPassive()` again (Layer-1 consistency across pages),
  `instrumentForm()` + the CDP-leak / cadence / biometrics collectors, and render
  the **active honeypot traps** ([docs/14 §8B](14-agentic-and-cdp-detection.md#8b-active-honeypot-probes--dom-agent-vs-vision-agent-traps)):
  a DOM honeypot field, a vision trap, a smooth-pursuit target. POST
  `/api/analyze { step: 'form', layer1, behavior, traps }`, and `POST /api/submit`
  on submit.

### Page 3 — Result (`GET /result`)

- **Server**: capture `connSignals #3`; run the final aggregate score over all
  steps (`engine.Score`); render the report into the page (or serve it for the
  client to render).
- **Client**: render banner + `automationType` + contradictions + the per-check
  list ([docs/08](08-frontend-ui.md)); offer "copy JSON" and "re-run" (which
  returns to `/`).

---

## 3. Funnel-integrity signals (the new detection value)

A multi-page funnel exposes signals a single page cannot. These are checked
server-side across the three navigations and fed to the engine.

### 3.1 Step ordering / deep-linking

Real users traverse `/` → `/step-2` → `/result` **in order**. A request to
`/step-2` or `/result` with **no prior step recorded for the session** means the
client **jumped straight to a deep URL** — typical of crawlers and DOM agents that
enumerate links, or an agent told "go to the form." Strong `funnel_bypass` signal.

### 3.2 The scroll-and-click that produced Page 2

Page 1's link is **below the fold**, so reaching Page 2 requires **scrolling then
clicking** — two provenance checks in one transition:

- **Scroll to the link** ([docs/14 §4.2](14-agentic-and-cdp-detection.md#42-scroll-provenance--how-the-viewport-got-where-it-is)):
  the link should enter the viewport via a **real gesture** (wheel/touch/keyboard/
  scrollbar, with human inertia and non-aligned landing). A **teleport**
  `scrollIntoView()`/`scrollTo()` — position jumps in one frame, no originating
  gesture, link lands **pixel-aligned** — is the automation tell (and DOM agents
  like Playwright/`browser-use` do exactly this before clicking).
- **The click** should be user-activated: `Sec-Fetch-User: ?1`,
  `Sec-Fetch-Site: same-origin`, `Sec-Fetch-Dest: document`,
  `Referer: https://app.example.com/`, and a **click-activated funnel token**
  (§4) — proof a *trusted, approached* click occurred, not `location = '/step-2'`
  or a direct GET.

Missing `Sec-Fetch-User`/Referer/token, **or** a teleport-scroll into the link,
⇒ the link was **not reached and clicked by a human hand**. This is the funnel's
version of "did a real person scroll down and click, or did the agent
`scrollIntoView` + navigate to the URL?" — among the cleanest agent tells
available.

### 3.3 Cross-page timing

- **Dwell on Page 1** before clicking (a human reads the text; sub-second dwell ⇒
  didn't read).
- **Time-to-first-interaction** on Page 2; **fill→submit** duration.
- **Total funnel time** — faster than a human could plausibly read + click + fill
  ⇒ automated, independent of how polished the input looks.

### 3.4 Cross-navigation fingerprint consistency ⭐ (new contradiction)

`connSignals #1`, `#2`, and `#3` should be **identical** for a genuine single
client: same **JA4**, same **User-Agent**, same **IP/ASN**, consistent Layer-1
(navigator/WebGL/fonts) across page loads. A change mid-funnel is a strong
`cross_nav_inconsistency` contradiction:

- **JA4 flips** between pages ⇒ a different TLS stack served different steps (e.g.
  one tool renders Page 1, another fetches Page 2).
- **UA or Layer-1 changes** ⇒ different client per step / session replay.
- **IP hops** across steps ⇒ proxy rotation mid-funnel.

A real browser produces one coherent client across all three navigations;
a multi-tool automation pipeline (a common agent/scraper pattern — one component
follows links, another submits) betrays itself here.

### 3.5 Referer & navigation-type continuity

`/result`'s Referer should be `/step-2`; its navigation should follow the form
submission, not a direct GET. Each hop's `Sec-Fetch-*` should match a genuine
same-origin document navigation.

> **Scoring.** These funnel signals become engine contributions and two new
> contradictions — `funnel_bypass` and `cross_nav_inconsistency` — added in
> [docs/07 §3](07-coherence-engine.md#3-contradiction-rules-the-high-weight-core).
> As always they inform the probability and `automationType`; the honeypot reports,
> it does not block.

---

## 4. The click-gated funnel token

Ties the three pages together with proof of a **real** Page-1 link click, directly
implementing the gesture-gated token from
[docs/14 §8B](14-agentic-and-cdp-detection.md#8b-active-honeypot-probes--dom-agent-vs-vision-agent-traps):

```
1. GET /  → server issues token T (bound to sessionId), embeds it inert in the page.
2. The link's href does NOT initially carry a valid T. On a TRUSTED click
   (isTrusted, real approach trail, coalesced samples), the client activates T —
   e.g. POST /api/analyze { step:'landing', linkClick } returns an activated T,
   or the client rewrites the href to include T at click-time from the gesture handler.
3. GET /step-2 must present an ACTIVATED T. 
      - activated  ⇒ a real human click produced this navigation.
      - absent / un-activated ⇒ direct navigation or synthetic click ⇒ funnel_bypass.
```

The token is single-use and session-bound (TTL ~10 min). It is a *signal input*,
not a hard gate — an un-activated token lowers the human probability and flips
`automationType` toward agentic; it does not 403 the request (the honeypot reports,
it does not enforce).

---

## 5. Session & connection capture (server internals)

TLS/H2/header-order are properties of the **connection**; we capture them per
navigation and bind them to the session per step.

```go
// One store: sessionId -> { connSignals[step], funnelState, runningReport }  (TTL ~10 min).
// tlscapture computes JA3/JA4 in GetConfigForClient (keyed by conn RemoteAddr);
// httpcapture reads header values+order from the raw navigation;
// each GET handler binds the current connection's signals to the session under its step.
srv := &http.Server{
    Addr:      ":443",
    TLSConfig: lc.InstrumentConfig(baseTLSConfig),   // go/tlscapture
    ConnContext: func(ctx context.Context, c net.Conn) context.Context {
        return context.WithValue(ctx, connKey, c.RemoteAddr())
    },
    Handler: router,   // GET / , /step-2 , /result each capture connSignals[step]
}
log.Fatal(srv.ListenAndServeTLS("", ""))             // certs via autocert
```

> **Keepalive / H2 note.** The `POST /api/analyze` calls are `fetch` requests
> (`Sec-Fetch-Mode: cors`/`same-origin`) and may reuse or reopen the TLS
> connection. We bind Layer 2/3 to each **navigation** (the `GET` of each page),
> because those carry true browser header-order and document `Sec-Fetch-*`
> semantics. An analyze POST that doesn't look same-origin is itself recorded (the
> payload may have been replayed outside the page).

---

## 6. Host configuration

| Setting | Value | Reason |
|---------|-------|--------|
| Host | Compute Engine VM (e2-small) or a VPS with a static IP | Need a raw :443 socket and our own cert. |
| TLS | `autocert` (Let's Encrypt) in-process | Our process runs the handshake — required for Layer 3. |
| Process mgmt | `systemd` unit (or a container) with auto-restart | Single always-on service. |
| Ports | 443 (HTTPS), 80 (ACME challenge + 301 redirect) | autocert HTTP-01, redirect to HTTPS. |
| Firewall | 80/443 in; deny the rest | Minimal surface. |
| Scaling | Vertical first. For horizontal, move the session store to Redis and front with an **L4 (TCP passthrough)** LB — never L7, which re-terminates TLS. | Preserve the socket. |
| Logs/metrics | Structured logs, anonymized IPs; funnel completion/bypass rate | See [docs/10](10-privacy-security.md). |

Header hygiene: filter hop-by-hop/proxy headers before analysis; if an L4 proxy
fronts the box, honor `PROXY protocol` or one trusted `X-Forwarded-For` hop,
else use `RemoteAddr`.

---

## 7. TLS & DNS

```
app.example.com  →  A/AAAA to the server's static IP  (autocert / Let's Encrypt)
```

One domain, one origin, all three pages same-origin (so the funnel transitions are
`same-origin` navigations). HTTPS via in-process autocert; port 80 serves the ACME
challenge and 301-redirects to HTTPS. **No CDN, no managed L7 LB, no Cloudflare
orange-cloud** — any of those re-terminate TLS and destroy Layer 3.

---

## 8. Local development

- `make dev` runs the server with a `mkcert` cert on `app.localtest.me`, so TLS
  termination (and Layer 3 capture) works locally exactly as in prod.
- Drive the full funnel with real Chrome and with headless Playwright (Chromium at
  `/opt/pw-browsers/chromium`) — and with an agent that **deep-links** straight to
  `/step-2` to exercise `funnel_bypass`.
- `Makefile`: `make dev`, `make test`, `make build`, `make deploy`
  (rsync the binary + `systemctl restart`), `make capture` (dump raw fixtures —
  [docs/11 §3](11-testing.md#3-capturing-fixtures-how-to-build-the-golden-set)).

---

## Appendix — Serverless fallback (split deployment)

Retained only for the case where someone is later *forced* onto a managed
serverless platform (Cloud Run / Cloud Functions) and still wants Layer 3. It is
**not** the chosen design.

The problem: a managed platform terminates TLS at the GFE (see
[docs/01 §2](01-architecture-and-hosting.md#2-why-we-do-not-deploy-on-a-google-cloud-function)),
so the function can't see Layer 3. The workaround: keep the app on the managed
platform and add **one small raw-socket "edge probe"** on a separate subdomain
that terminates its own TLS; the browser makes an extra cross-origin `fetch` to it,
and the probe returns JA3/JA4 + H2 + header order keyed by a single-use nonce the
app minted. Trade-offs: a second host, a nonce store, CORS, and same-client
verification — all of which self-hosting eliminates; and the transport signals then
describe a `fetch` connection, not a navigation. Every part of this exists *only*
to compensate for not owning the socket. The recommendation stands: own the socket.
