# 08 — Frontend / Report UI (the Honeypot Web App)

> **This is the honeypot's web app** (`honeypot/web`), a **consumer of
> `@botdetect/client`** ([docs/13](13-libraries-and-packaging.md)). It imports the
> client library to collect signals and renders the report; it has no detection
> logic of its own. Another consumer could collect with the same library and render
> however it likes — this doc describes *our* reference UI.

The honeypot is a **three-page funnel** ([docs/02](02-deployment-topology.md)):
a landing page with a link, a form page, and a report page. Each page is a real
navigation that the server re-captures, and each runs `@botdetect/client`. The
**report** (banner + checklist) lives on **Page 3**.

Governing constraint: **the frontend must not pollute the fingerprint it
measures.** No framework, no web-font CDN, no analytics, no third-party requests.
One small same-origin JS bundle + CSS, served on every page.

---

## 1. The three pages

### Page 1 — Landing (`GET /`)

```
┌──────────────────────────────────────────────────────────────┐
│  HEADER: title + one-line purpose                            │
│                                                              │
│  A short paragraph of real, readable copy (gives a human a   │
│  reason to pause and read — dwell is measured).              │
│                                                              │
│              →  [ Continue to the check ]  ←  (the LINK)      │
│                                                              │
│  (silent) @botdetect/client: passive Layer 1 + instrument    │
│  the link click (approach trail, trusted, coalesced, dwell)  │
└──────────────────────────────────────────────────────────────┘
```

The link is an ordinary `<a href="/step-2?…">`. On a **trusted** click the client
activates the funnel token ([docs/02 §4](02-deployment-topology.md#4-the-click-gated-funnel-token))
and the browser navigates normally to Page 2. An agent that jumps straight to
`/step-2` skips this and trips `funnel_bypass`.

### Page 2 — Form (`GET /step-2`)

```
┌──────────────────────────────────────────────────────────────┐
│  THE FORM (a plausible "request a demo" / contact form)      │
│   ┌────────────────────────────────────────────────────────┐ │
│   │  Name  [__________]   Email [__________]               │ │
│   │  Topic [ ▼ ]          Message [____________________]   │ │
│   │  (+ hidden DOM honeypot field; + vision/pursuit traps) │ │
│   │             [ Submit ▸ ]                               │ │
│   └────────────────────────────────────────────────────────┘ │
│   "We measure HOW you fill this in — timing and movement,    │
│    never what you type. Nothing here is submitted anywhere."  │
│                                                              │
│  (silent) passive Layer 1 (again, for cross-page consistency)│
│  + form behavior + CDP-leak/cadence/biometrics + trap results│
└──────────────────────────────────────────────────────────────┘
```

On submit → `POST /api/submit` → 303 → Page 3.

### Page 3 — Report (`GET /result`)

```
┌──────────────────────────────────────────────────────────────┐
│  ███████  VERDICT BANNER                                     │
│  █ 93% █   🔴  LIKELY AUTOMATED  ·  agent-driven (agentic-os) │
│  █ auto █   Automation probability 93%   Confidence 90%      │
│  ███████   (green 🟢 PASS  /  amber 🟡 SUSPICIOUS  /  red 🔴)  │
├──────────────────────────────────────────────────────────────┤
│  ⚠ CONTRADICTIONS (shown first — they matter most)           │
│   • TLS says Go/net-http, User-Agent says Chrome   [critical] │
│   • Reached the form by deep-link (no click)        [high]    │
│   • JA4 changed between pages 1 and 2               [high]    │
├──────────────────────────────────────────────────────────────┤
│  CHECKLIST — every test, grouped, each with a status badge:  │
│   Automation flags   · Headless · WebGL/Canvas/Audio         │
│   Transport/network  · Funnel integrity · Input provenance   │
│   Form behavior      · Honeypot traps                        │
│     ✗ Reached form without a real click   [fail]             │
│     ✗ Click landed at exact element center [fail]            │
│     ⚠ IP is datacenter-owned   AS15169 GOOGLE  [warn]         │
│   … all remaining checks …                                   │
├──────────────────────────────────────────────────────────────┤
│  FOOTER: "Copy report as JSON"  ·  privacy note  ·  re-run   │
└──────────────────────────────────────────────────────────────┘
```

The report on Page 3 aggregates **all three steps** — passive Layer 1 (twice),
Layer 2/3 from all three navigations, the funnel-integrity signals, the link-click
provenance, the form behavior, and the honeypot-trap outcomes.

### The banner

- Dominant element. A large **percentage** (the automation probability) + a **band
  word** (PASS / SUSPICIOUS / FAIL) + **color** (green/amber/red) + an **icon**
  (✓ / ⚠ / ✗). State is conveyed by text **and** shape **and** color — never color
  alone (colorblind-safe).
- Shows `confidence` as a secondary line ("confidence 90%") so a green result on
  thin evidence reads honestly.
- Shows `automationType` when not `none` (e.g. "agent-driven browser
  (`agentic-os`)") so the banner says *what kind* of automation was found.

### Checklist rows

Each check from `report.checks` renders as one row:

```
[badge]  Check title                     captured value
         one-line explanation of why it matters
```

- **Badge:** `pass` (green ✓), `warn` (amber ⚠), `fail` (red ✗), `unavailable`
  (grey –). Grey is first-class: "couldn't run this probe" (e.g. WebGL disabled),
  visually distinct from a pass, and excluded from the score.
- **Value:** the raw captured value, monospaced, long hashes truncated with
  "show more".
- **Explanation:** the `explanation` string straight from the report — the tool
  teaches as it reports.
- Rows are grouped by `check.group` (Automation flags, Headless, WebGL/Canvas/
  Audio, Hardware/Screen, Fonts, Locale, HTTP headers, Transport/network, **Funnel
  integrity**, **Input provenance**, Form behavior, **Honeypot traps**). Groups are
  collapsible; failing groups auto-expand.

---

## 2. Rendering flow (across the three pages)

```
Page 1 (/):        read { sessionId, step:'landing', funnelToken } from the bootstrap island;
                   collect passive Layer 1; instrument the link;
                   POST /api/analyze {step:'landing'}  (fire-and-forget; no report shown yet).
Page 2 (/step-2):  collect passive Layer 1 again; instrument the form + traps;
                   on submit POST /api/analyze {step:'form'} then POST /api/submit → 303 /result.
Page 3 (/result):  read the aggregated report (server-rendered island, or GET it);
                   render(report): banner + automationType + contradictions + full checklist.
```

Pages 1–2 collect silently (the funnel should feel like an ordinary sign-up flow —
that naturalness is what makes the behavior measurable). The **verdict is revealed
on Page 3**. A single small `app.js` handles all three pages, branching on
`bootstrap.step`.

```

The banner + checklist are rendered once, on Page 3, from the aggregated report:

```js
function render(report) {                        // Page 3 only
  renderBanner(report.score);                    // %, band, color, confidence, automationType, pass/fail
  renderContradictions(report.contradictions);   // sorted by severity, on top
  const groups = groupBy(report.checks, c => c.group);
  for (const [name, checks] of groups) renderGroup(name, checks);
  wireCopyJson(report);
}
```

The UI has **no detection logic** of its own beyond formatting — everything comes
from the JSON contract ([docs/03](03-api-contract.md)).

---

## 3. The form (Page 2, interaction surface)

- A plausible, self-justifying form: **name, email, a topic `<select>`, a message
  `<textarea>`, and a normal **Submit** button** — it should read like an ordinary
  "request a demo" form, not a "bot test," so the interaction is natural.
- Instrumented per [docs/04 §2.8](04-layer1-browser.md#28-form-behavior-signals-phase-2):
  per-field cadence, focus/tab order, mouse path into fields, paste-vs-type,
  corrections, submit timing.
- **Privacy, stated inline:** *"We measure how you fill this in — timing and
  movement — never what you type. Nothing here is stored."* And it's true: only
  dynamics (counts/timings/variances) are sent; field **contents never leave the
  browser** — the `POST /api/submit` carries the behavior payload, not the values.
- On submit → `POST /api/submit` → the server 303-redirects to **Page 3**
  (`/result`), which shows the verdict. (Submitting is a real navigation, so it's
  also a funnel transition the server captures.)
- Works for keyboard-only and autofill users: tabbing through or using a password
  manager lowers behavioral confidence rather than penalizing them (autofill ≠
  automation — see the gating in
  [docs/07 §2.6](07-coherence-engine.md#26-form-behavior-layer-1-phase-2-bounded)).
- **Embeds the active honeypot traps** ([docs/14 §8B](14-agentic-and-cdp-detection.md#8b-active-honeypot-probes--dom-agent-vs-vision-agent-traps)):
  a DOM honeypot field (off-screen, `aria-hidden`, "leave empty"), a vision trap,
  a smooth-pursuit target. These bait real-browser AI agents and, by *which* trap
  trips, attribute the agent as DOM-based vs. vision-based. They must never trap
  assistive tech (accessibility caveat in §8B).

---

## 4. "Copy report as JSON" & re-run (Page 3)

- **Copy JSON:** one button copies `report.raw` + `score` + `contradictions` +
  `funnel`, pretty-printed, to the clipboard (with a "Download JSON" `Blob`
  fallback). Primary sharing/debugging affordance — a QA engineer pastes it into a
  bug report.
- **Re-run:** returns to `GET /` (fresh session → fresh funnel), so a developer can
  tweak their client and traverse the funnel again.

---

## 5. States to design for

| State | UI |
|-------|-----|
| Page 1 / Page 2 | Ordinary landing + form; collection is silent (no verdict shown yet) |
| Page 3 rendering | Banner "compiling report…" then the full report |
| Page 3 done | Banner + probability + `automationType` + confidence + full grouped checklist |
| Probe failed (e.g. WebGL disabled) | That check greys to `unavailable` with a reason; score unaffected |
| Funnel bypass (deep-linked to `/step-2` or `/result`) | Page 3 still renders, with the `funnel_bypass` contradiction prominent and the missing steps noted |
| Session expired (404) | Friendly card: "session expired — start over"; a link back to `/` |
| Analyze error (400/429/5xx) | Error card with retry; never a blank page |

---

## 6. Keeping the frontend fingerprint-clean

| Rule | Reason |
|------|--------|
| No framework runtime (React/Vue/…) | Adds globals and timing artifacts; changes the JS environment we measure. |
| No web-font `<link>` to a CDN | A cross-origin request pollutes the very connection we fingerprint; use a system font stack. |
| No analytics / tag managers | Inject globals and make network requests that confuse the report. |
| Inline critical CSS, one same-origin `app.css` | Avoid extra origins. |
| One same-origin `app.js`, no CDN imports | Same. Bundle with esbuild to a single file if needed. |
| Avoid global-patching polyfills | We measure globals; don't mutate them — feature-detect and degrade. |
| Strict `Content-Security-Policy` (`default-src 'self'`) | Hardens the app *and* guarantees the frontend stays self-contained. |

A bot-detection tool whose own page made ten third-party requests would be
diagnosing a fingerprint it corrupted. The clean-frontend rule is a correctness
requirement, not just hygiene.

---

## 7. Accessibility

- Semantic HTML; `aria-live="polite"` on the banner so the verdict is announced
  when it resolves and when it updates at phase 2.
- Badges use text + shape + color, never color alone.
- Full keyboard operability of the form; keyboard-only fills are not penalized.
- Respect `prefers-reduced-motion` and `prefers-color-scheme` (light/dark).
- No layout shift when the report lands (reserve banner + checklist space in the
  skeleton).
