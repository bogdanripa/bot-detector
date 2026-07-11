# 08 — Frontend / Report UI (the Honeypot Web App)

> **This is the honeypot's web app** (`honeypot/web`), a **consumer of
> `@botdetect/client`** ([docs/13](13-libraries-and-packaging.md)). It imports the
> client library to collect signals and renders the report; it has no detection
> logic of its own. Another consumer could collect with the same library and render
> however it likes — this doc describes *our* reference UI.

The app itself does the reporting: **a big green/red pass-or-fail banner with the
automation probability, plus a checklist of every test with a status badge next to
each.** The page is also the measurement surface — it centers **an instrumented
form** whose fill dynamics feed phase 2.

Governing constraint: **the frontend must not pollute the fingerprint it
measures.** No framework, no web-font CDN, no analytics, no third-party requests.
One small same-origin JS file, one CSS file.

---

## 1. Page structure

```
┌──────────────────────────────────────────────────────────────┐
│  HEADER: title + one-line purpose                            │
├──────────────────────────────────────────────────────────────┤
│  ███████  VERDICT BANNER (fills on phase 1, updates phase 2)  │
│  █ 93% █   🔴  LIKELY AUTOMATED                               │
│  █ auto █   Automation probability: 93%   Confidence: 90%     │
│  ███████   (green 🟢 PASS  /  amber 🟡 SUSPICIOUS  /  red 🔴)  │
├──────────────────────────────────────────────────────────────┤
│  ⚠ CONTRADICTIONS (shown first — they matter most)           │
│   • TLS says Go/net-http, User-Agent says Chrome   [critical] │
│   • Header order matches curl                       [high]    │
├──────────────────────────────────────────────────────────────┤
│  THE FORM  (the interaction surface — phase 2)               │
│   ┌────────────────────────────────────────────────────────┐ │
│   │  Name  [__________]   Email [__________]               │ │
│   │  Topic [ ▼ ]          Message [____________________]   │ │
│   │             [ Run the behavioral check ▸ ]             │ │
│   └────────────────────────────────────────────────────────┘ │
│   "We measure how you fill this in — timing and movement,    │
│    never what you type. Nothing here is submitted anywhere."  │
├──────────────────────────────────────────────────────────────┤
│  CHECKLIST — every test, grouped, each with a status badge:  │
│   Automation flags                                           │
│     ✓ navigator.webdriver           false          [pass]    │
│     ✗ ChromeDriver cdc_ artifacts   found (2)       [fail]    │
│   Transport / network                                        │
│     ✗ TLS fingerprint vs UA         go-nethttp ≠ Chrome [fail]│
│     ⚠ IP is datacenter-owned        AS15169 GOOGLE  [warn]    │
│   Form behavior (phase 2)                                    │
│     ✗ Typing cadence variance       ~0ms stdev      [fail]    │
│   … all remaining checks …                                   │
├──────────────────────────────────────────────────────────────┤
│  FOOTER: "Copy report as JSON"  ·  privacy note  ·  re-run   │
└──────────────────────────────────────────────────────────────┘
```

### The banner

- Dominant element. A large **percentage** (the automation probability) + a **band
  word** (PASS / SUSPICIOUS / FAIL) + **color** (green/amber/red) + an **icon**
  (✓ / ⚠ / ✗). State is conveyed by text **and** shape **and** color — never color
  alone (colorblind-safe).
- Shows `confidence` as a secondary line ("confidence 90%") so a green result on
  thin evidence reads honestly.
- Animates its update from the phase-1 value to the phase-2 value (respecting
  `prefers-reduced-motion`), with a small "updated after form" note.

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
  Audio, Hardware/Screen, Fonts, Locale, HTTP headers, Transport/network, Form
  behavior). Groups are collapsible; failing groups auto-expand.

---

## 2. Rendering flow (two phases)

```
1. On load, read { sessionId } from the <script id="bootstrap"> island.
2. Render the page shell with the form live and the banner in a "checking…" state.
3. PHASE 1: collect passive Layer 1 → POST /api/analyze {phase:1} → render(report1):
     banner + contradictions + full checklist appear (checks that need phase 2 show
     "awaiting interaction").
4. Instrument the form. When the user submits ("Run the behavioral check"):
     PHASE 2: POST /api/analyze {phase:2, behavior} → render(report2):
     banner + probability + confidence update in place; changed checks
     (report.score.phaseDelta.changed) briefly highlight; the form-behavior group
     fills in.
```

```js
function render(report) {
  renderBanner(report.score);                 // %, band, color, confidence, pass/fail
  renderContradictions(report.contradictions); // sorted by severity, on top
  const groups = groupBy(report.checks, c => c.group);
  for (const [name, checks] of groups) renderGroup(name, checks);
  if (report.score.phaseDelta) highlightChanged(report.score.phaseDelta.changed);
  wireCopyJson(report);
}
```

The UI has **no detection logic** of its own beyond formatting — everything comes
from the JSON contract ([docs/03](03-api-contract.md)).

---

## 3. The form (interaction surface)

- A plausible, self-justifying form: **name, email, a topic `<select>`, a message
  `<textarea>`, a submit button** labeled as the behavioral check ("Run the
  behavioral check").
- Instrumented per [docs/04 §2.8](04-layer1-browser.md#28-form-behavior-signals-phase-2):
  per-field cadence, focus/tab order, mouse path into fields, paste-vs-type,
  corrections, submit timing.
- **Privacy, stated inline:** *"We measure how you fill this in — timing and
  movement — never what you type. Nothing here is submitted anywhere."* And it's
  true: `submit` is `preventDefault()`ed; only dynamics (counts/timings/variances)
  are sent; field **contents never leave the browser**.
- Works for keyboard-only and autofill users: if the user tabs through or uses a
  password manager, phase 2 simply reports lower behavioral confidence rather than
  penalizing them (autofill ≠ automation — see the gating in
  [docs/07 §2.6](07-coherence-engine.md#26-form-behavior-layer-1-phase-2-bounded)).

---

## 4. "Copy report as JSON" & re-run

- **Copy JSON:** one button copies `report.raw` + `score` + `contradictions`,
  pretty-printed, to the clipboard (with a "Download JSON" `Blob` fallback where
  clipboard is blocked). Primary sharing/debugging affordance — a QA engineer
  pastes it into a bug report.
- **Re-run:** reloads `GET /` (fresh session → fresh connection capture), so a
  developer can tweak their client and immediately re-test.

---

## 5. States to design for

| State | UI |
|-------|-----|
| Phase-1 checking | Shell + form live + banner "analyzing…"; checklist skeleton |
| Phase-1 done | Banner + probability + full checklist; behavior checks show "awaiting interaction" |
| Phase-2 done | Banner/probability/confidence updated in place; behavior group filled; changed checks highlighted |
| Probe failed (e.g. WebGL disabled) | That check greys to `unavailable` with a reason; score unaffected |
| Session expired (404) | Friendly card: "session expired — reload to re-run"; a reload button |
| Analyze error (400/429/5xx) | Error card with retry; never a blank page |
| No interaction | Phase-1 report stands; a subtle "fill the form for a deeper check" nudge; behavior stays `inconclusive` |

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
