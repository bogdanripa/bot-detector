# 08 — Frontend / Report UI

A single-page report. The constraint that dominates every UI decision:
**the frontend must not pollute the fingerprint it measures.** No framework, no
web-font CDN, no analytics, no third-party requests. One small JS file, one CSS
file, both same-origin.

---

## 1. Page structure

```
┌─────────────────────────────────────────────────────────────┐
│  HEADER: title + one-line purpose + coverage badge           │
├─────────────────────────────────────────────────────────────┤
│  HERO SCORE                                                   │
│   ┌───────────┐   Verdict: LIKELY AUTOMATED                   │
│   │   38/100  │   Confidence: 86%                             │
│   │ coherence │   Coverage: layers 1–2–3 (edge probe)        │
│   └───────────┘                                               │
├─────────────────────────────────────────────────────────────┤
│  ⚠ CONTRADICTIONS (surfaced first — they matter most)        │
│   • TLS says Go/net-http, User-Agent says Chrome   [critical] │
│   • Header order matches curl                       [high]    │
├─────────────────────────────────────────────────────────────┤
│  INTERACTIVE TEST AREA (button + input, for behavior)        │
├─────────────────────────────────────────────────────────────┤
│  SIGNAL SECTIONS (collapsible), mirroring docs 04–06:        │
│   ▸ Automation flags        ▸ Headless indicators            │
│   ▸ WebGL / Canvas / Audio  ▸ Hardware / Screen              │
│   ▸ Fonts                   ▸ Locale / Timezone              │
│   ▸ Behavior                ▸ HTTP headers & order           │
│   ▸ TLS / HTTP2 / IP        (labeled "unavailable" on Topo A)│
├─────────────────────────────────────────────────────────────┤
│  FOOTER: "Copy report as JSON"  ·  privacy note  ·  re-run   │
└─────────────────────────────────────────────────────────────┘
```

### Row anatomy

Each signal renders as one row:

```
[badge]  Signal name                         captured value
         one-line explanation of why it matters
```

- **Badge:** `ok` (green), `suspicious` (amber), `automation` (red),
  `unavailable` (grey). Grey is a first-class state — it means "not captured on
  this deployment," visually distinct from a pass.
- **Value:** the raw captured value, monospaced, truncated with a "show more"
  for long hashes.
- **Explanation:** the `explanation` string from the report — the tool teaches
  as it reports.

---

## 2. Rendering flow

1. On load, read the bootstrap nonce from the inlined
   `<script type="application/json" id="bootstrap">` island.
2. Render a **skeleton** immediately with a "collecting…" state and start the 3s
   behavioral sampler (so the user sees the interactive area and can play with it).
3. Fire the edge-probe fetch in parallel (Topology B).
4. When collection completes, POST `/api/analyze`, then render the report by
   iterating `report.signals` grouped by `group`, plus `report.contradictions` at
   the top and `report.score` in the hero.
5. Everything renders from the JSON contract ([docs/03](03-api-contract.md)) — the
   UI has no detection logic of its own beyond formatting.

```js
function render(report) {
  renderHero(report.score, report.coverage);
  renderContradictions(report.contradictions);   // sorted by severity
  const groups = groupBy(report.signals, s => s.group);
  for (const [name, signals] of groups) renderSection(name, signals);
  wireCopyJson(report);
}
```

---

## 3. "Copy report as JSON"

- A single button that copies `report.raw` (the full echo) + the score +
  contradictions to the clipboard as pretty-printed JSON.
- Also offer a "Download JSON" fallback (`Blob` + `a[download]`) for clients where
  clipboard is blocked.
- This is the primary sharing/debugging affordance — a QA engineer pastes it into
  a bug report.

---

## 4. Interactive test area

A small `<section>` with:

- a **button** ("click me") — measures click position vs. element center, and
  time-to-first-interaction;
- a **text input** ("type something") — measures inter-keystroke variance and
  paste-vs-type;
- optionally a small scrollable box — measures scroll behavior.

Purely to give the behavioral collector something to observe. Label it clearly:
*"Interact here for a few seconds — we measure timing/movement patterns, not what
you type."* (And genuinely don't send the typed *content* — only timing metrics.)

---

## 5. Accessibility & UX

- Semantic HTML, `aria-live="polite"` on the score region so it announces when it
  resolves.
- Badges convey state with **text + shape + color**, never color alone
  (colorblind-safe).
- Works without the behavioral area (keyboard-only users, no-mouse users) — the
  report still renders; behavior is simply `inconclusive`.
- Respect `prefers-reduced-motion` and `prefers-color-scheme` (light/dark).
- No layout shift once the report lands (reserve the hero space in the skeleton).

---

## 6. Keeping the frontend fingerprint-clean

| Rule | Reason |
|------|--------|
| No framework runtime (React/Vue/etc.) | Adds globals and timing artifacts; changes the JS environment we measure. |
| No web-font `<link>` to a CDN | A cross-origin request pollutes Layer 2/3 for that connection and adds a network dependency; use system font stack. |
| No analytics / tag managers | They inject globals and make network requests that confuse the report. |
| Inline critical CSS, one same-origin `app.css` | Avoids extra origins. |
| One same-origin `app.js`, no CDN imports | Same. Build with esbuild to a single file if you must bundle. |
| Avoid polyfills that patch globals | We measure globals; don't mutate them. Feature-detect and degrade instead. |
| Set an explicit, documented `Content-Security-Policy` | `default-src 'self'`; no external origins. This both hardens the app and guarantees the frontend stays self-contained. |

The irony to embrace: a bot-detection tool whose own page made ten third-party
requests would be diagnosing a fingerprint it corrupted. The clean-frontend rule
is a correctness requirement, not just hygiene.

---

## 7. States to design for

| State | UI |
|-------|-----|
| Collecting | Skeleton + interactive area live + "sampling behavior (3s)…" |
| Full report (Topo B/C) | All sections populated, Layer 3 shown |
| Degraded (Topo A) | Layer 3 section greyed with the "unavailable on this deployment" explainer + a coverage caption on the hero |
| Probe failed (Topo B, probe unreachable) | Layer 3 greyed with "probe unreachable" note; report still renders on L1–2 |
| Analyze error (400/429/5xx) | Friendly error card with a "retry" button; never a blank page |
| Re-run | A "re-run" button re-collects (fresh behavior sample, fresh nonce) without a full reload |
