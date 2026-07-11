# 04 — Layer 1: Browser Environment (Frontend JS)

> **This is the spec for the `@botdetect/client` library**
> ([docs/13 §3.1](13-libraries-and-packaging.md#31-botdetectclient-ts-browser--layer-1)).
> A consumer imports it to collect Layer-1 signals; the honeypot is one such
> consumer. The library returns plain objects and never assumes an endpoint — the
> consumer owns transport.

Everything in this layer is collected by JavaScript in the visitor's browser. It
is the richest layer and the only one that works with **no server at all** (a
client-only deployment can even score it in-browser via `@botdetect/engine`).

**Design rules for every collector**

1. Each collector is an **independent module** exporting `collect(): Promise<Result>`
   and returning `{ value, verdict, note }` where `verdict ∈ ok | suspicious | automation`.
2. Collectors **must not throw** — wrap in try/catch and return
   `{ value: null, verdict: 'unavailable', note: 'threw: <msg>' }`. A single
   failing probe must never abort collection.
3. Collectors must be **cheap and fast** (except the behavioral one, which samples
   over ~3s). Total non-behavioral collection should complete in <150ms.
4. Collectors must **not depend on third-party libraries.** Every added byte
   changes the fingerprint we're measuring (see [docs/01 §6](01-architecture-and-hosting.md)).
5. The *verdict a collector assigns is advisory*; the authoritative scoring
   happens in the backend coherence engine, which can override based on
   cross-layer context. The frontend verdict is a hint and a UI convenience.

> **Important:** the frontend computes raw values and *suggested* verdicts, but the
> backend recomputes verdicts so it can weigh cross-layer contradictions. Never
> trust a client-sent verdict for scoring — trust only the raw values, and even
> those are "claims."

---

## 2.1 Explicit automation flags

The most direct tells. Any single one is a strong `automation` verdict.

### Signals

| Signal | Check | Verdict if positive |
|--------|-------|---------------------|
| `navigator.webdriver` | `=== true` | `automation` |
| PhantomJS globals | `window._phantom`, `window.__phantom`, `window.callPhantom` present | `automation` |
| Nightmare | `window.__nightmare` present | `automation` |
| Selenium/Chromedriver DOM | `document.__selenium_unwrapped`, `__webdriver_evaluate`, `__driver_evaluate`, `__webdriver_script_fn`, `__fxdriver_evaluate`, `__driver_unwrapped`, `__webdriver_unwrapped`, `__selenium_evaluate`, `__webdriver_script_func` | `automation` |
| `cdc_` artifacts | Any `window`/`document` key matching `/^[$]?cdc_/` or the classic `$cdc_asdjflasutopfhvcZLmcfl_` | `automation` (ChromeDriver) |
| CDP / DevTools automation | `window.domAutomation`, `window.domAutomationController` | `automation` |
| Node leakage | `window.Buffer`, `window.emit`, `window.spawn`, `window.process`, `window.require`, `window.global` present in a browser context | `automation` |
| Playwright/Puppeteer bindings | Keys matching `/(playwright|puppeteer|__pw|__playwright)/i`; `window.__playwright__binding__`, exposed `window.__name` (Playwright's addInitScript helper) | `automation` |
| `window.chrome` shape | On a Chrome UA: `window.chrome` missing, or present but `chrome.runtime` missing/`{}` (real Chrome has a populated `runtime`; naive stealth fakes it poorly) | `suspicious` |

### Sketch

```js
export function collectAutomationFlags() {
  const found = { injectedGlobals: [], cdcArtifacts: [], seleniumAttributes: [] };

  if (navigator.webdriver === true) found.navigatorWebdriver = true;

  const globals = ['_phantom','__phantom','callPhantom','__nightmare','domAutomation',
    'domAutomationController','Buffer','emit','spawn','process','require','global'];
  for (const g of globals) if (g in window) found.injectedGlobals.push(g);

  for (const k of Object.keys(window)) if (/^[$]?cdc_/.test(k)) found.cdcArtifacts.push(k);
  for (const k of Object.getOwnPropertyNames(document))
    if (/^__(selenium|webdriver|driver|fxdriver)/.test(k)) found.seleniumAttributes.push(k);

  const chrome = window.chrome;
  found.chromeObject = {
    present: !!chrome,
    runtimePresent: !!(chrome && chrome.runtime),
    shape: chrome ? (chrome.runtime ? 'populated' : 'empty-runtime') : 'absent',
  };
  return found;
}
```

> **Note on `webdriver`.** Some stealth setups delete or redefine
> `navigator.webdriver`. Also probe *how* it's defined: a genuine `false` is a data
> property on the `Navigator` prototype; a value patched via `Object.defineProperty`
> on the instance, or a getter that returns `false`, can be detected by inspecting
> the property descriptor (`Object.getOwnPropertyDescriptor(Navigator.prototype,
> 'webdriver')` vs. the instance). Record the descriptor shape, not just the value.

---

## 2.2 Headless indicators

| Signal | Check | Verdict |
|--------|-------|---------|
| Headless UA | `navigator.userAgent` contains `HeadlessChrome` | `automation` |
| No plugins | `navigator.plugins.length === 0` **and** `navigator.mimeTypes.length === 0` on a desktop Chrome UA | `suspicious` (real headless Chrome now populates some, so combine with others) |
| Empty languages | `navigator.languages` empty or missing | `suspicious` |
| **Permissions contradiction** | `navigator.permissions.query({name:'notifications'})` returns `denied` while `Notification.permission === 'default'` | `automation` (classic headless tell) |
| Missing `chrome.runtime` | UA claims Chrome but `window.chrome.runtime` absent | `suspicious` |
| `navigator.connection` shape | Missing on a UA that should have the Network Information API | `suspicious` |
| Media devices | `navigator.mediaDevices.enumerateDevices()` returns zero devices with blank labels on desktop | `suspicious` |

### The permissions contradiction (worth spelling out)

```js
export async function permissionsContradiction() {
  try {
    const status = await navigator.permissions.query({ name: 'notifications' });
    const perm = Notification.permission;      // 'default' | 'granted' | 'denied'
    // Genuine browsers: query state agrees with Notification.permission.
    // Headless Chrome historically reported permissions='denied' while
    // Notification.permission='default' — an impossible combination.
    const contradiction = (status.state === 'denied' && perm === 'default');
    return { permissionsState: status.state, notificationPermission: perm, contradiction };
  } catch (e) {
    return { permissionsState: null, notificationPermission: null, contradiction: false, note: String(e) };
  }
}
```

---

## 2.3 WebGL

```js
export function collectWebGL() {
  const canvas = document.createElement('canvas');
  const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
  if (!gl) return { supported: false, verdict: 'suspicious', note: 'WebGL unavailable' };

  const dbg = gl.getExtension('WEBGL_debug_renderer_info');
  const vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
  const renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);

  const software = /SwiftShader|llvmpipe|Mesa OffScreen|Software|Microsoft Basic Render|ANGLE \(Google, Vulkan[^)]*SwiftShader/i
    .test(renderer + ' ' + vendor);

  // Also hash a broad set of gl.getParameter(...) values for a stable webgl param fingerprint.
  const paramsHash = hashWebGLParams(gl);
  return { supported: true, unmaskedVendor: vendor, unmaskedRenderer: renderer, isSoftware: software, paramsHash };
}
```

| Signal | Verdict |
|--------|---------|
| Software renderer (`SwiftShader`, `llvmpipe`, `Mesa OffScreen`, `Microsoft Basic Render Driver`, `ANGLE (Google, Vulkan … SwiftShader)`) | `suspicious` on a desktop UA (common in headless/VM/CI) |
| WebGL entirely absent where the UA implies it should exist | `suspicious` |
| Renderer/OS contradiction (Apple GPU string on a Windows UA; NVIDIA/Direct3D on a macOS UA) | **cross-layer contradiction** — flagged strongly by the engine |
| `UNMASKED_*` returns empty strings while claiming a GPU | `suspicious` |

The **renderer-vs-claimed-OS** check is a coherence check and is evaluated by the
backend against `Sec-CH-UA-Platform` and the font-set OS — see
[docs/07](07-coherence-engine.md).

---

## 2.4 Canvas & Audio fingerprints

Both are **consistency** signals, not automation-in-themselves. The *value* is
neutral; what matters is: identical hashes across supposedly-different clients,
blocked/zeroed output, or output that contradicts the claimed platform.

### Canvas

```js
export function collectCanvas() {
  try {
    const c = document.createElement('canvas'); c.width = 280; c.height = 60;
    const ctx = c.getContext('2d');
    ctx.textBaseline = 'top'; ctx.font = "14px 'Arial'";
    ctx.fillStyle = '#f60'; ctx.fillRect(0,0,100,40);
    ctx.fillStyle = '#069'; ctx.fillText('Bot-Detector \u{1F916} 0123', 2, 15);
    ctx.strokeStyle = 'rgba(0,120,200,0.7)'; ctx.arc(50,30,20,0,Math.PI*2); ctx.stroke();
    const data = c.toDataURL();
    const blocked = data === 'data:,' || data.length < 100;   // some blockers return empty
    return { supported: true, hash: sha256(data), blocked, zeroed: isAllOnePixel(ctx) };
  } catch (e) { return { supported: false, note: String(e) }; }
}
```

| Signal | Verdict |
|--------|---------|
| `toDataURL` returns empty / `data:,` / throws | `suspicious` (canvas blocked — privacy tool or automation) |
| Output is a single flat color / all-transparent | `suspicious` (zeroed / spoofed) |
| Hash matches a known automation-default hash (headless Chrome on a stock VM has recurring canvas hashes) | `suspicious` (maintained in the reference DB) |

### Audio

```js
export async function collectAudio() {
  try {
    const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    const ctx = new Ctx(1, 44100, 44100);
    const osc = ctx.createOscillator(); osc.type = 'triangle'; osc.frequency.value = 10000;
    const comp = ctx.createDynamicsCompressor();
    osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
    const buf = await ctx.startRendering();
    const slice = buf.getChannelData(0).slice(4500, 5000);
    let sum = 0; for (const v of slice) sum += Math.abs(v);
    return { supported: true, sampleSum: sum, hash: sha256(slice.join(',')), blocked: sum === 0 };
  } catch (e) { return { supported: false, note: String(e) }; }
}
```

Same reasoning: zeroed output or a hash matching known automation defaults is
`suspicious`; otherwise the value is a neutral consistency anchor.

> **Weighting caution (from the original plan's gotchas).** Do not over-weight
> canvas/audio/WebGL *values*. A distinct fingerprint is normal and human; only
> *blocked*, *zeroed*, or *known-default* outputs, or values that *contradict*
> other layers, should move the score.

---

## 2.5 Hardware / screen plausibility

| Signal | Check | Verdict |
|--------|-------|---------|
| `hardwareConcurrency` | `0`, `1`, or absurd (>128) on a consumer UA | `suspicious` |
| `deviceMemory` | Absent on Chrome, or implausible (e.g. `0.25`) | `suspicious` |
| `outerWidth/Height === 0` | Classic headless tell (no window chrome) | `automation` |
| `screen.width < window.innerWidth` | Physically impossible on a real device | `automation` |
| `availWidth/Height > width/height` | Impossible | `suspicious` |
| `devicePixelRatio` vs. screen size | DPR inconsistent with a plausible physical display | `suspicious` |
| `colorDepth` / `pixelDepth` | Not 24 or 30 on modern hardware | `suspicious` |
| `maxTouchPoints` vs. UA | `>0` on a desktop UA with no touch, or `0` on a mobile UA | contributes to the mobile/desktop coherence check |

```js
export function collectHardwareScreen() {
  const s = screen;
  return {
    hardwareConcurrency: navigator.hardwareConcurrency ?? null,
    deviceMemory: navigator.deviceMemory ?? null,
    maxTouchPoints: navigator.maxTouchPoints ?? 0,
    width: s.width, height: s.height, availWidth: s.availWidth, availHeight: s.availHeight,
    innerWidth: window.innerWidth, innerHeight: window.innerHeight,
    outerWidth: window.outerWidth, outerHeight: window.outerHeight,
    devicePixelRatio: window.devicePixelRatio, colorDepth: s.colorDepth, pixelDepth: s.pixelDepth,
  };
}
```

The impossible-geometry checks (`outerWidth===0`, `screen.width < innerWidth`)
are among the most reliable single signals and are hard to fake without breaking
layout — weight them high.

---

## 2.6 Fonts

Two methods; prefer the Font Access API where available, fall back to measurement.

### Measurement method (universal)

Render a probe string in a base fallback font, then in `"<candidate>", <fallback>`.
If the measured width/height changes, the candidate font is installed.

```js
const BASELINES = ['monospace', 'sans-serif', 'serif'];
const PROBE = 'mmmmmmmmmmlli' + '\u{1F600}';
export function detectFonts(candidates) {
  const span = document.createElement('span');
  span.style.cssText = 'position:absolute;left:-9999px;font-size:72px';
  span.textContent = PROBE; document.body.appendChild(span);
  const base = {};
  for (const b of BASELINES) { span.style.fontFamily = b; base[b] = [span.offsetWidth, span.offsetHeight]; }
  const detected = [];
  for (const f of candidates) {
    let hit = false;
    for (const b of BASELINES) {
      span.style.fontFamily = `'${f}',${b}`;
      if (span.offsetWidth !== base[b][0] || span.offsetHeight !== base[b][1]) { hit = true; break; }
    }
    if (hit) detected.push(f);
  }
  span.remove();
  return detected;
}
```

The candidate list should mix **OS-signature fonts**:

- Windows: `Segoe UI`, `Calibri`, `Cambria`, `Consolas`, `Tahoma`, `MS Gothic`
- macOS: `San Francisco`/`.SF NS`, `Helvetica Neue`, `Menlo`, `Geneva`, `Apple Color Emoji`
- Linux: `DejaVu Sans`, `Liberation Sans`, `Ubuntu`, `Noto Sans`, `FreeSans`
- Android: `Roboto`, `Droid Sans`, `Noto Color Emoji`

| Signal | Verdict |
|--------|---------|
| Font set contains **no** signature fonts of the claimed OS | `suspicious` |
| Font set contains signature fonts of a **different** OS than claimed (Linux-only fonts on a Windows UA — typical of headless-on-CI) | **cross-layer contradiction** |
| Suspiciously tiny font count (headless minimal images ship very few fonts) | `suspicious` |

This OS inference feeds the coherence engine's OS-triangulation
(UA-platform ↔ WebGL-OS ↔ font-OS).

---

## 2.7 Timezone / locale coherence (client side)

Collect and send to the backend for cross-check against IP geolocation and the
`Accept-Language` header — the client alone can only flag *internal*
inconsistency; the cross-check with IP is a Layer-3 join.

```js
export function collectLocale() {
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  return {
    intlTimeZone: tz,
    timezoneOffsetMin: new Date().getTimezoneOffset(),
    language: navigator.language,
    languages: navigator.languages ? [...navigator.languages] : [],
    intlLocale: Intl.DateTimeFormat().resolvedOptions().locale,
    numberingSystem: Intl.NumberFormat().resolvedOptions().numberingSystem,
  };
}
```

| Client-only signal | Verdict |
|--------|---------|
| `Intl` timezone and `getTimezoneOffset()` disagree | `suspicious` |
| `navigator.language` not the first of `navigator.languages` | `suspicious` |
| `languages` empty | `suspicious` (headless tell, overlaps §2.2) |

Backend joins (see [docs/07](07-coherence-engine.md)):
- `Intl` timezone vs. IP-geolocated timezone.
- `navigator.languages` vs. `Accept-Language` header (should be consistent).
- `UTC` timezone + datacenter IP + `en-US` is a well-known automation cluster.

---

## 2.8 Form-behavior signals (phase 2)

This is the app's deliberate interaction surface: **the homepage is an
instrumented form**, and phase 2 measures *how the visitor fills it in*. It is the
richest human-vs-scripted signal class the tool has, and it is only observable
after interaction — hence the second phase (see
[docs/01 §4](01-architecture-and-hosting.md#4-the-detection-flow-a-3-step-funnel)).

The form should be plausible and self-justifying (e.g. a short "request a demo" /
"contact us" form: name, email, a select, a message box, a submit button) so a
human has a natural reason to fill it and a script has to engage with real fields.

### What to capture (dynamics only — never field contents)

| Channel | Metrics | Automation tell |
|---------|---------|-----------------|
| Per-field typing | keydown count, inter-keystroke mean/stdev, backspaces/corrections, paste events, `filledWithoutKeys` (value appeared with no keystrokes) | Zero-variance cadence; value set with no keystrokes; paste-only fills; no corrections at all across a long form |
| Focus / tab order | the order fields were focused, whether Tab was used, per-field dwell time | Focus order that never matches the visual order; instantaneous field-to-field jumps; programmatic `.focus()` with 0ms dwell |
| Mouse-to-field | whether each field was entered by a real mouse move vs. programmatic focus; path linearity into the field; clicks at exact element-center | Fields focused with no pointer movement; dead-straight paths; clicks at the exact geometric center |
| Submit timing | fill→submit latency; latency after the last field; total interaction duration | Sub-100ms fill→submit; submit fired the same tick as the last keystroke |
| Global | time-to-first-interaction; scroll presence; blur/focus of the window | TTFI ≈ 0; no scroll on an overflowing page; form completed before the page could plausibly be read |

### Sketch

```js
// Attach on load; flush on submit (or after an interaction threshold).
export function instrumentForm(formEl) {
  const t0 = performance.now();
  const fields = new Map();          // name -> per-field accumulator
  const mouse = [];
  let firstInteraction = null, tabUsed = false, focusOrder = [];
  const mark = () => { if (firstInteraction === null) firstInteraction = performance.now() - t0; };
  const acc = name => fields.get(name) ?? (fields.set(name, {
    name, keydowns: 0, interKeys: [], backspaces: 0, pasteEvents: 0,
    filledWithoutKeys: false, focusAt: null, dwellMs: 0, enteredByMouse: false, lastKeyAt: null,
  }), fields.get(name));

  for (const el of formEl.querySelectorAll('input,textarea,select')) {
    const f = acc(el.name || el.id);
    el.addEventListener('focus', () => { mark(); f.focusAt = performance.now();
      if (!focusOrder.includes(f.name)) focusOrder.push(f.name);
      // entered-by-mouse if a mousemove landed on this field just before focus
      f.enteredByMouse = recentMouseOver(el, mouse);
    });
    el.addEventListener('blur', () => { if (f.focusAt) f.dwellMs += performance.now() - f.focusAt; });
    el.addEventListener('keydown', e => { mark(); f.keydowns++;
      const now = performance.now(); if (f.lastKeyAt) f.interKeys.push(now - f.lastKeyAt); f.lastKeyAt = now;
      if (e.key === 'Tab') tabUsed = true; if (e.key === 'Backspace') f.backspaces++;
    });
    el.addEventListener('paste', () => { mark(); f.pasteEvents++; });
    // detect value set with no keystrokes (scripted .value = "…")
    el.addEventListener('input', () => { if (f.keydowns === 0 && el.value.length > 0 && f.pasteEvents === 0) f.filledWithoutKeys = true; });
  }
  addEventListener('mousemove', e => { mark(); mouse.push([e.clientX, e.clientY, performance.now() - t0]); }, { passive: true });

  return () => summarizeForm(formEl, fields, mouse, focusOrder, tabUsed, firstInteraction, t0); // call on submit
}
```

`summarizeForm()` computes the phase-2 payload in
[docs/03 §4](03-api-contract.md#4-post-apianalyze--phase-2-form-behavior-after-interaction):
per-field cadence mean/stdev, `straightSegmentsRatio` of the mouse path (fraction
of near-collinear point triples — human paths jitter, scripted `mouse.move(x,y)`
is dead straight), focus/tab order vs. visual order, and the submit-timing
figures. **Only counts, timings, and variances leave the browser — never the text
the user typed.**

### Weighting caution

Behavior is **noisy and legitimately absent sometimes** (fast typists, keyboard-
only users, password managers that autofill). So:

- The whole behavior group is **bounded** — it can *reinforce* an automated
  verdict but must not *create* one alone (see the cap in
  [docs/07 §2.6](07-coherence-engine.md#26-form-behavior-layer-1-phase-2-bounded)).
- **Autofill is not automation.** A password manager or browser autofill produces
  `filledWithoutKeys` / paste-like patterns; treat a single such field as neutral,
  and only weight the pattern when it spans the *whole* form with zero mouse and
  zero corrections.
- "No interaction at all" is `inconclusive`, not a fail — the phase-1 report
  already stands; phase 2 simply doesn't get to add behavioral confidence.
- The strongest tells (all fields filled sub-100ms, zero-variance cadence,
  programmatic focus with no pointer movement, submit on the same tick as the last
  key) are weighted higher because they're hard to produce accidentally.

### 2.9 Agent-specific collectors (CDP leaks, input provenance, cadence, biometrics)

The form-behavior collector above generalizes into four additional client-side
collectors aimed at **real-browser AI agents** (Comet, Atlas, Claude computer-use,
Operator, CDP stealth) that pass every passive check. These are specified in full
in **[docs/14](14-agentic-and-cdp-detection.md)** and also ship in
`@botdetect/client`:

- **`cdpLeaks`** — the `Runtime.enable` console-getter probe and the rest of the
  CDP/automation-driver leak set ([docs/14 §3](14-agentic-and-cdp-detection.md#3-signal-class-a--cdp--automation-driver-leaks)).
- **`inputProvenance`** — teleporting/trail-less clicks, `getCoalescedEvents()`,
  exact-integer-center landing, `movementX/Y` consistency — the class that catches
  OS-level screenshot agents that `navigator.webdriver` and `isTrusted` both miss
  ([docs/14 §4](14-agentic-and-cdp-detection.md#4-signal-class-b--input-provenance-catches-os-level-agents-)).
- **`cadence`** — the perceive→think→act timing signature
  ([docs/14 §5](14-agentic-and-cdp-detection.md#5-signal-class-c--screenshot-agent-cadence-perceive--think--act)).
- **`biometrics`** — mouse Fitts/curvature/tremor, typing-latency distribution,
  non-continuous scroll ([docs/14 §6](14-agentic-and-cdp-detection.md#6-signal-class-d--behavioral-biometrics-the-fp-agent-core)).

---

## 3. Collector orchestration (two phases)

```js
// app.js
async function main() {
  const { sessionId } = JSON.parse(document.getElementById('bootstrap').textContent);

  // ---- PHASE 1: passive, on load ----
  const layer1 = {
    automationFlags: collectAutomationFlags(),
    headless: await collectHeadless(),
    webgl: collectWebGL(),
    canvas: collectCanvas(),
    audio: await collectAudio(),
    hardware: collectHardwareScreen(),
    fonts: { method: 'measurement', detected: detectFonts(FONT_CANDIDATES) },
    locale: collectLocale(),
    environment: collectEnvironment(),
  };
  const report1 = await postJSON('/api/analyze', { reportVersion:'1', sessionId, phase:1, layer1 });
  render(report1);                       // green/red banner + checklist appear immediately

  // ---- PHASE 2: form behavior, after interaction ----
  const flush = instrumentForm(document.getElementById('probe-form'));
  document.getElementById('probe-form').addEventListener('submit', async (e) => {
    e.preventDefault();                  // we don't actually submit user data anywhere
    const behavior = flush();
    const report2 = await postJSON('/api/analyze', { reportVersion:'1', sessionId, phase:2, behavior });
    render(report2);                     // banner + checklist update in place, highlighting phaseDelta
  });
}
```

Phase 1 renders the verdict before the user touches anything (the strongest tells
need no interaction). Phase 2 fires on form submit, refining the probability and
raising confidence. The server captured Layer 2/3 at the `GET /` navigation, so
both phases just join to the stored session.

---

## 4. Anti-tamper notes (measuring the measurers)

A sophisticated stealth stack patches these APIs. We can sometimes detect the
*patch itself*:

- **`toString` leaks:** a native function's `Function.prototype.toString` returns
  `"function webdriver() { [native code] }"`. A patched getter often returns JS
  source. Check `Object.getOwnPropertyDescriptor(...).get.toString()` for
  `[native code]`.
- **Property descriptor anomalies:** genuine `navigator` props are on the
  prototype with specific `enumerable/configurable` flags; instance-level
  overrides (how many stealth scripts patch) differ.
- **Error stack traces:** calling certain APIs from a Proxy-wrapped object leaves
  distinctive frames.
- **Iframe re-read:** read `navigator.webdriver` (etc.) from a fresh same-origin
  iframe's `contentWindow`; some patches apply only to the top window.

These are recorded as `automation` signals when the patch is detected, and feed
the "the client is actively trying to hide" narrative in the report. Keep them in
a dedicated `antiTamper` sub-module so they're clearly separated from the naive
flag checks.
