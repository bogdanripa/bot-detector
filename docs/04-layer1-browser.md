# 04 — Layer 1: Browser Environment (Frontend JS)

Everything in this layer is collected by JavaScript in the visitor's browser and
POSTed to `/api/analyze`. It is the richest layer and the only one that works
identically across all three deployment topologies.

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

## 2.8 Behavioral signals (sampled over ~3s)

Provide a small interactive test area (a button and a text input) so there's
something to measure. Buffer events for ~3 seconds, then submit alongside the
rest of Layer 1.

### What to capture

| Channel | Metrics | Automation tell |
|---------|---------|-----------------|
| Mouse | move count, path points, **linearity** (fraction of near-perfectly-straight segments), speed mean/variance, whether clicks land at exact element-center pixels | Perfectly straight teleport-like paths; zero curvature; clicks at exact geometric center; no movement at all |
| Keyboard | keydown count, inter-keystroke interval mean/stdev, paste events, whether values appear without keystrokes | Zero variance timing; value set with no keystrokes; paste-only fills |
| Scroll | event count, distance, wheel vs. programmatic | Instant jumps; no scroll at all on a scrollable page |
| Focus | focus/blur events fired | Never firing on a form-bearing page |
| Timing | time-to-first-interaction; form-fill-to-submit duration | Sub-100ms fill→submit = scripted; TTFI of 0 |

### Sketch

```js
export function startBehaviorCollector(durationMs = 3000) {
  const mouse = [], keys = [];
  let clicks = 0, clicksAtCenter = 0, scrollEvents = 0, scrollDist = 0, firstInteraction = null;
  const t0 = performance.now();
  const mark = () => { if (firstInteraction === null) firstInteraction = performance.now() - t0; };

  const onMove = e => { mark(); mouse.push([e.clientX, e.clientY, performance.now() - t0]); };
  const onClick = e => {
    mark(); clicks++;
    const r = e.target.getBoundingClientRect?.();
    if (r && Math.abs(e.clientX - (r.left + r.width/2)) < 1 && Math.abs(e.clientY - (r.top + r.height/2)) < 1)
      clicksAtCenter++;
  };
  const onKey = e => { mark(); keys.push(performance.now() - t0); };
  const onPaste = () => { mark(); keys.paste = (keys.paste||0)+1; };
  const onScroll = () => { mark(); scrollEvents++; };

  addEventListener('mousemove', onMove, { passive: true });
  addEventListener('click', onClick, true);
  addEventListener('keydown', onKey, true);
  addEventListener('paste', onPaste, true);
  addEventListener('scroll', onScroll, { passive: true });

  return new Promise(resolve => setTimeout(() => {
    removeEventListener('mousemove', onMove); /* …remove the rest… */
    resolve(summarize(mouse, keys, clicks, clicksAtCenter, scrollEvents, scrollDist, firstInteraction, durationMs));
  }, durationMs));
}
```

`summarize()` computes:

- **Linearity:** for consecutive triples of mouse points, the fraction whose
  cross-product (deviation from a straight line) is below a small epsilon.
  Human paths are jittery; scripted `mouse.move(x,y)` is dead straight.
- **Inter-key stdev:** humans have high variance; scripted typing with a fixed
  delay has near-zero variance.
- **Interacted flag:** whether any of mouse/key/scroll fired at all.

### Weighting caution

Behavior is **noisy and easily absent for legitimate reasons** (a user who reads
without moving the mouse, a keyboard-only user, someone who submits fast). So:

- Behavioral signals are **bounded** — the entire behavior group can contribute
  at most a moderate penalty; it can *reinforce* an automation verdict but must
  not *create* one on its own.
- "No interaction at all within 3s" is treated as `inconclusive`, not
  `automation` — many humans just look at the page.
- The strongest behavioral tell (perfectly linear mouse paths + zero-variance
  keystrokes) is weighted higher because it's hard to produce accidentally.

---

## 3. Collector orchestration

```js
// app.js — runs on load
async function run() {
  const behaviorP = startBehaviorCollector(3000);          // start the 3s sampler immediately
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
  if (CAPTURE_MODE === 'b') fireEdgeProbe(NONCE);           // parallel cross-origin fetch
  layer1.behavior = await behaviorP;                        // resolves at ~3s
  const report = await postJSON('/api/analyze', { reportVersion:'1', nonce: NONCE, layer1 });
  render(report);
}
```

All non-behavioral collectors run synchronously/immediately; the behavioral
collector runs concurrently for 3s; the edge-probe fetch (Topology B) fires in
parallel so its transport report is ready by the time `/api/analyze` is called.

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
