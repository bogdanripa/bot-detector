# 14 — Detecting Agentic Browsers & CDP-Driven Automation

The hardest client class in 2026 is **an AI agent driving a real browser on the
user's own device**: Perplexity Comet, ChatGPT Atlas, OpenAI Operator, Claude's
computer-use, `browser-use`, and CDP-driven Playwright/Puppeteer stealth stacks.
These run **real Chromium on a real OS from a residential IP**, so Layers 2–3
(TLS/JA4, HTTP/2, header order, IP/ASN) and most of passive Layer 1 come back
**clean**. Our existing plan would score many of them as `human`.

This document adds the signal classes that *do* catch them. It draws on recent
research and industry practice (sources at the end); the two most directly
relevant academic results:

- **FP-Agent** (arXiv 2605.01247) — a controlled study of 7 AI browsing agents vs.
  humans. Finding: **browser fingerprints have limited discriminative power for
  agents; behavioral fingerprints (typing, scrolling, mouse) are what separate
  agents from humans and from each other.** In a head-to-head, FP-Agent detected
  **all 7 agents; Cloudflare detected 1.** This is the thesis of this whole
  document: for on-device agents, **behavior and input provenance beat
  fingerprinting.**
- **"Whose Agent Are You?"** (arXiv 2606.20910) — multi-layer fingerprinting and
  *attribution* of autonomous web agents (telling *which* agent, not just that
  it's an agent).

> **Scope note.** This stays diagnostic. We report to the visitor what a detector
> would conclude and why. Nothing here is an evasion recipe; where an evasion
> exists (e.g. rebrowser-patches, ghost-cursor) we name it only to be honest about
> the arms race and to weight signals accordingly.

---

## 1. Why the existing layers miss on-device agents

| Client | Layer 3 TLS/JA4 | Layer 2 headers | Passive Layer 1 | What still catches it |
|--------|:---------------:|:---------------:|:---------------:|-----------------------|
| curl / requests / Go | ❌ library | ❌ wrong | n/a (no JS) | already caught (docs 05–07) |
| Puppeteer/Playwright **headless** | ✅ real Chrome | ✅ | ❌ `webdriver`/headless tells | already caught (docs 04, 07) |
| Playwright/Puppeteer **headed, CDP-driven, stealthed** | ✅ | ✅ | ⚠️ patched | **CDP leaks + input + behavior** (§3–§6) |
| `browser-use` (CDP) | ✅ | ✅ | ⚠️ | **CDP leaks + input + behavior** |
| **Perplexity Comet** (renderer extension) | ✅ | ✅ | ✅ mostly clean | **DOM/extension artifacts + behavior + cadence** (§7) |
| **ChatGPT Atlas** (external agent via OWL) | ✅ | ⚠️ UA/CFNetwork tells | ✅ mostly clean | **UA/header tells + behavior + cadence** (§7) |
| **Claude computer-use / Operator** (screenshot + OS input) | ✅ | ✅ | ✅ clean | **input provenance + screenshot cadence + behavior** (§4–§6) |

The row that matters most is the last: a screenshot-driven agent controlling a
real browser through **OS-level input** (xdotool on Linux, Accessibility APIs on
macOS) presents an essentially perfect environment fingerprint. **CDP detection
does not see it** (there's no CDP client), and `isTrusted` is `true` (the OS
events are genuine). It is caught only by *how the pointer and keyboard move* and
*the rhythm of its actions*.

---

## 2. A new output dimension: `automationType`

Because these clients differ in *kind*, not just degree, the report gains an
`automationType` alongside the probability — it changes what the number *means*
and what a site would do about it:

```
automationType ∈
  none            // ordinary human
  scripted        // curl/requests/HTTP library (no browser)
  headless        // headless browser automation
  agentic-cdp     // real browser driven via Chrome DevTools Protocol (Playwright/Puppeteer/browser-use)
  agentic-os      // real browser driven via OS-level input + screenshots (computer-use/Operator)
  agentic-ext     // agent embedded as a browser extension/renderer component (Comet)
  agentic-declared// self-identified via Web Bot Auth signature (§8)
```

The engine infers it from which signal classes fired (§9). It's a best-effort
label, and `unknown-agentic` is valid when behavior says "agent" but the specific
mechanism isn't pinned.

---

## 3. Signal class A — CDP / automation-driver leaks

Catches anything driven through the **Chrome DevTools Protocol**: Playwright,
Puppeteer, Selenium 4, `browser-use`, and many stealth stacks. These are
**client-side JS** checks (a new group in `@botdetect/client`). The canonical,
well-maintained reference set is `rebrowser/rebrowser-bot-detector`; we mirror its
tests:

| Check | Mechanism | Catches |
|-------|-----------|---------|
| **`runtimeEnableLeak`** ⭐ | Create an object whose `id` is a **getter**, `console.log` it, and see if the getter fires. Chrome buffers console messages unless a CDP client sent `Runtime.enable`; when it did, the object is serialized for the controller and **the getter fires**. On a normal browser nothing reads the property. | Any CDP client with the Runtime domain enabled (default for Puppeteer/Playwright/Selenium) |
| **`sourceUrlLeak`** | Throw and inspect the stack trace for injection source-URLs the automation tool adds to evaluated scripts. | Injected-script evaluation |
| **`mainWorldExecution`** | Watch for automation touching main-world functions (`document.querySelector` et al.) that a page never called itself. | Main-world script injection |
| **`__pwInitScripts`** | Playwright injects a `__pwInitScripts` global by default. | Playwright |
| **`exposeFunctionLeak`** | `page.exposeFunction()` leaves detectable binding artifacts. | Puppeteer/Playwright exposeFunction |
| **`bypassCsp`** | `page.setBypassCSP(true)` is observable and impossible in a real browser. | CSP-bypassing automation |
| **`navigatorWebdriver`** | `navigator.webdriver === true`. | WebDriver-controlled (already in docs/04) |
| **`useragent` / `viewport`** | "Chrome for Testing" UA; default viewports (Puppeteer 800×600, Playwright 1280×720). | Out-of-the-box automation |

### The `runtimeEnableLeak` probe (sketch)

```js
// Fires only when a CDP client has sent Runtime.enable (Puppeteer/Playwright/Selenium default).
export function runtimeEnableLeak() {
  let leaked = false;
  const bait = { id: 0 };
  Object.defineProperty(bait, 'id', { get() { leaked = true; return 1; } });
  console.debug(bait);            // serialized for the CDP controller iff Runtime.enable is active
  return leaked;                  // true ⇒ agentic-cdp
}
```

### Honesty about the arms race

`Runtime.enable` detection is **necessary but not sufficient**. `rebrowser-patches`
(and forks like Patchright, Kameleo) create CDP execution contexts *without*
`Runtime.enable`, defeating this specific probe. So:

- We weight `runtimeEnableLeak` **high** (it's decisive when present) but **treat
  its absence as no evidence**, not as "human."
- The `sourceUrlLeak`, `mainWorldExecution`, and `exposeFunctionLeak` checks catch
  some patched stacks that fixed only `Runtime.enable`.
- Crucially, **CDP-patched agents still lose on input provenance and behavior**
  (§4–§6), which they cannot patch as cheaply. That's why we don't rely on CDP
  detection alone.

---

## 4. Signal class B — input provenance (catches OS-level agents) ⭐

This is the class that catches **computer-use / Operator** agents that CDP
detection and `isTrusted` both miss. It asks: *did this click/keystroke come from
a human hand on real hardware, or was it injected?*

| Signal | Human | Agent (OS-injected or CDP `Input.dispatch*`) |
|--------|-------|----------------------------------------------|
| **`event.isTrusted`** | `true` | `true` for OS-level and CDP input (**not** a discriminator for real agents); `false` only for naïve JS-dispatched events. Keep it as a cheap filter, don't rely on it. |
| **Pointer trail before a click** ⭐ | Dense stream of `pointermove`/`mousemove` events approaching the target | A click with **no or negligible preceding movement** — OS coordinate-clicks and `page.click()` **teleport** the cursor to the target. |
| **`mousemove` event count** | Hundreds over a short session | Impossibly low (often ~0 between actions). |
| **`getCoalescedEvents()`** on `pointermove` | Multiple coalesced hardware samples per frame (125–1000 Hz mouse) | Empty / single — injected input has no hardware coalescing. |
| **Click landing position** | Sub-pixel, **off-center**, scattered within the element | Exact **integer** pixel, frequently the **geometric center** of the target's bounding box (the agent computed it from a screenshot). |
| **`movementX/Y` vs `clientX/Y` deltas** | Consistent, hardware-derived | Often `0` or inconsistent for injected events. |
| **Pointer pressure / tilt / `pointerType`** | Present on touch/pen; plausible on mouse | Frequently absent/default. |
| **Cursor path acceleration** | Ballistic: accelerate → peak → decelerate (Fitts's law), with micro-tremor | Near-zero acceleration, constant velocity, or a too-smooth Bézier (ghost-cursor style). |

### The strongest single tell: **a click with no approach trail**

```js
// Track recent pointer movement; flag clicks whose target was never approached.
let trail = [];
addEventListener('pointermove', e => {
  trail.push({ x: e.clientX, y: e.clientY, t: e.timeStamp,
               coalesced: e.getCoalescedEvents?.().length ?? 0 });
  if (trail.length > 200) trail.shift();
}, { passive: true, capture: true });

addEventListener('pointerdown', e => {
  const near = trail.filter(p => Math.hypot(p.x - e.clientX, p.y - e.clientY) < 80
                                 && e.timeStamp - p.t < 500);
  const r = e.target.getBoundingClientRect();
  const atExactCenter = Number.isInteger(e.clientX) && Number.isInteger(e.clientY)
    && Math.abs(e.clientX - (r.left + r.width/2)) < 1
    && Math.abs(e.clientY - (r.top + r.height/2)) < 1;
  record({
    approachPoints: near.length,             // ~0 ⇒ teleport ⇒ injected
    coalescedNearby: near.reduce((s,p)=>s+p.coalesced,0),  // 0 ⇒ no hardware sampling
    atExactIntegerCenter: atExactCenter,      // agent computed a bbox center
  });
}, { capture: true });
```

A click that is (approach-trail ≈ 0) **and** (coalesced ≈ 0) **and** (exact
integer center) is an extremely strong `agentic-os` / `agentic-cdp` signal, and it
holds even against a perfectly clean fingerprint.

---

## 5. Signal class C — screenshot-agent cadence (perceive → think → act)

Screenshot-driven agents (computer-use, Operator, and the "reason then act" loop
in general) act in **discrete steps** gated by an LLM round-trip. Their *timing
signature* is distinctive and hard to disguise because it's inherent to the
architecture.

| Signal | Human | Screenshot/agent loop |
|--------|-------|-----------------------|
| **Inter-action gaps** | Continuous micro-activity; sub-second reactions | **Multi-second** pauses (screenshot → API → decision), then a precise action, then another long pause — **bursty and slow**. |
| **Idle micro-motion** | Constant tiny mouse jitter, accidental movement, reading-scroll | **Still** between actions — no idle jitter. |
| **Action efficiency** | Hesitation, backtracking, mis-clicks, re-reads | **Clean**: straight to the right element, correct field order, no corrections, no exploration. |
| **Dwell time per page** | Variable, correlated with content length | **Near-zero dwell, no scroll depth**, rapid multi-page navigation (industry-observed). |
| **Scroll shape** (FP-Agent) | Smooth, continuous, overshoot-and-settle | **Non-continuous**: position jumps in discrete increments. |
| **Reaction to unexpected DOM** | Natural pause/confusion | Either instant correct handling or a long think-pause. |

These are **phase-2 (behavioral)** signals in our model, but for agents they carry
much more weight than for scripted bots — because for an on-device agent, cadence
is one of the *few* things that leaks.

---

## 6. Signal class D — behavioral biometrics (the FP-Agent core)

Per FP-Agent, these are the most discriminative features for agents. They
generalize the form-behavior collector in [docs/04 §2.8](04-layer1-browser.md#28-form-behavior-signals-phase-2)
into a richer biometric set.

**Mouse dynamics**
- **Curvature & straightness:** humans curve, overshoot, and correct (ballistic);
  bots draw straight lines or too-smooth curves. Acceleration ≈ 0 almost always ⇒
  synthetic.
- **Velocity profile:** human motion follows Fitts's law (accelerate→peak→
  decelerate); constant velocity or artificial easing ⇒ synthetic.
- **Micro-tremor:** genuine motion has high-frequency muscle jitter; synthetic
  paths lack it.
- **Path entropy:** low entropy / high regularity ⇒ synthetic.

**Typing dynamics** (FP-Agent: *the most informative behavioral features*)
- **Inter-key latency distribution** (human ≈ log-normal, digraph-dependent; agent
  ≈ uniform, too regular, or zero when values are set programmatically).
- **Hold latency** (key down→up dwell) — present and variable for humans.
- **Backspace/delete usage & corrections** — humans make and fix mistakes; agents
  rarely do.
- **DOM `input`/`change` event counts vs. keystrokes** — a value that appears with
  few/no `keydown`s (set via `.value` or `insertText`) is a strong tell.

**Scroll dynamics**
- Continuous wheel/trackpad deltas with overshoot (human) vs. discrete jumps or
  programmatic `scrollTo` (agent).

All of these live in the client behavior collector and feed the engine's bounded
behavior group — but with an **agent-aware sub-weighting** (§9): for a client with
an otherwise clean fingerprint, these behavioral tells are *promoted*, because
they're the primary evidence available.

---

## 7. Signal class E — agent architecture artifacts (product-specific)

Different agent products leave different traces. These are lower-recall (they
change per release) but high-precision when present, and enable *attribution*
(which agent), echoing "Whose Agent Are You?".

| Product | Client-side artifacts | Server-side artifacts |
|---------|----------------------|-----------------------|
| **Perplexity Comet** | Agent runs as a **renderer-process extension** that is *not* in the public extensions UI but is **visible in the DOM/devtools when active**; it leaves **DOM-level artifacts during agentic actions** (injected nodes, content-script isolated-world traces, MutationObserver-detectable UI). | `PerplexityBot` UA on its crawler paths; Chromium manifest gaps. |
| **ChatGPT Atlas** | Agent is **out-of-process via OWL (OpenAI Web Layer)** — *fewer* in-page artifacts by design; the control channel is external. | UA containing `Atlas`; on macOS, **`CFNetwork`/`Darwin`** agent signatures; **TTS voice-list absence** and other Chromium-build gaps. |
| **Operator / declared agents** | May be a hosted browser (cloud), so on-device artifacts vary. | **Web Bot Auth signature headers** (§8) — the cleanest positive ID. |
| **Generic CDP agents** (`browser-use` etc.) | CDP leaks (§3), `navigator.webdriver`, injected helpers. | Chrome-for-Testing UA. |

Practical checks: enumerate injected DOM under known agent markers, watch for
content-script isolated-world side effects, check `navigator.userAgent` /
`userAgentData` for `Atlas`/`Comet`/`PerplexityBot`, and (server-side) inspect for
`CFNetwork`/`Darwin` UA shapes on "Chrome" traffic. Keep these in a **versioned,
per-product table** ([docs/09](09-reference-data.md)) since they drift fast, and
degrade to `unknown-agentic` rather than a wrong attribution.

---

## 8. Signal class F — positive agent identification (Web Bot Auth)

The cooperative flip side: some agents **want to be identified**. **Web Bot Auth**
(Cloudflare-led IETF proposal, built on **RFC 9421 HTTP Message Signatures**,
backed by OpenAI, Amazon, Akamai) lets an agent cryptographically sign its
requests. A signed request carries:

- **`Signature`** — an Ed25519 signature over selected request components;
- **`Signature-Input`** — validity window, key id (JWK thumbprint), purpose tag;
- **`Signature-Agent`** — a URL to the agent's public-key directory (e.g.
  `operator.openai.com`).

This is a **server-side Layer-2 check** in `go/httpcapture`:

- **Present + valid signature ⇒ `automationType: agentic-declared`** with high
  confidence and (optionally) an allow-list decision — this is a *feature*, not a
  failure, for legitimate agents.
- **Absent ⇒ no evidence either way** — an uncooperative agent simply won't sign;
  absence is not a human signal.
- Verify the signature against the published directory; a *malformed or unverified*
  signature is itself suspicious (spoof attempt).

Supporting Web Bot Auth also future-proofs the tool: the ecosystem is moving from
"detect adversarially" toward "verify cryptographically" for the agents that
choose to declare themselves.

---

## 9. Scoring: the agentic case

The scoring engine ([docs/07](07-coherence-engine.md)) extends with new groups and
one pivotal new idea.

### 9.1 New signal groups & weights (log-odds contributions)

| Group | Example signals | Weight |
|-------|-----------------|:------:|
| CDP leaks (§3) | `runtimeEnableLeak` | +4.5 (decisive when present) |
| | `sourceUrlLeak`, `mainWorldExecution`, `__pwInitScripts`, `exposeFunctionLeak` | +2.5–3.5 |
| Input provenance (§4) | click with no approach trail + no coalesced events + exact-integer center | +3.5 (combined) |
| | impossibly low `mousemove` count in an interactive session | +2.0 |
| Screenshot cadence (§5) | multi-second bursty action gaps + zero idle motion + non-continuous scroll | +2.5 (combined, phase 2) |
| Behavioral biometrics (§6) | near-zero mouse acceleration; uniform inter-key latency; value set with no keystrokes | promoted for clean-fingerprint clients (§9.2) |
| Agent artifacts (§7) | Comet DOM extension trace; `Atlas`/`CFNetwork` UA | +3.0, plus sets `automationType` |
| Declared agent (§8) | valid Web Bot Auth signature | sets `agentic-declared`; routes to allow/verify, not penalty |

### 9.2 The pivotal contradiction: **clean fingerprint + agent behavior**

For scripted bots, contradictions are *cross-layer* (TLS≠UA). For on-device
agents, the decisive contradiction is **intra-behavioral vs. environmental**:

> **`clean_env_agentic_behavior`** — the environment fingerprint is a pristine
> real browser (real TLS/JA4, real OS, no headless tells, residential IP), **yet**
> the input provenance and/or cadence say "not a human hand." A real human on a
> real browser produces human input; a pristine environment with teleporting,
> trail-less, exact-center clicks and multi-second bursty cadence is an **agent
> driving that real browser.** Weight **+3.5**, and it flips `automationType` to
> `agentic-os`/`agentic-cdp`.

This is why the tool must **promote behavioral/input evidence when environmental
evidence is clean**: a datacenter IP would have carried the scripted case, but the
agent has none, so the behavioral channel is where the truth is. The engine
detects "all environment signals clean AND ≥1 strong input/cadence tell" and
raises the behavioral group's cap for that client (the normal bounded-behavior
gate in [docs/07 §2.6](07-coherence-engine.md#26-form-behavior-layer-1-phase-2-bounded)
is relaxed *only* in the presence of a hard input-provenance tell, never on
timing noise alone).

### 9.3 Confidence & honesty

- A `runtimeEnableLeak` or a trail-less exact-center click gives **high
  confidence** even on a clean environment.
- A verdict resting only on soft cadence (a bit slow, a bit efficient) is **low
  confidence** and labeled as such — a careful human can look agent-like, and a
  cloud-hosted agent can be fast. We report the probability *and* how soft the
  evidence is.
- **The honest ceiling holds:** a sufficiently advanced agent that reproduces
  human input dynamics (ghost-cursor + human-like typing models + human pacing) on
  a clean environment approaches indistinguishability. We say so, and lean on the
  *combination* — reproducing CDP-silence *and* hardware-coalesced pointer streams
  *and* Fitts's-law ballistics *and* human typing distributions *and* human cadence
  *simultaneously* is expensive, which is exactly the "must fix all layers at once"
  thesis, moved into the behavioral domain.

---

## 10. Where this lives (libraries)

Per the two-part split ([docs/13](13-libraries-and-packaging.md)):

- **`@botdetect/client`** gains: a `cdpLeaks` collector (§3), an `inputProvenance`
  collector (§4), a `cadence` collector (§5), and an expanded `biometrics`
  collector (§6). All are passive/behavioral, browser-side, zero-dependency.
- **`go/httpcapture`** gains: Web Bot Auth signature parsing/verification (§8) and
  the server-side UA/`CFNetwork` product tells (§7).
- **`go/engine` / `@botdetect/engine`** gain: the new groups, the
  `clean_env_agentic_behavior` contradiction, and `automationType` inference — all
  in `config/scoring.json`.
- **Reference tables** ([docs/09](09-reference-data.md)) gain a per-product
  agent-artifact table and the CDP-leak signatures.

---

## 11. Testing additions (agent matrix)

Add these rows to the validation matrix ([docs/11 §1](11-testing.md#1-the-validation-matrix)):

| Client | Expected | Primary signals |
|--------|----------|-----------------|
| Playwright/Puppeteer **headed, CDP, no stealth** | `automated` / `agentic-cdp` | `runtimeEnableLeak`, input teleport |
| CDP stealth (`rebrowser`/Patchright) | `suspicious`–`automated` / `agentic-cdp` | input provenance + behavior (CDP leak patched) |
| `browser-use` | `automated` / `agentic-cdp` | CDP leaks + behavior |
| **Perplexity Comet** (agent mode) | `suspicious`–`automated` / `agentic-ext` | DOM extension artifact + cadence + behavior |
| **ChatGPT Atlas** (agent mode) | `suspicious`–`automated` / `agentic-os`/`ext` | UA/CFNetwork tells + cadence + behavior |
| **Claude computer-use / Operator** | `suspicious`–`automated` / `agentic-os` | **input provenance (teleport, no coalesced, exact center) + screenshot cadence** |
| Operator with **Web Bot Auth** | `agentic-declared` (allow/verify) | valid RFC 9421 signature |
| **Human using Comet/Atlas normally (reading, not agent mode)** | `human` | must **not** be penalized for merely using an AI browser — only *agent-driven* interaction fires |

The last row is the important false-positive guard: **using an AI browser is not
automation.** Only the *agent driving it* should score as agentic; a human reading
in Comet is a human.

---

## 12. Summary of the new playbook

1. On-device agents defeat Layers 2–3 and passive Layer 1 — so **catch them on
   input provenance, cadence, behavioral biometrics, CDP leaks, and product
   artifacts.**
2. **The decisive move is the intra-client contradiction**: a *pristine
   environment* combined with *non-human input/cadence* = an agent driving a real
   browser. Promote behavioral evidence exactly when environmental evidence is
   clean.
3. **CDP detection (`Runtime.enable` et al.)** catches CDP-driven agents but is
   patchable — necessary, not sufficient.
4. **Input provenance** (teleporting, trail-less, exact-center, non-coalesced
   clicks) catches OS-level screenshot agents that CDP detection and `isTrusted`
   both miss.
5. **Web Bot Auth** turns cooperative agents into a positive, high-precision ID.
6. Emit **`automationType`** so the report distinguishes scripted vs. headless vs.
   agentic-cdp vs. agentic-os vs. agentic-ext vs. declared.
7. Stay honest about the arms race and the false-positive guard (using an AI
   browser ≠ being an agent).

---

## Sources

- FP-Agent: Fingerprinting AI Browsing Agents — arXiv 2605.01247 — https://arxiv.org/abs/2605.01247
- Whose Agent Are You? Multi-Layer Fingerprinting and Attribution of Autonomous Web Agents — arXiv 2606.20910 — https://arxiv.org/html/2606.20910v1
- Fingerprinting the Fingerprinters (FP-Inspector) — https://arxiv.org/pdf/2008.04480
- rebrowser-bot-detector (modern CDP/automation leak tests) — https://github.com/rebrowser/rebrowser-bot-detector
- rebrowser-patches (how Runtime.enable is patched — the arms race) — https://github.com/rebrowser/rebrowser-patches
- "How to fix Runtime.enable CDP detection" (mechanism) — https://rebrowser.net/blog/how-to-fix-runtime-enable-cdp-detection-of-puppeteer-playwright-and-other-automation-libraries
- Scrappey — What is CDP detection — https://scrappey.com/qa/anti-bot/what-is-cdp-detection
- DataDome — New headless Chrome & the CDP signal — https://datadome.co/threat-research/how-new-headless-chrome-the-cdp-signal-are-impacting-bot-detection/
- HUMAN Security — ChatGPT Atlas vs Perplexity Comet: how agentic browsers work — https://www.humansecurity.com/learn/blog/chatgpt-atlas-vs-perplexity-comet-agentic-browsers/
- Cloudflare — Web Bot Auth (verify agents with cryptography) — https://blog.cloudflare.com/web-bot-auth/ and https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/
- Cloudflare — Message Signatures in the Verified Bots Program — https://blog.cloudflare.com/verified-bots-with-cryptography/
- Castle — Authenticating OpenAI Operator via HTTP message signatures — https://blog.castle.io/how-to-authenticate-openai-operator-requests-using-http-message-signatures/
- Castle — Bot or not: spotting automated mouse movements — https://blog.castle.io/bot-or-not-can-you-spot-the-automated-mouse-movements/
- DMTG: entropy-controlled human-like mouse trajectory generation (what evasion looks like) — https://arxiv.org/html/2410.18233v1
- Anthropic — Computer use tool (screenshot + xdotool/Accessibility loop) — https://docs.claude.com/en/docs/agents-and-tools/tool-use/computer-use-tool
- browser-use issue #3829 — synthetic events / isTrusted leak — https://github.com/browser-use/browser-use/issues/3829
- Bot detection in 2026: JA4 & HTTP/2 fingerprinting — https://krowdev.com/article/bot-detection-2026/
