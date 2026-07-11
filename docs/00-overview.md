# 00 — Overview, Scope & Threat Model

## 1. What we are building

A single-page diagnostic web app. A visitor loads it in whatever client they
like (a real browser, a headless browser, a stealth-patched automation stack, or
a raw HTTP client), and the app returns a structured report of every signal a
production anti-bot system would evaluate, together with:

- an **overall verdict** — `likely human browser` / `suspicious` / `likely automated`;
- a **per-signal breakdown** — each signal's raw value, a verdict badge, and a one-line explanation of why it matters;
- a **contradiction list** — cross-layer inconsistencies, surfaced separately because they carry the most weight;
- a **coherence score** — a single 0–100 number expressing how internally consistent the client's self-presentation is.

The differentiator versus existing tools (`bot.sannysoft.com`, `browserleaks.com`,
`pixelscan`, `creepjs`) is not any single novel check — it is the explicit
**cross-layer coherence engine** that scores *contradictions between layers*
(the TLS stack says Go, the User-Agent says Chrome) rather than treating each
flag in isolation.

## 2. Goals

1. **Comprehensive** — cover all three detection layers to the extent the
   deployment allows, and clearly label what a given deployment can and cannot see.
2. **Explanatory** — every signal is documented in-product; a developer should
   learn *why* something is a tell, not just that it fired.
3. **Coherent** — the headline output is a single consistency score derived from
   weighted signals and contradictions, not a wall of green/red dots.
4. **Honest about limits** — never claim a signal we didn't actually capture.
   "Unavailable on this deployment" is a first-class result, distinct from "ok".
5. **Low self-noise** — the frontend must be dependency-light so the tool does
   not pollute the very fingerprint it is measuring.
6. **Reproducible** — the same client hitting the tool twice should get the same
   verdict (modulo behavioral signals, which are inherently noisy).

## 3. Non-goals (hard boundaries)

- **No CAPTCHA solving, no protection bypass, no detection evasion.** We report
  to the visitor about themselves. We do not help anyone defeat a third party's
  anti-bot system.
- **No covert tracking.** Fingerprints are computed to give the visitor their own
  report. We do not build cross-site identity graphs or sell/share fingerprints.
- **No stealth guidance.** The report explains *why* a signal is suspicious; it
  does not ship a checklist of "here's how to patch each tell." (Documenting the
  underlying browser behavior for education is fine; packaging an evasion kit is
  not.)
- **Not a WAF.** This is a diagnostic surface, not an inline enforcement product.
  It does not block, throttle, or challenge traffic based on its verdict.

## 4. Users & use cases

| User | Use case |
|------|----------|
| QA / automation engineer | Verify their Playwright/Puppeteer fleet presents consistently; find which layer leaks. |
| Anti-fraud / detection engineer | Understand what a given client stack looks like across layers; build intuition for coherence checks. |
| Privacy-conscious user | See what their browser leaks and whether hardening (e.g. resistFingerprinting) introduces *new* tells. |
| Security researcher / student | A didactic reference implementation of layered bot detection. |

## 5. Threat model (what the tool is trying to characterize)

We describe clients along two axes: **how much they've invested in looking human**
and **which layer they patched**. The tool's job is to place a client on this map.

| Client class | Layer 1 (browser) | Layer 2 (HTTP) | Layer 3 (transport) | How it should score |
|--------------|-------------------|----------------|---------------------|---------------------|
| Real desktop/mobile browser | coherent | coherent | coherent | clean |
| `curl` / `requests` / `axios` / Go `http.Client` | n/a (no JS runs) or trivially wrong | wrong headers + wrong order | wrong TLS/H2 | flagged immediately, usually before JS |
| Vanilla Puppeteer/Playwright, headless | `webdriver`, headless tells, permissions mismatch | browser-like | browser-like (uses real Chrome TLS) | flagged on Layer 1 |
| Vanilla Puppeteer/Playwright, **headed** | `webdriver=true`, behavioral flatness | browser-like | browser-like | flagged on `webdriver` + behavior |
| `puppeteer-extra-plugin-stealth` | most single flags patched | browser-like | browser-like | **the hard case** — should still be caught by contradictions + behavior |
| Anti-detect browser (Multilogin, GoLogin, etc.) | spoofed but often internally inconsistent | browser-like | may mismatch spoofed UA | caught by cross-layer coherence |
| Real browser driven by CDP with no stealth | `webdriver` may be off, but automation globals / behavior tells | coherent | coherent | caught by behavior + subtle globals |

The **design target** is the stealth-patched headless case: any single flag it
patched should not save it if the *combination* of what it presents is
internally inconsistent. That is the entire reason the coherence engine exists.

## 6. What "detection" means here — a note on epistemics

We are not building a classifier that outputs truth. We are building a
**transparency instrument**. Every verdict is "this is what a detector would
likely conclude, and here is the evidence." False positives are expected and
acceptable (a hardened privacy browser may look suspicious — that is itself
useful information for its user). The tool's value is in *explaining the
reasoning*, not in being an oracle.

## 7. Glossary

| Term | Meaning |
|------|---------|
| **Layer 1** | Signals observable from frontend JavaScript (`navigator`, WebGL, canvas, behavior). |
| **Layer 2** | HTTP request metadata (header values, header order, client hints, `Sec-Fetch-*`). |
| **Layer 3** | Transport-level fingerprints (TLS ClientHello → JA3/JA4, HTTP/2 SETTINGS, IP/ASN). |
| **JA3 / JA4** | Hash fingerprints of the TLS ClientHello. JA3 is legacy (MD5 of a field string); JA4 is the current, more robust scheme. |
| **GFE** | Google Front End — the reverse-proxy / TLS-termination tier in front of all Google-hosted HTTP services, including Cloud Functions and Cloud Run. |
| **Client hints** | The `Sec-CH-UA*` header family; a structured, opt-in replacement for parts of the User-Agent string. |
| **Coherence score** | The headline 0–100 metric expressing internal consistency across all captured signals. |
| **Contradiction** | A specific pair (or set) of signals that cannot both be true of a genuine client (e.g. TLS=Go, UA=Chrome). |
| **Edge probe** | A separate, raw-socket host we control that terminates TLS itself, so it *can* capture Layer 3. Needed because a Cloud Function cannot. |
