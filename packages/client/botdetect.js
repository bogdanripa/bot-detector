/*
 * @botdetect/client — browser detection library (Layer 1 + behavior/provenance).
 * Zero dependencies. Exposes window.botdetect. See docs/04, docs/14, docs/15.
 * Never sends field VALUES — only dynamics (timings/counts/variances).
 */
(function () {
  "use strict";
  function readBoot() {
    try { var el = document.getElementById("bd-bootstrap"); if (el) return JSON.parse(el.textContent); } catch (e) {}
    return (typeof window !== "undefined" && window.__BD_BOOTSTRAP__) || {};
  }
  var BOOT = readBoot();
  var ENDPOINT = "/api/analyze";

  // ---------- Layer 1 passive collectors ----------
  function scanGlobals(names) {
    var found = [];
    for (var i = 0; i < names.length; i++) { try { if (names[i] in window) found.push(names[i]); } catch (e) {} }
    return found;
  }
  function cdcArtifacts() {
    var out = [];
    try { for (var k in window) { if (/^[$]?cdc_/.test(k)) out.push(k); } } catch (e) {}
    try {
      var d = Object.getOwnPropertyNames(document);
      for (var i = 0; i < d.length; i++) if (/^[$]?cdc_/.test(d[i])) out.push(d[i]);
    } catch (e) {}
    return out;
  }
  function seleniumAttrs() {
    var out = [], names = ["__selenium_unwrapped", "__webdriver_evaluate", "__driver_evaluate",
      "__webdriver_script_fn", "__fxdriver_evaluate", "__driver_unwrapped", "__webdriver_unwrapped",
      "__selenium_evaluate", "__webdriver_script_func"];
    for (var i = 0; i < names.length; i++) { try { if (names[i] in document) out.push(names[i]); } catch (e) {} }
    return out;
  }
  function playwrightBindings() {
    var out = [], names = ["__pwInitScripts", "__playwright__binding__", "__pw_manual", "__PW_inspect"];
    for (var i = 0; i < names.length; i++) { try { if (names[i] in window) out.push(names[i]); } catch (e) {} }
    try { for (var k in window) if (/playwright|puppeteer/i.test(k)) out.push(k); } catch (e) {}
    return out;
  }
  function webdriverDescriptor() {
    try {
      var d = Object.getOwnPropertyDescriptor(Navigator.prototype, "webdriver");
      if (d && d.get) { return /\[native code\]/.test(d.get.toString()) ? "native" : "patched-getter"; }
      if (Object.getOwnPropertyDescriptor(navigator, "webdriver")) return "instance-override";
      return "native";
    } catch (e) { return "native"; }
  }
  function cdpRuntimeEnableLeak() {
    // A getter that only fires when a CDP client with Runtime.enable serializes the object.
    var leaked = false;
    try {
      var bait = {};
      Object.defineProperty(bait, "id", { get: function () { leaked = true; return 1; }, configurable: true });
      console.debug(bait);
    } catch (e) {}
    return leaked;
  }
  function webgl() {
    try {
      var c = document.createElement("canvas");
      var gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!gl) return { supported: false, unmaskedVendor: "", unmaskedRenderer: "", isSoftware: false };
      var dbg = gl.getExtension("WEBGL_debug_renderer_info");
      var vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : String(gl.getParameter(gl.VENDOR));
      var renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : String(gl.getParameter(gl.RENDERER));
      var soft = /SwiftShader|llvmpipe|Mesa OffScreen|Software|Microsoft Basic Render/i.test(renderer + " " + vendor);
      return { supported: true, unmaskedVendor: String(vendor), unmaskedRenderer: String(renderer), isSoftware: soft };
    } catch (e) { return { supported: false, unmaskedVendor: "", unmaskedRenderer: "", isSoftware: false }; }
  }
  function canvasBlocked() {
    try {
      var c = document.createElement("canvas"); c.width = 40; c.height = 20;
      var ctx = c.getContext("2d"); ctx.fillStyle = "#069"; ctx.fillText("bd", 2, 12);
      var d = c.toDataURL();
      return { supported: true, blocked: (d === "data:," || d.length < 60) };
    } catch (e) { return { supported: false, blocked: true }; }
  }
  async function permissionsContradiction() {
    try {
      var s = await navigator.permissions.query({ name: "notifications" });
      return s.state === "denied" && Notification.permission === "default";
    } catch (e) { return false; }
  }

  async function collectPassive() {
    var af = {
      navigatorWebdriver: navigator.webdriver === true,
      injectedGlobals: scanGlobals(["_phantom", "__phantom", "callPhantom", "__nightmare", "domAutomation", "domAutomationController"]),
      cdcArtifacts: cdcArtifacts(),
      seleniumAttributes: seleniumAttrs(),
      playwrightBindings: playwrightBindings(),
      nodeGlobals: scanGlobals(["Buffer", "process", "require", "global", "emit", "spawn"]),
      chromeRuntimePresent: !!(window.chrome && window.chrome.runtime),
      webdriverDescriptor: webdriverDescriptor(),
      cdpRuntimeEnableLeak: cdpRuntimeEnableLeak(),
      antiTamperPatched: webdriverDescriptor() !== "native"
    };
    var g = webgl(), cv = canvasBlocked();
    return {
      automationFlags: af,
      headless: {
        uaHasHeadlessChrome: /HeadlessChrome/.test(navigator.userAgent),
        pluginsLength: (navigator.plugins && navigator.plugins.length) || 0,
        mimeTypesLength: (navigator.mimeTypes && navigator.mimeTypes.length) || 0,
        languagesEmpty: !navigator.languages || navigator.languages.length === 0,
        permissionsContradiction: await permissionsContradiction()
      },
      webgl: g,
      canvas: cv,
      hardware: {
        hardwareConcurrency: navigator.hardwareConcurrency || 0,
        deviceMemory: navigator.deviceMemory || 0,
        maxTouchPoints: navigator.maxTouchPoints || 0
      },
      screen: {
        width: screen.width, height: screen.height,
        innerWidth: window.innerWidth, innerHeight: window.innerHeight,
        outerWidth: window.outerWidth, outerHeight: window.outerHeight
      },
      locale: {
        intlTimeZone: (Intl.DateTimeFormat().resolvedOptions().timeZone) || "",
        language: navigator.language || "",
        languages: navigator.languages ? [].slice.call(navigator.languages) : []
      },
      environment: { userAgent: navigator.userAgent, vendor: navigator.vendor || "", platform: navigator.platform || "" }
    };
  }

  // ---------- transport ----------
  function post(step, extra) {
    var body = Object.assign({ reportVersion: "1", sessionId: BOOT.sessionId, step: step, collectedAtMs: Date.now() }, extra || {});
    var json = JSON.stringify(body);
    // Prefer fetch (so we can read the report); beacon as fallback for unload.
    return fetch(ENDPOINT, { method: "POST", headers: { "Content-Type": "application/json" }, body: json, keepalive: true })
      .then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; });
  }
  function beacon(step, extra) {
    try {
      var body = Object.assign({ reportVersion: "1", sessionId: BOOT.sessionId, step: step, collectedAtMs: Date.now() }, extra || {});
      navigator.sendBeacon(ENDPOINT, new Blob([JSON.stringify(body)], { type: "application/json" }));
    } catch (e) {}
  }

  // ---------- scroll + click provenance (Page 1) ----------
  function instrumentScrollAndLink(linkEl, extraFn) {
    var lastGesture = 0, wheelCount = 0, wheelFractional = false, touchScroll = false,
      keyboardScroll = false, scrollbarDrag = false, scrollEvents = 0, prevY = window.scrollY,
      teleport = false, trail = [];
    function gesture() { lastGesture = performance.now(); }
    addEventListener("wheel", function (e) { gesture(); wheelCount++; if (e.deltaY % 1 !== 0) wheelFractional = true; }, { passive: true, capture: true });
    addEventListener("touchmove", function () { gesture(); touchScroll = true; }, { passive: true, capture: true });
    addEventListener("keydown", function (e) { if (["PageDown", "PageUp", "ArrowDown", "ArrowUp", " ", "End", "Home"].indexOf(e.key) >= 0) { gesture(); keyboardScroll = true; } }, true);
    addEventListener("pointerdown", function (e) { if (e.clientX > document.documentElement.clientWidth - 20) { gesture(); scrollbarDrag = true; } }, true);
    addEventListener("pointermove", function (e) {
      trail.push({ x: e.clientX, y: e.clientY, t: e.timeStamp, c: (e.getCoalescedEvents ? e.getCoalescedEvents().length : 0) });
      if (trail.length > 300) trail.shift();
    }, { passive: true, capture: true });
    addEventListener("scroll", function () {
      scrollEvents++;
      if (Math.abs(window.scrollY - prevY) > 300 && performance.now() - lastGesture > 150) teleport = true;
      prevY = window.scrollY;
    }, { passive: true });

    function scrollProvenance() {
      var r = linkEl.getBoundingClientRect();
      var aligned = Math.abs(r.top) < 2 || Math.abs(r.top + r.height / 2 - window.innerHeight / 2) < 2;
      return {
        reachedLink: true, wheelCount: wheelCount, wheelFractional: wheelFractional, touchScroll: touchScroll,
        keyboardScroll: keyboardScroll, scrollbarDrag: scrollbarDrag,
        anyUserGesture: lastGesture > 0, teleport: teleport, landedPixelAligned: aligned, scrollEvents: scrollEvents
      };
    }
    function clickProvenance(e) {
      var near = trail.filter(function (p) { return Math.hypot(p.x - e.clientX, p.y - e.clientY) < 80 && e.timeStamp - p.t < 600; });
      var coalesced = near.reduce(function (s, p) { return s + p.c; }, 0);
      var rr = e.target.getBoundingClientRect();
      var center = Number.isInteger(e.clientX) && Number.isInteger(e.clientY) &&
        Math.abs(e.clientX - (rr.left + rr.width / 2)) < 1 && Math.abs(e.clientY - (rr.top + rr.height / 2)) < 1;
      return {
        occurred: true, isTrusted: e.isTrusted, approachPoints: near.length, coalescedNearby: coalesced,
        atExactIntegerCenter: center, dwellBeforeClickMs: Math.round(performance.now()),
        sourceCapabilitiesPresent: !!e.sourceCapabilities
      };
    }
    linkEl.addEventListener("click", function (e) {
      // send synchronously via beacon so it lands before the navigation
      var extra = { scrollToLink: scrollProvenance(), linkClick: clickProvenance(e) };
      if (extraFn) Object.assign(extra, extraFn());
      beacon("landing", extra);
      // do NOT preventDefault — let the normal <a> navigation proceed
    }, true);
  }

  // ---------- form behavior (Page 2) ----------
  function instrumentForm(formEl) {
    var t0 = performance.now(), fields = {}, focusOrder = [], tabUsed = false, mouseMoves = 0, firstInteraction = null;
    function mark() { if (firstInteraction === null) firstInteraction = performance.now() - t0; }
    function acc(name) { return fields[name] || (fields[name] = { name: name, keydowns: 0, inter: [], last: 0, backspaces: 0, pasteEvents: 0, filledWithoutKeys: false, autofillPseudo: false }); }
    addEventListener("mousemove", function () { mouseMoves++; }, { passive: true, capture: true });
    var els = formEl.querySelectorAll("input,textarea,select");
    els.forEach(function (el) {
      var name = el.name || el.id || "field";
      var f = acc(name);
      el.addEventListener("focus", function () { mark(); if (focusOrder.indexOf(name) < 0) focusOrder.push(name); });
      el.addEventListener("keydown", function (e) {
        mark(); f.keydowns++;
        var now = performance.now(); if (f.last) f.inter.push(now - f.last); f.last = now;
        if (e.key === "Tab") tabUsed = true; if (e.key === "Backspace") f.backspaces++;
      });
      el.addEventListener("paste", function () { mark(); f.pasteEvents++; });
      el.addEventListener("input", function () {
        try { f.autofillPseudo = el.matches(":autofill") || el.matches(":-webkit-autofill"); } catch (e) {}
        if (f.keydowns === 0 && f.pasteEvents === 0 && el.value && el.value.length > 0) f.filledWithoutKeys = true;
      });
    });
    return function flush() {
      var out = [];
      for (var k in fields) {
        var f = fields[k];
        out.push({ name: f.name, keydowns: f.keydowns, interKeyStdev: stdev(f.inter), backspaces: f.backspaces,
          pasteEvents: f.pasteEvents, filledWithoutKeys: f.filledWithoutKeys, autofillPseudo: f.autofillPseudo });
      }
      return {
        durationMs: Math.round(performance.now() - t0),
        fillToSubmitMs: Math.round(performance.now() - t0),
        fields: out, focusOrder: focusOrder, tabKeyUsed: tabUsed,
        mouseMoveEvents: mouseMoves, straightSegmentsRatio: 0, globalInterKeyStdev: 0
      };
    };
  }

  function readTraps(formEl) {
    var hp = formEl.querySelector('[data-bd-honeypot]');
    return {
      domHoneypotFilled: !!(hp && hp.value && hp.value.length > 0),
      visionTrapTripped: false, smoothPursuitTracked: true, fillFasterThanHuman: false
    };
  }

  function stdev(a) {
    if (a.length < 2) return 0;
    var m = a.reduce(function (s, x) { return s + x; }, 0) / a.length;
    var v = a.reduce(function (s, x) { return s + (x - m) * (x - m); }, 0) / a.length;
    return Math.sqrt(v);
  }

  // ---------- report rendering (Page 3) ----------
  function renderReport(report, mount) {
    if (!report) { mount.textContent = "No report."; return; }
    var sc = report.score, bandColor = { human: "#1a7f37", suspicious: "#bf8700", automated: "#cf222e" }[sc.band] || "#555";
    var icon = { human: "✓", suspicious: "⚠", automated: "✗" }[sc.band] || "";
    var h = "";
    h += '<div class="bd-banner" style="border-color:' + bandColor + '">';
    h += '<div class="bd-pct" style="color:' + bandColor + '">' + sc.percent + '%</div>';
    h += '<div><div class="bd-verdict" style="color:' + bandColor + '">' + icon + " " + sc.band.toUpperCase() + '</div>';
    h += '<div class="bd-sub">automation probability ' + sc.percent + '% &middot; confidence ' + Math.round(sc.confidence * 100) + '%';
    if (sc.automationType && sc.automationType !== "none") h += ' &middot; type: <code>' + sc.automationType + '</code>';
    h += "</div></div></div>";
    if (report.contradictions && report.contradictions.length) {
      h += '<h3>Contradictions</h3><ul class="bd-contra">';
      report.contradictions.forEach(function (c) { h += "<li><b>" + esc(c.title) + "</b> — " + esc(c.explanation) + "</li>"; });
      h += "</ul>";
    }
    h += '<h3>Checks</h3><table class="bd-checks">';
    (report.checks || []).forEach(function (c) {
      var badge = { pass: "PASS", warn: "WARN", fail: "FAIL", unavailable: "N/A" }[c.status] || c.status;
      var col = { pass: "#1a7f37", warn: "#bf8700", fail: "#cf222e", unavailable: "#888" }[c.status] || "#555";
      h += '<tr><td><span class="bd-badge" style="background:' + col + '">' + badge + "</span></td>";
      h += "<td><b>" + esc(c.title) + "</b><br><span class=bd-exp>" + esc(c.explanation) + "</span></td>";
      h += "<td class=bd-val>" + esc(c.value || "") + "</td></tr>";
    });
    h += "</table>";
    mount.innerHTML = h;
  }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  // ---------- drop-in autostart (docs/15) ----------
  function autostart(opts) {
    opts = opts || {};
    if (opts.endpoint) ENDPOINT = opts.endpoint;
    collectPassive().then(function (l1) { post("landing", { layer1: l1 }); });
    // global, passive, capture-phase — covers existing forms/links, never preventDefault
    var forms = document.querySelectorAll("form");
    forms.forEach(function (f) {
      var flush = instrumentForm(f);
      f.addEventListener("submit", function () { beacon("form", { behavior: flush(), traps: readTraps(f) }); }, true);
    });
    return { onVerdict: function () {} };
  }

  // ---------- honeypot per-step auto-init ----------
  var FORBIDDEN = BOOT.forbidden || "/test/forbidden";
  var ENFORCE = BOOT.enforceBand || "suspicious";
  function bandRank(b) { return b === "automated" ? 2 : b === "suspicious" ? 1 : 0; }
  function isBot(report) { return report && report.score && bandRank(report.score.band) >= bandRank(ENFORCE); }
  // In test mode, redirect a detected bot; returns true if it redirected.
  function enforce(report) {
    if (BOOT.mode === "test" && isBot(report)) { location.replace(FORBIDDEN); return true; }
    return false;
  }

  function initHoneypot() {
    var link, form;
    if (BOOT.step === "landing") {
      var passive = null;
      collectPassive().then(function (l1) {
        passive = l1;
        link = document.querySelector("[data-bd-link]") || document.querySelector("a.cta") || document.querySelector("a");
        if (BOOT.mode === "test") {
          // fetch a verdict on load; block obvious bots before they can proceed
          post("landing", { layer1: l1 }).then(function (rep) {
            if (!enforce(rep) && link) instrumentScrollAndLink(link, function () { return { layer1: passive }; });
          });
        } else if (link) {
          instrumentScrollAndLink(link, function () { return { layer1: passive }; });
        }
      });
    } else if (BOOT.step === "form") {
      var passiveF = null;
      collectPassive().then(function (l1) { passiveF = l1; });
      form = document.querySelector("form");
      if (form) {
        var flush = instrumentForm(form);
        form.addEventListener("submit", function (e) {
          var payload = { layer1: passiveF, behavior: flush(), traps: readTraps(form) };
          if (BOOT.mode === "test") {
            e.preventDefault();
            post("form", payload).then(function (rep) {
              if (!enforce(rep)) location.href = BOOT.submit || "/test/submit";
            });
          } else {
            beacon("form", payload); // let the form POST to /<mode>/submit → /<mode>/result
          }
        }, true);
      }
    } else if (BOOT.step === "result") {
      var mount = document.getElementById("bd-report");
      if (mount && BOOT.report) renderReport(BOOT.report, mount);
    }
  }

  window.botdetect = {
    boot: BOOT, collectPassive: collectPassive, post: post, beacon: beacon,
    instrumentScrollAndLink: instrumentScrollAndLink, instrumentForm: instrumentForm,
    readTraps: readTraps, renderReport: renderReport, autostart: autostart
  };

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initHoneypot);
  else initHoneypot();
})();
