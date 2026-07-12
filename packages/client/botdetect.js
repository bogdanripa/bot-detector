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
      // Real Chrome only exposes chrome.runtime to extension-connectable pages;
      // normal pages get window.chrome with loadTimes/csi/app. Test the object.
      chromeRuntimePresent: !!(window.chrome && (window.chrome.loadTimes || window.chrome.csi || window.chrome.app || window.chrome.runtime)),
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
      var near = trail.filter(function (p) { return Math.hypot(p.x - e.clientX, p.y - e.clientY) < 120 && e.timeStamp - p.t < 1500; });
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
    // Live scroll (debug): re-post provenance as the user scrolls (throttled) so
    // the scroll_teleport check climbs pending → inconclusive → pass in real time.
    if (BOOT.mode !== "test") {
      var liveScrollT = 0;
      addEventListener("scroll", function () {
        var now = performance.now();
        if (now - liveScrollT < 400) return; liveScrollT = now;
        var prov = scrollProvenance(); prov.reachedLink = false;
        var extra = { scrollToLink: prov };
        if (extraFn) Object.assign(extra, extraFn());
        post("landing", extra).then(renderSidebar);
      }, { passive: true });
    }
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
    sortChecks(report.checks || []).forEach(function (c) {
      var badge = STATUS_LABEL[c.status] || c.status;
      var col = STATUS_COLOR[c.status] || "#555";
      var conf = (c.index >= 80) ? ' <span class=bd-exp>· ' + Math.round((c.confidence || 0) * 100) + "% confidence</span>" : "";
      h += '<tr><td><span class="bd-badge" style="background:' + col + '">' + badge + "</span></td>";
      h += "<td><b>" + esc(c.title) + "</b>" + conf + "<br><span class=bd-exp>" + esc(c.explanation) + "</span></td>";
      h += "<td class=bd-val>" + esc(c.value || "") + "</td></tr>";
    });
    h += "</table>";
    mount.innerHTML = h;
  }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  // ---------- debug sidebar show/hide toggle (custom checklist icon) ----------
  function initSidebarToggle() {
    var btn = document.querySelector(".bds-toggle");
    if (!btn) return;
    var collapsed = false;
    try { collapsed = localStorage.getItem("bds-collapsed") === "1"; } catch (e) {}
    document.body.classList.toggle("bds-collapsed", collapsed);
    btn.setAttribute("aria-expanded", String(!collapsed));
    btn.addEventListener("click", function () {
      var c = document.body.classList.toggle("bds-collapsed");
      btn.setAttribute("aria-expanded", String(!c));
      try { localStorage.setItem("bds-collapsed", c ? "1" : "0"); } catch (e) {}
    });
  }

  // ---------- debug sidebar resize (drag the left edge; width persists) ----------
  // Clamp to [300px, 92vw] so a width saved on a wide monitor can't cover the
  // whole page (and leave the drag handle off-screen) on a narrower one.
  function clampWidth(w) { return Math.max(300, Math.min(w, Math.round(window.innerWidth * 0.92))); }
  function initSidebarResize() {
    var el = document.querySelector("aside.bds-side");
    if (!el) return;
    try {
      var saved = parseInt(localStorage.getItem("bds-w"), 10);
      if (saved) document.documentElement.style.setProperty("--bds-w", clampWidth(saved) + "px");
    } catch (e) {}
    var dragging = false;
    el.addEventListener("pointerdown", function (e) {
      if (e.clientX - el.getBoundingClientRect().left > 10) return;
      dragging = true;
      e.preventDefault();
      document.body.style.userSelect = "none";
    });
    addEventListener("pointermove", function (e) {
      if (!dragging) return;
      document.documentElement.style.setProperty("--bds-w", clampWidth(window.innerWidth - e.clientX) + "px");
    });
    addEventListener("pointerup", function () {
      if (!dragging) return;
      dragging = false;
      document.body.style.userSelect = "";
      try { localStorage.setItem("bds-w", parseInt(getComputedStyle(el).width, 10)); } catch (e) {}
    });
  }

  // ---------- continuous behavior monitor (page-independent, cross-page) ----------
  // A drop-in library watches every user action on every page and keeps a running
  // ratio of suspicious actions to total. State persists in sessionStorage so it
  // survives navigations in non-SPA apps. Only high-precision tells count as
  // suspicious (synthetic isTrusted=false events, exact-center clicks, metronomic
  // typing, teleport scrolls) so a real human stays near 0% no matter how much
  // they interact — and one injected action among N human ones reads as 1/(N+1).
  var behaviorMonitor = (function () {
    var KEY = "bd_behavior_v1";
    var state = { total: 0, suspicious: 0, reasons: {}, startMs: 0 };
    var started = false, rafPending = false, lastSaveMs = 0;
    var lastMoveMs = 0, lastScrollMs = 0, lastGestureMs = 0, lastScrollY = 0, keyTimes = [];
    function tnow() { return Date.now(); }
    function load() {
      try { var s = JSON.parse(sessionStorage.getItem(KEY)); if (s && typeof s.total === "number") state = s; } catch (e) {}
      if (!state.startMs) state.startMs = tnow();
      if (!state.reasons) state.reasons = {};
    }
    function save() {
      var t = tnow(); if (t - lastSaveMs < 300) return; lastSaveMs = t;
      try { sessionStorage.setItem(KEY, JSON.stringify(state)); } catch (e) {}
    }
    function scheduleRender() {
      if (rafPending) return; rafPending = true;
      (window.requestAnimationFrame || function (f) { setTimeout(f, 16); })(function () { rafPending = false; render(); });
    }
    // Ignore interaction with our own debug sidebar so reading the panel never
    // pollutes the subject's behavior signals.
    function fromSidebar(e) {
      var t = e.target;
      return !!(t && t.closest && (t.closest("aside.bds-side") || t.closest(".bds-toggle")));
    }
    function observe(suspicious, reason) {
      state.total++;
      if (suspicious) { state.suspicious++; state.reasons[reason] = (state.reasons[reason] || 0) + 1; }
      save(); scheduleRender();
    }
    function stdev(a) {
      if (a.length < 2) return Infinity;
      var m = a.reduce(function (s, x) { return s + x; }, 0) / a.length;
      return Math.sqrt(a.reduce(function (s, x) { return s + (x - m) * (x - m); }, 0) / a.length);
    }
    function exactCenter(e) {
      try {
        var r = e.target.getBoundingClientRect();
        return Number.isInteger(e.clientX) && Number.isInteger(e.clientY) &&
          Math.abs(e.clientX - (r.left + r.width / 2)) < 1 && Math.abs(e.clientY - (r.top + r.height / 2)) < 1;
      } catch (x) { return false; }
    }
    function onPointerDown(e) {
      if (fromSidebar(e)) return;
      if (e.isTrusted === false) return observe(true, "synthetic click (isTrusted=false)");
      observe(exactCenter(e), "injected click (exact element center)");
    }
    function onKeyDown(e) {
      if (fromSidebar(e)) return;
      if (e.isTrusted === false) return observe(true, "synthetic keypress (isTrusted=false)");
      keyTimes.push(tnow()); if (keyTimes.length > 8) keyTimes.shift();
      var iv = []; for (var i = 1; i < keyTimes.length; i++) iv.push(keyTimes[i] - keyTimes[i - 1]);
      observe(iv.length >= 5 && stdev(iv) < 8, "metronomic typing (robotic cadence)");
    }
    function onGesture(e) { lastGestureMs = tnow(); if (e.isTrusted === false) observe(true, "synthetic " + e.type); }
    function onMove(e) {
      if (fromSidebar(e)) return;
      var t = tnow(); if (t - lastMoveMs < 400) return; lastMoveMs = t;
      observe(e.isTrusted === false, "synthetic pointer movement");
    }
    function onScroll() {
      var t = tnow(); if (t - lastScrollMs < 400) return; lastScrollMs = t;
      var y = window.scrollY || 0, jump = Math.abs(y - lastScrollY); lastScrollY = y;
      observe(jump > 800 && t - lastGestureMs > 200, "teleport scroll (jump without a gesture)");
    }
    function render() {
      var el = document.getElementById("bds-live"); if (!el) return;
      var pct = state.total ? Math.round(100 * state.suspicious / state.total) : 0;
      var color = pct >= 50 ? "#cf222e" : pct >= 15 ? "#bf8700" : "#1a7f37";
      var secs = Math.round((tnow() - state.startMs) / 1000);
      var h = '<div class="bds-live-hd">Live behavioral score <span style="color:#888;font-weight:400">· all pages</span></div>';
      if (!state.total) { h += '<div class="bds-live-meta">watching for activity…</div>'; el.innerHTML = h; return; }
      h += '<div class="bds-live-row"><span class="bds-live-pct" style="color:' + color + '">' + pct + '%</span>';
      h += '<span class="bds-live-meta">' + state.suspicious + ' suspicious of ' + state.total + ' actions · ' + secs + 's watched</span></div>';
      var rs = Object.keys(state.reasons);
      if (rs.length) { h += '<ul class="bds-live-reasons">'; rs.forEach(function (r) { h += '<li>' + esc(r) + ' &times;' + state.reasons[r] + '</li>'; }); h += '</ul>'; }
      else h += '<div class="bds-live-ok">No automation tells in your activity yet.</div>';
      el.innerHTML = h;
    }
    function reset() {
      state = { total: 0, suspicious: 0, reasons: {}, startMs: tnow() };
      keyTimes = []; lastSaveMs = 0;
      try { sessionStorage.removeItem(KEY); } catch (e) {}
      render();
    }
    function start() {
      if (started) return; started = true;
      load();
      var opt = { capture: true, passive: true };
      addEventListener("pointerdown", onPointerDown, opt);
      addEventListener("keydown", onKeyDown, opt);
      addEventListener("wheel", onGesture, opt);
      addEventListener("touchstart", onGesture, opt);
      addEventListener("pointermove", onMove, opt);
      addEventListener("scroll", onScroll, opt);
      addEventListener("pagehide", function () { lastSaveMs = 0; save(); });
      lastScrollY = window.scrollY || 0;
      // Periodic tick: repaints even when rAF is throttled (background tabs) and
      // advances the "Xs watched" clock so the score visibly evolves over time.
      setInterval(render, 500);
      render();
    }
    return { start: start, render: render, reset: reset, snapshot: function () { return state; } };
  })();

  // ---------- debug sidebar (server-rendered; re-rendered here when new
  // signals are posted mid-page, e.g. the passive Layer 1 snapshot on load) ----------
  function renderSidebar(report) {
    var el = document.querySelector("aside.bds-side");
    if (!el || !report || !report.score) return;
    var sc = report.score;
    var color = { human: "#1a7f37", suspicious: "#bf8700", automated: "#cf222e" }[sc.band] || "#555";
    var icon = { human: "✓", suspicious: "⚠", automated: "✗" }[sc.band] || "";
    var h = '<div class="bds-head"><h2>Live report — checks so far</h2>' +
      '<button class="bds-reset" type="button" title="Clear the running tally and start a fresh session">Reset</button></div>';
    h += '<div class="bds-live" id="bds-live"></div>';
    h += '<div class="bds-banner" style="border-color:' + color + '">';
    h += '<div class="bds-pct" style="color:' + color + '">' + sc.percent + "%</div><div>";
    h += '<div style="font-weight:700;color:' + color + '">' + icon + " " + esc(sc.band.toUpperCase()) + "</div>";
    h += '<div class="bds-sub">automation probability ' + sc.percent + "% &middot; confidence " + Math.round(sc.confidence * 100) + "%";
    if (sc.automationType && sc.automationType !== "none") h += " &middot; type: <code>" + esc(sc.automationType) + "</code>";
    h += "</div></div></div>";
    if (report.contradictions && report.contradictions.length) {
      h += '<ul class="bds-contra">';
      report.contradictions.forEach(function (c) {
        h += '<li><b style="color:#cf222e">' + esc(c.title) + "</b> — " + esc(c.explanation);
        if (c.value) h += ' <code style="font-size:.75rem">' + esc(c.value) + "</code>";
        h += "</li>";
      });
      h += "</ul>";
    }
    h += '<table class="bds-checks">';
    sortChecks(report.checks || []).forEach(function (c) {
      var badge = STATUS_LABEL[c.status] || c.status;
      var col = STATUS_COLOR[c.status] || "#555";
      var conf = (c.index >= 80) ? '<br><span class="bds-conf">' + Math.round((c.confidence || 0) * 100) + "%</span>" : "";
      h += '<tr><td><span class="bds-badge" style="background:' + col + '">' + esc(badge) + "</span>" + conf + "</td>";
      h += "<td><b>" + esc(c.title) + '</b><br><span class="bds-exp">' + esc(c.explanation) + "</span></td>";
      h += '<td class="bds-val">' + esc(c.value || "") + "</td></tr>";
    });
    h += "</table>";
    el.innerHTML = h;
    behaviorMonitor.render(); // refill the live block the rebuild just cleared
  }
  // Shared status presentation + ordering (index desc, then status severity).
  var STATUS_LABEL = { pass: "PASS", warn: "WARN", fail: "FAIL", unavailable: "N/A", pending: "PENDING", inconclusive: "UNCLEAR" };
  var STATUS_COLOR = { pass: "#1a7f37", warn: "#bf8700", fail: "#cf222e", unavailable: "#888", pending: "#57606a", inconclusive: "#8250df" };
  var STATUS_RANK = { fail: 0, warn: 1, inconclusive: 2, pending: 3, unavailable: 4, pass: 5 };
  function sortChecks(list) {
    return list.slice().sort(function (a, b) {
      if ((a.index || 0) !== (b.index || 0)) return (b.index || 0) - (a.index || 0);
      return (STATUS_RANK[a.status] || 9) - (STATUS_RANK[b.status] || 9);
    });
  }

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
    initSidebarResize();
    initSidebarToggle();
    behaviorMonitor.start(); // watch everything, every page, regardless of step
    // Reset button (delegated so it survives sidebar re-renders): clear the
    // client tally, then hit /reset to drop the server session and start clean.
    document.addEventListener("click", function (e) {
      if (e.target && e.target.closest && e.target.closest(".bds-reset")) {
        behaviorMonitor.reset();
        location.href = "/reset?to=/" + (BOOT.mode || "debug");
      }
    }, true);
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
        } else {
          // debug: post the passive environment snapshot right away so the
          // sidebar grows with the no-interaction client checks on page 1
          post("landing", { layer1: l1 }).then(renderSidebar);
          if (link) instrumentScrollAndLink(link, function () { return { layer1: passive }; });
        }
      });
    } else if (BOOT.step === "form") {
      var passiveF = null;
      collectPassive().then(function (l1) {
        passiveF = l1;
        // debug: refresh the sidebar with this page's snapshot (also covers
        // deep-links to /debug/form where the landing post never happened)
        if (BOOT.mode !== "test") post("form", { layer1: l1 }).then(renderSidebar);
      });
      form = document.querySelector("form");
      if (form) {
        var flush = instrumentForm(form);
        if (BOOT.mode !== "test") {
          // Live typing: re-post behavior as the user types (throttled) so the
          // behavior_scripted check moves pending → inconclusive → pass/fail on
          // screen instead of sitting at "awaiting form typing" until submit.
          var liveT = 0;
          form.addEventListener("input", function () {
            var now = Date.now();
            if (now - liveT < 400) return; liveT = now;
            post("form", { layer1: passiveF, behavior: flush(), traps: readTraps(form) }).then(renderSidebar);
          }, true);
        }
        form.addEventListener("submit", function (e) {
          var payload = { layer1: passiveF, behavior: flush(), traps: readTraps(form) };
          e.preventDefault();
          // Keep the submitted field VALUES in the browser only (the promise is
          // that form contents never leave it) so the result page can echo them.
          try {
            var data = {};
            form.querySelectorAll("input,textarea,select").forEach(function (el) {
              if (el.hasAttribute("data-bd-honeypot")) return;
              var k = el.name || el.id; if (k) data[k] = el.value;
            });
            sessionStorage.setItem("bd_form_v1", JSON.stringify(data));
          } catch (x) {}
          // Wait for the server to record this page's behavior BEFORE navigating,
          // so /<mode>/result scores WITH the typing signals. A fire-and-forget
          // beacon races the navigation and the result page would show
          // behavior_scripted stuck at "awaiting form typing".
          var go = function () { location.href = BOOT.submit || ("/" + BOOT.mode + "/submit"); };
          post("form", payload).then(function (rep) {
            if (BOOT.mode === "test" && enforce(rep)) return; // redirected to /forbidden
            go();
          }, go); // navigate even if the post failed
        }, true);
      }
    } else if (BOOT.step === "result") {
      // The detection report already lives in the sidebar — don't reprint it.
      // Echo the submitted form data (kept client-side) as the app's confirmation.
      var mount = document.getElementById("bd-report");
      if (mount) renderSubmitted(mount);
    }
  }

  // Render the just-submitted form data (from sessionStorage) as an app-style
  // confirmation — the honeypot's cover story, and the "text to be checked".
  function renderSubmitted(mount) {
    var data = {};
    try { data = JSON.parse(sessionStorage.getItem("bd_form_v1")) || {}; } catch (e) {}
    var keys = Object.keys(data);
    if (!keys.length) {
      mount.innerHTML = '<p class="note">No submission found — you reached this page directly. ' +
        'Start at the <a href="/' + (BOOT.mode || "debug") + '">beginning</a> to submit the form.</p>';
      return;
    }
    var h = '<p class="note">Thanks — a real app would process this now. Here is exactly what you submitted ' +
      '(kept in your browser; only timing and movement were analyzed):</p><dl class="bd-submitted">';
    keys.forEach(function (k) { h += "<dt>" + esc(k) + "</dt><dd>" + esc(data[k] || "(empty)") + "</dd>"; });
    mount.innerHTML = h + "</dl>";
  }

  window.botdetect = {
    boot: BOOT, collectPassive: collectPassive, post: post, beacon: beacon,
    instrumentScrollAndLink: instrumentScrollAndLink, instrumentForm: instrumentForm,
    readTraps: readTraps, renderReport: renderReport, autostart: autostart,
    behaviorMonitor: behaviorMonitor
  };

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initHoneypot);
  else initHoneypot();
})();
