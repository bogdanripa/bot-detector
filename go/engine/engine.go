// Package engine scores a (possibly partial) SignalSet into a Report.
// It is a pure interpreter of config/scoring.json plus a registry of rule
// functions. See docs/07 and docs/14.
package engine

import (
	"encoding/json"
	"math"
	"sort"
	"strings"

	"github.com/bogdanripa/bot-detector/go/schema"
)

type signalDef struct {
	Weight      float64 `json:"weight"`
	Status      string  `json:"status"`
	Severity    string  `json:"severity"`
	Title       string  `json:"title"`
	Explanation string  `json:"explanation"`
}

type config struct {
	ConfigVersion             string                             `json:"configVersion"`
	ReportVersion             string                             `json:"reportVersion"`
	Bias                      float64                            `json:"bias"`
	Bands                     struct{ Human, Automated float64 } `json:"bands"`
	CriticalFloorWeight       float64                            `json:"criticalFloorWeight"`
	TransportContradictionCap float64                            `json:"transportContradictionCap"`
	BehaviorGroupCap          float64                            `json:"behaviorGroupCap"`
	Signals                   map[string]signalDef               `json:"signals"`
	Contradictions            map[string]signalDef               `json:"contradictions"`
}

type Engine struct{ cfg config }

func New(configJSON []byte) (*Engine, error) {
	var c config
	if err := json.Unmarshal(configJSON, &c); err != nil {
		return nil, err
	}
	return &Engine{cfg: c}, nil
}

// checkIndex orders checks in the UI. Lower = server-side (transport/IP/TLS),
// higher = client-side (browser environment, then live behavior). Rendered desc,
// so the dynamic behavioral checks sit on top and server transport at the bottom.
var checkIndex = map[string]int{
	// server-side transport / network / funnel (low)
	"ip_datacenter": 10, "tls_ua_vendor_mismatch": 12, "header_order_is_library": 14,
	"missing_client_hints": 20, "missing_sec_fetch": 21, "minimal_accept": 22,
	"funnel_bypass": 30, "cross_nav_inconsistency": 31,
	// client-side browser environment — deterministic once JS runs (mid)
	"implausible_hardware": 50, "software_webgl": 51, "no_plugins": 52, "languages_empty": 53,
	"permissions_contradiction": 54, "headless_ua": 55, "canvas_blocked": 56, "impossible_geometry": 57,
	"chrome_runtime_missing": 58, "navigator_webdriver": 60, "cdc_artifacts": 61, "selenium_attributes": 62,
	"playwright_bindings": 63, "phantom_globals": 64, "node_globals": 65, "cdp_runtime_enable": 66,
	"anti_tamper_patched": 67,
	// client-side live behavior — confidence grows as the user acts (high)
	"scroll_teleport": 82, "click_no_trail": 84, "behavior_scripted": 86, "clean_env_agentic_behavior": 88,
}

// confFor is the default confidence for a deterministic finding: 1.0 once a
// conclusion is reached (pass/fail/warn), 0 while there is nothing to conclude.
func confFor(status string) float64 {
	switch status {
	case "pass", "fail", "warn":
		return 1.0
	}
	return 0.0
}

// Score runs every rule against the SignalSet and produces a Report.
func (e *Engine) Score(ss schema.SignalSet) schema.Report {
	checks := []schema.Finding{}
	contradictions := []schema.Finding{}
	L := e.cfg.Bias
	var transportAccum, behaviorAccum float64
	fired := map[string]bool{}

	// fire records a signal check as fired and adds its log-odds weight.
	fire := func(id, value string) {
		def, ok := e.cfg.Signals[id]
		if !ok {
			return
		}
		fired[id] = true
		checks = append(checks, schema.Finding{
			ID: id, Title: def.Title, Explanation: def.Explanation,
			Status: def.Status, Weight: def.Weight, Value: value,
			Index: checkIndex[id], Confidence: 1.0,
		})
		switch id {
		case "behavior_scripted":
			behaviorAccum += def.Weight
		default:
			L += def.Weight
		}
	}
	record := func(id, status, value string) {
		def, ok := e.cfg.Signals[id]
		if !ok {
			return
		}
		checks = append(checks, schema.Finding{
			ID: id, Title: def.Title, Explanation: def.Explanation,
			Status: status, Weight: 0, Value: value,
			Index: checkIndex[id], Confidence: confFor(status),
		})
	}
	pass := func(id, value string) { record(id, "pass", value) }
	// recordConf records a non-weighted check with an explicit status+confidence
	// (the live behavioral checks, which cross thresholds as the user acts).
	recordConf := func(id, status, value string, conf float64) {
		def, ok := e.cfg.Signals[id]
		if !ok {
			return
		}
		checks = append(checks, schema.Finding{
			ID: id, Title: def.Title, Explanation: def.Explanation,
			Status: status, Weight: 0, Value: value,
			Index: checkIndex[id], Confidence: conf,
		})
	}
	// fireConf fires a check with an explicit status+confidence (adds weight).
	fireConf := func(id, status, value string, conf float64) {
		def, ok := e.cfg.Signals[id]
		if !ok {
			return
		}
		fired[id] = true
		checks = append(checks, schema.Finding{
			ID: id, Title: def.Title, Explanation: def.Explanation,
			Status: status, Weight: def.Weight, Value: value,
			Index: checkIndex[id], Confidence: conf,
		})
		switch id {
		case "behavior_scripted":
			behaviorAccum += def.Weight
		default:
			L += def.Weight
		}
	}
	// recordContra logs a contradiction rule that was evaluated and did NOT fire.
	recordContra := func(id, status, value string) {
		def, ok := e.cfg.Contradictions[id]
		if !ok {
			return
		}
		checks = append(checks, schema.Finding{
			ID: id, Title: def.Title, Explanation: def.Explanation,
			Status: status, Weight: 0, Value: value,
			Index: checkIndex[id], Confidence: confFor(status),
		})
	}
	passContra := func(id, value string) { recordContra(id, "pass", value) }
	fireContra := func(id, value string) {
		def, ok := e.cfg.Contradictions[id]
		if !ok {
			return
		}
		fired[id] = true
		f := schema.Finding{ID: id, Title: def.Title, Explanation: def.Explanation,
			Severity: def.Severity, Weight: def.Weight, Value: value, Status: "fail",
			Index: checkIndex[id], Confidence: 1.0}
		contradictions = append(contradictions, f)
		if id == "tls_ua_vendor_mismatch" || id == "header_order_is_library" {
			transportAccum += def.Weight
		} else {
			L += def.Weight
		}
	}

	// ---- Layer 1 rules ----
	if l1 := ss.Layer1; l1 != nil {
		af := l1.AutomationFlags
		if len(af.CdcArtifacts) > 0 {
			fire("cdc_artifacts", strings.Join(af.CdcArtifacts, ","))
		} else {
			pass("cdc_artifacts", "none")
		}
		if len(af.SeleniumAttributes) > 0 {
			fire("selenium_attributes", strings.Join(af.SeleniumAttributes, ","))
		} else {
			pass("selenium_attributes", "none")
		}
		if hasAny(af.InjectedGlobals, "_phantom", "__phantom", "callPhantom", "__nightmare") {
			fire("phantom_globals", strings.Join(af.InjectedGlobals, ","))
		} else {
			pass("phantom_globals", "none")
		}
		if len(af.PlaywrightBindings) > 0 {
			fire("playwright_bindings", strings.Join(af.PlaywrightBindings, ","))
		} else {
			pass("playwright_bindings", "none")
		}
		if af.NavigatorWebdriver {
			fire("navigator_webdriver", "true")
		} else {
			pass("navigator_webdriver", "false")
		}
		if len(af.NodeGlobals) > 0 {
			fire("node_globals", strings.Join(af.NodeGlobals, ","))
		} else {
			pass("node_globals", "none")
		}
		if af.CdpRuntimeEnableLeak {
			fire("cdp_runtime_enable", "true")
		} else {
			pass("cdp_runtime_enable", "not detected")
		}
		if af.AntiTamperPatched || af.WebdriverDescriptor == "patched-getter" || af.WebdriverDescriptor == "instance-override" {
			fire("anti_tamper_patched", af.WebdriverDescriptor)
		} else {
			pass("anti_tamper_patched", "native")
		}

		h := l1.Headless
		if h.UaHasHeadlessChrome {
			fire("headless_ua", "HeadlessChrome")
		} else {
			pass("headless_ua", "no HeadlessChrome token")
		}
		if h.PermissionsContradiction {
			fire("permissions_contradiction", "denied vs default")
		} else {
			pass("permissions_contradiction", "consistent")
		}
		if h.LanguagesEmpty {
			fire("languages_empty", "empty")
		} else {
			pass("languages_empty", "present")
		}
		if isChromeUA(env(l1)) {
			if h.PluginsLength == 0 && h.MimeTypesLength == 0 {
				fire("no_plugins", "0/0")
			} else {
				pass("no_plugins", itoa(h.PluginsLength)+"/"+itoa(h.MimeTypesLength))
			}
		}
		if l1.WebGL.IsSoftware {
			fire("software_webgl", l1.WebGL.UnmaskedRenderer)
		} else if l1.WebGL.Supported {
			pass("software_webgl", l1.WebGL.UnmaskedRenderer)
		}
		if l1.Hardware.HardwareConcurrency == 0 || l1.Hardware.HardwareConcurrency == 1 || l1.Hardware.HardwareConcurrency > 128 {
			fire("implausible_hardware", itoa(l1.Hardware.HardwareConcurrency))
		} else {
			pass("implausible_hardware", itoa(l1.Hardware.HardwareConcurrency)+" cores")
		}
		if l1.Canvas.Supported {
			if l1.Canvas.Blocked {
				fire("canvas_blocked", "blocked")
			} else {
				pass("canvas_blocked", "readable")
			}
		}
		s := l1.Screen
		if s.Width > 0 {
			if s.OuterWidth == 0 || s.OuterHeight == 0 || s.InnerWidth > s.Width {
				fire("impossible_geometry", "outer=0 or screen<inner")
			} else {
				pass("impossible_geometry", "consistent")
			}
		}
		if isChromeUA(env(l1)) {
			if !af.ChromeRuntimePresent {
				fire("chrome_runtime_missing", "absent")
			} else {
				pass("chrome_runtime_missing", "present")
			}
		}
	} else {
		// No client JS yet — surface the full checklist as pending so the
		// debug panel shows everything that will be evaluated.
		for _, id := range []string{"cdc_artifacts", "selenium_attributes", "phantom_globals",
			"playwright_bindings", "navigator_webdriver", "node_globals", "cdp_runtime_enable",
			"anti_tamper_patched", "headless_ua", "permissions_contradiction", "languages_empty",
			"no_plugins", "software_webgl", "implausible_hardware", "canvas_blocked",
			"impossible_geometry", "chrome_runtime_missing"} {
			record(id, "pending", "awaiting browser JS")
		}
	}

	// ---- Layer 2 rules ----
	if l2 := ss.Layer2; l2 != nil {
		chromium := strings.Contains(l2.UserAgent, "Chrome/") || l2.SecChUa != ""
		if chromium {
			if l2.SecChUa == "" {
				fire("missing_client_hints", "no Sec-CH-UA")
			} else {
				pass("missing_client_hints", l2.SecChUa)
			}
			if l2.SecFetchMode == "" {
				fire("missing_sec_fetch", "no Sec-Fetch-*")
			} else {
				pass("missing_sec_fetch", "mode="+l2.SecFetchMode)
			}
		}
		if isMinimalAccept(l2.Accept) || isMinimalEncoding(l2.AcceptEncoding) {
			fire("minimal_accept", l2.Accept+" | "+l2.AcceptEncoding)
		} else {
			pass("minimal_accept", "browser-like")
		}
		switch {
		case strings.HasPrefix(l2.HeaderOrderMatch, "library:"):
			fireContra("header_order_is_library", l2.HeaderOrderMatch)
		case l2.HeaderOrderMatch == "browser":
			passContra("header_order_is_library", "browser-shaped order")
		case l2.HeaderOrderMatch != "":
			recordContra("header_order_is_library", "unavailable", l2.HeaderOrderMatch)
		}
	}

	// ---- Layer 3 rules ----
	if l3 := ss.Layer3; l3 != nil && l3.Available {
		if l3.IsDatacenter {
			fire("ip_datacenter", "AS"+itoa(l3.ASN)+" "+l3.Org)
		} else if l3.ASN != 0 {
			pass("ip_datacenter", "AS"+itoa(l3.ASN)+" "+l3.Org)
		} else {
			record("ip_datacenter", "unavailable", "ASN unknown (no IP table loaded)")
		}
		// TLS stack vs UA vendor
		ua := ""
		if ss.Layer2 != nil {
			ua = ss.Layer2.UserAgent
		}
		claimsBrowser := strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Firefox/") || strings.Contains(ua, "Safari/")
		if l3.StackClass == "library" && claimsBrowser {
			fireContra("tls_ua_vendor_mismatch", l3.MatchedStack+" vs "+shortUA(ua))
		} else if claimsBrowser {
			passContra("tls_ua_vendor_mismatch", l3.StackClass+" stack ("+l3.JA4+")")
		}
	}

	// ---- Behavior / provenance rules (client-side, live) ----
	// These carry a confidence that starts at 0 (pending) and rises as the user
	// acts, crossing thresholds: pending → inconclusive → pass/fail.
	humanScroll := ss.ScrollToLink != nil && ss.ScrollToLink.AnyUserGesture
	if st := ss.ScrollToLink; st != nil && st.ReachedLink {
		if st.Teleport && !st.AnyUserGesture && st.LandedPixelAligned {
			fireConf("scroll_teleport", "fail", "no gesture, pixel-aligned", 1.0)
		} else if st.AnyUserGesture {
			recordConf("scroll_teleport", "pass", "human scroll gesture", 1.0)
		} else {
			recordConf("scroll_teleport", "inconclusive", "reached the link without a scroll", 0.4)
		}
	} else {
		recordConf("scroll_teleport", "pending", "awaiting scroll on the landing page", 0)
	}
	if lc := ss.LinkClick; lc != nil && lc.Occurred {
		// A trackpad/wheel scroll moves the page under a parked pointer, so a
		// genuine scroll gesture counts as approach provenance too.
		if lc.AtExactIntegerCenter {
			fireConf("click_no_trail", "fail", "click at exact element center", 1.0)
		} else if lc.ApproachPoints == 0 && lc.CoalescedNearby == 0 && !humanScroll {
			fireConf("click_no_trail", "fail", "no approach trail or scroll gesture", 1.0)
		} else {
			recordConf("click_no_trail", "pass", "human approach (pointer trail or scroll gesture)", 1.0)
		}
	} else {
		recordConf("click_no_trail", "pending", "awaiting the landing-page link click", 0)
	}
	// Typing cadence: confidence grows with observed keystrokes (~12 ⇒ certain),
	// so the check moves pending → inconclusive → pass/fail live as you type.
	{
		b := ss.Behavior
		totalKeys, noKeyFill, metronomic := 0, false, false
		reasons := []string{}
		if b != nil {
			for _, f := range b.Fields {
				totalKeys += f.Keydowns
				if f.FilledWithoutKeys && !f.AutofillPseudo {
					noKeyFill = true
					reasons = append(reasons, f.Name+":no-keys")
				}
				if f.Keydowns >= 4 && f.InterKeyStdev < 3 {
					metronomic = true
					reasons = append(reasons, f.Name+":metronomic")
				}
			}
		}
		subFast := b != nil && b.FillToSubmitMs > 0 && b.FillToSubmitMs < 400 && totalKeys > 0
		if subFast {
			reasons = append(reasons, "sub-400ms fill")
		}
		conf := float64(totalKeys) / 12.0
		if conf > 1 {
			conf = 1
		}
		switch {
		case noKeyFill:
			// values appeared with no keystrokes at all — a strong tell regardless of count
			fireConf("behavior_scripted", "fail", strings.Join(reasons, ","), 0.9)
		case totalKeys == 0:
			recordConf("behavior_scripted", "pending", "awaiting form typing", 0)
		case conf < 0.5:
			recordConf("behavior_scripted", "inconclusive",
				"not enough typing yet ("+itoa(totalKeys)+" keys, "+pct(conf)+" confidence)", conf)
		case metronomic || subFast:
			fireConf("behavior_scripted", "fail",
				strings.Join(reasons, ",")+" ("+pct(conf)+" confidence)", conf)
		default:
			recordConf("behavior_scripted", "pass",
				"human-like typing ("+itoa(totalKeys)+" keys, "+pct(conf)+" confidence)", conf)
		}
	}
	if tr := ss.Traps; tr != nil {
		if tr.DomHoneypotFilled {
			fireContra("funnel_bypass", "DOM honeypot field filled")
		}
	}

	// ---- Funnel rules ----
	if fn := ss.Funnel; fn != nil {
		if !fn.ReachedInOrder {
			fireContra("funnel_bypass", "reached out of order / deep-link")
		} else if !fired["funnel_bypass"] {
			passContra("funnel_bypass", "steps in order")
		}
		if len(fn.StepsSeen) >= 2 {
			if !fn.CrossNavConsistent {
				fireContra("cross_nav_inconsistency", "JA4/UA/IP changed between pages")
			} else {
				passContra("cross_nav_inconsistency", "stable JA4/UA/IP across pages")
			}
		} else {
			recordContra("cross_nav_inconsistency", "pending", "awaiting the next page")
		}
	}

	// ---- Cross-cutting: clean environment + non-human input ----
	envClean := ss.Layer1 != nil && !anyHardAutomation(fired) &&
		(ss.Layer3 == nil || ss.Layer3.StackClass != "library")
	nonHumanInput := fired["scroll_teleport"] || fired["click_no_trail"]
	if envClean && nonHumanInput {
		fireContra("clean_env_agentic_behavior", "pristine environment + injected input")
	}

	// ---- Apply caps ----
	L += math.Min(transportAccum, e.cfg.TransportContradictionCap)
	L += math.Min(behaviorAccum, e.cfg.BehaviorGroupCap)

	// ---- Aggregate ----
	prob := 1.0 / (1.0 + math.Exp(-L))
	// critical floor: any critical contradiction forces >= automated band
	for _, c := range contradictions {
		if c.Severity == "critical" || c.Weight >= e.cfg.CriticalFloorWeight {
			if prob < e.cfg.Bands.Automated+0.01 {
				prob = 0.95
			}
		}
	}
	band := "human"
	if prob >= e.cfg.Bands.Automated {
		band = "automated"
	} else if prob >= e.cfg.Bands.Human {
		band = "suspicious"
	}

	report := schema.Report{
		ReportVersion: e.cfg.ReportVersion,
		Funnel:        ss.Funnel,
		Score: schema.Score{
			AutomationProbability: round(prob, 4),
			Percent:               int(math.Round(prob * 100)),
			Band:                  band,
			AutomationType:        inferType(fired),
			Pass:                  band == "human",
			Confidence:            round(confidence(ss, fired), 3),
			WeightedEvidence:      round(L, 3),
		},
		Contradictions: contradictions,
		Checks:         sortChecks(checks),
		Coverage:       coverage(ss),
	}
	return report
}

func anyHardAutomation(fired map[string]bool) bool {
	for _, id := range []string{"cdc_artifacts", "selenium_attributes", "phantom_globals",
		"playwright_bindings", "navigator_webdriver", "node_globals", "cdp_runtime_enable",
		"headless_ua", "anti_tamper_patched"} {
		if fired[id] {
			return true
		}
	}
	return false
}

func inferType(fired map[string]bool) string {
	switch {
	case fired["tls_ua_vendor_mismatch"] || fired["header_order_is_library"]:
		return "scripted"
	case fired["headless_ua"]:
		return "headless"
	case fired["cdp_runtime_enable"] || fired["playwright_bindings"] || fired["cdc_artifacts"] ||
		fired["selenium_attributes"] || fired["navigator_webdriver"] || fired["funnel_bypass"]:
		return "agentic-cdp"
	case fired["clean_env_agentic_behavior"]:
		return "agentic-os"
	default:
		return "none"
	}
}

func confidence(ss schema.SignalSet, fired map[string]bool) float64 {
	c := 0.5
	for _, id := range []string{"cdp_runtime_enable", "tls_ua_vendor_mismatch", "headless_ua",
		"cdc_artifacts", "selenium_attributes"} {
		if fired[id] {
			c += 0.4
			break
		}
	}
	cov := 0.0
	if ss.Layer1 != nil {
		cov += 0.34
	}
	if ss.Layer2 != nil {
		cov += 0.33
	}
	if ss.Layer3 != nil && ss.Layer3.Available {
		cov += 0.33
	}
	c += cov * 0.2
	if c > 0.98 {
		c = 0.98
	}
	return c
}

func coverage(ss schema.SignalSet) map[string]string {
	cov := map[string]string{}
	set := func(k string, present bool) {
		if present {
			cov[k] = "captured"
		} else {
			cov[k] = "unavailable"
		}
	}
	set("layer1", ss.Layer1 != nil)
	set("layer2", ss.Layer2 != nil)
	set("layer3Tls", ss.Layer3 != nil && ss.Layer3.Available)
	set("layer3Ip", ss.Layer3 != nil && ss.Layer3.ASN != 0)
	set("behavior", ss.Behavior != nil || ss.LinkClick != nil || ss.ScrollToLink != nil)
	return cov
}

// helpers
func hasAny(list []string, want ...string) bool {
	m := map[string]bool{}
	for _, w := range want {
		m[w] = true
	}
	for _, s := range list {
		if m[s] {
			return true
		}
	}
	return false
}
func env(l1 *schema.Layer1) string {
	if l1 == nil {
		return ""
	}
	return l1.Environment.UserAgent
}
func isChromeUA(ua string) bool { return strings.Contains(ua, "Chrome/") }
func isMinimalAccept(a string) bool {
	return a == "" || a == "*/*"
}
func isMinimalEncoding(e string) bool {
	return e == "" || e == "identity" || (!strings.Contains(e, "gzip") && !strings.Contains(e, "br"))
}
func shortUA(ua string) string {
	if len(ua) > 40 {
		return ua[:40] + "…"
	}
	return ua
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
func round(f float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(f*p) / p
}
func sortChecks(c []schema.Finding) []schema.Finding {
	// Primary: index descending (client-side/behavioral on top, server at the
	// bottom). Secondary: severity of the status within an index band.
	order := map[string]int{"fail": 0, "warn": 1, "inconclusive": 2, "pending": 3, "unavailable": 4, "pass": 5}
	sort.SliceStable(c, func(i, j int) bool {
		if c[i].Index != c[j].Index {
			return c[i].Index > c[j].Index
		}
		return order[c[i].Status] < order[c[j].Status]
	})
	return c
}

// pct formats a 0..1 confidence as a whole percent.
func pct(f float64) string { return itoa(int(f*100+0.5)) + "%" }
