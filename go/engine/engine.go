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

// Score runs every rule against the SignalSet and produces a Report.
func (e *Engine) Score(ss schema.SignalSet) schema.Report {
	checks := []schema.Finding{}
	contradictions := []schema.Finding{}
	L := e.cfg.Bias
	var transportAccum, behaviorAccum float64
	fired := map[string]bool{}

	// fire records a signal check and adds its log-odds weight.
	fire := func(id, value string) {
		def, ok := e.cfg.Signals[id]
		if !ok {
			return
		}
		fired[id] = true
		checks = append(checks, schema.Finding{
			ID: id, Title: def.Title, Explanation: def.Explanation,
			Status: def.Status, Weight: def.Weight, Value: value,
		})
		switch id {
		case "behavior_scripted":
			behaviorAccum += def.Weight
		default:
			L += def.Weight
		}
	}
	pass := func(id, value string) {
		def, ok := e.cfg.Signals[id]
		if !ok {
			return
		}
		checks = append(checks, schema.Finding{
			ID: id, Title: def.Title, Explanation: def.Explanation,
			Status: "pass", Weight: 0, Value: value,
		})
	}
	fireContra := func(id, value string) {
		def, ok := e.cfg.Contradictions[id]
		if !ok {
			return
		}
		fired[id] = true
		f := schema.Finding{ID: id, Title: def.Title, Explanation: def.Explanation,
			Severity: def.Severity, Weight: def.Weight, Value: value, Status: "fail"}
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
		}
		if hasAny(af.InjectedGlobals, "_phantom", "__phantom", "callPhantom", "__nightmare") {
			fire("phantom_globals", strings.Join(af.InjectedGlobals, ","))
		}
		if len(af.PlaywrightBindings) > 0 {
			fire("playwright_bindings", strings.Join(af.PlaywrightBindings, ","))
		}
		if af.NavigatorWebdriver {
			fire("navigator_webdriver", "true")
		} else {
			pass("navigator_webdriver", "false")
		}
		if len(af.NodeGlobals) > 0 {
			fire("node_globals", strings.Join(af.NodeGlobals, ","))
		}
		if af.CdpRuntimeEnableLeak {
			fire("cdp_runtime_enable", "true")
		} else {
			pass("cdp_runtime_enable", "not detected")
		}
		if af.AntiTamperPatched || af.WebdriverDescriptor == "patched-getter" || af.WebdriverDescriptor == "instance-override" {
			fire("anti_tamper_patched", af.WebdriverDescriptor)
		}

		h := l1.Headless
		if h.UaHasHeadlessChrome {
			fire("headless_ua", "HeadlessChrome")
		}
		if h.PermissionsContradiction {
			fire("permissions_contradiction", "denied vs default")
		}
		if h.LanguagesEmpty {
			fire("languages_empty", "empty")
		}
		if h.PluginsLength == 0 && h.MimeTypesLength == 0 && isChromeUA(env(l1)) {
			fire("no_plugins", "0/0")
		}
		if l1.WebGL.IsSoftware {
			fire("software_webgl", l1.WebGL.UnmaskedRenderer)
		} else if l1.WebGL.Supported {
			pass("software_webgl", l1.WebGL.UnmaskedRenderer)
		}
		if l1.Hardware.HardwareConcurrency == 0 || l1.Hardware.HardwareConcurrency == 1 || l1.Hardware.HardwareConcurrency > 128 {
			fire("implausible_hardware", itoa(l1.Hardware.HardwareConcurrency))
		}
		if l1.Canvas.Supported && l1.Canvas.Blocked {
			fire("canvas_blocked", "blocked")
		}
		s := l1.Screen
		if s.Width > 0 && (s.OuterWidth == 0 || s.OuterHeight == 0 || s.InnerWidth > s.Width) {
			fire("impossible_geometry", "outer=0 or screen<inner")
		}
		if !af.ChromeRuntimePresent && isChromeUA(env(l1)) {
			fire("chrome_runtime_missing", "absent")
		}
	}

	// ---- Layer 2 rules ----
	if l2 := ss.Layer2; l2 != nil {
		chromium := strings.Contains(l2.UserAgent, "Chrome/") || l2.SecChUa != ""
		if chromium && l2.SecChUa == "" {
			fire("missing_client_hints", "no Sec-CH-UA")
		}
		if chromium && l2.SecFetchMode == "" {
			fire("missing_sec_fetch", "no Sec-Fetch-*")
		}
		if isMinimalAccept(l2.Accept) || isMinimalEncoding(l2.AcceptEncoding) {
			fire("minimal_accept", l2.Accept+" | "+l2.AcceptEncoding)
		}
		if strings.HasPrefix(l2.HeaderOrderMatch, "library:") {
			fireContra("header_order_is_library", l2.HeaderOrderMatch)
		}
	}

	// ---- Layer 3 rules ----
	if l3 := ss.Layer3; l3 != nil && l3.Available {
		if l3.IsDatacenter {
			fire("ip_datacenter", "AS"+itoa(l3.ASN)+" "+l3.Org)
		} else if l3.ASN != 0 {
			pass("ip_datacenter", "AS"+itoa(l3.ASN)+" "+l3.Org)
		}
		// TLS stack vs UA vendor
		ua := ""
		if ss.Layer2 != nil {
			ua = ss.Layer2.UserAgent
		}
		claimsBrowser := strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Firefox/") || strings.Contains(ua, "Safari/")
		if l3.StackClass == "library" && claimsBrowser {
			fireContra("tls_ua_vendor_mismatch", l3.MatchedStack+" vs "+shortUA(ua))
		} else if l3.StackClass == "browser" {
			pass("navigator_webdriver", "") // no-op guard; keeps engine tolerant
		}
	}

	// ---- Behavior / provenance rules ----
	if st := ss.ScrollToLink; st != nil && st.ReachedLink {
		if st.Teleport && !st.AnyUserGesture && st.LandedPixelAligned {
			fire("scroll_teleport", "no gesture, pixel-aligned")
		} else if st.AnyUserGesture {
			pass("scroll_teleport", "human scroll gesture")
		}
	}
	if lc := ss.LinkClick; lc != nil && lc.Occurred {
		if (lc.ApproachPoints == 0 && lc.CoalescedNearby == 0) || lc.AtExactIntegerCenter {
			fire("click_no_trail", "no approach trail / exact center")
		} else {
			pass("click_no_trail", "approached, off-center")
		}
	}
	if b := ss.Behavior; b != nil {
		scripted := false
		reasons := []string{}
		if b.FillToSubmitMs > 0 && b.FillToSubmitMs < 400 {
			scripted = true
			reasons = append(reasons, "sub-400ms fill")
		}
		for _, f := range b.Fields {
			if f.FilledWithoutKeys && !f.AutofillPseudo {
				scripted = true
				reasons = append(reasons, f.Name+":no-keys")
			}
			if f.Keydowns >= 4 && f.InterKeyStdev < 3 {
				scripted = true
				reasons = append(reasons, f.Name+":metronomic")
			}
		}
		if scripted {
			fire("behavior_scripted", strings.Join(reasons, ","))
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
		}
		if len(fn.StepsSeen) >= 2 && !fn.CrossNavConsistent {
			fireContra("cross_nav_inconsistency", "JA4/UA/IP changed between pages")
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
	order := map[string]int{"fail": 0, "warn": 1, "unavailable": 2, "pass": 3}
	sort.SliceStable(c, func(i, j int) bool {
		return order[c[i].Status] < order[c[j].Status]
	})
	return c
}
