package engine

import (
	"os"
	"testing"

	"github.com/bogdanripa/bot-detector/go/schema"
)

func newEngine(t *testing.T) *Engine {
	t.Helper()
	cfg, err := os.ReadFile("../../config/scoring.json")
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return e
}

func chromeUA() string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36"
}

func TestCleanBrowserIsHuman(t *testing.T) {
	e := newEngine(t)
	ss := schema.SignalSet{
		Layer1: &schema.Layer1{
			AutomationFlags: schema.AutomationFlags{ChromeRuntimePresent: true, WebdriverDescriptor: "native"},
			Headless:        schema.Headless{PluginsLength: 3, MimeTypesLength: 2},
			WebGL:           schema.WebGL{Supported: true, UnmaskedRenderer: "ANGLE (NVIDIA)"},
			Screen:          schema.Screen{Width: 2560, Height: 1440, InnerWidth: 1280, InnerHeight: 720, OuterWidth: 1280, OuterHeight: 800},
			Hardware:        schema.Hardware{HardwareConcurrency: 8, DeviceMemory: 8},
			Environment:     schema.Environment{UserAgent: chromeUA()},
		},
		Layer2: &schema.Layer2{UserAgent: chromeUA(), SecChUa: `"Chromium";v="124"`, SecFetchMode: "navigate",
			Accept: "text/html,application/xhtml+xml", AcceptEncoding: "gzip, deflate, br", HeaderOrderMatch: "browser"},
		Layer3: &schema.Layer3{Available: true, StackClass: "browser", ASN: 7922, Org: "COMCAST"},
	}
	r := e.Score(ss)
	if r.Score.Band != "human" {
		t.Fatalf("clean browser should be human, got %s (%.2f)", r.Score.Band, r.Score.AutomationProbability)
	}
}

func TestTLSVsUAMismatchIsAutomated(t *testing.T) {
	e := newEngine(t)
	ss := schema.SignalSet{
		Layer2: &schema.Layer2{UserAgent: chromeUA(), Accept: "*/*", HeaderOrderMatch: "library:curl"},
		Layer3: &schema.Layer3{Available: true, StackClass: "library", MatchedStack: "library"},
	}
	r := e.Score(ss)
	if r.Score.Band != "automated" {
		t.Fatalf("tls/ua mismatch should be automated, got %s (%.2f)", r.Score.Band, r.Score.AutomationProbability)
	}
	if !hasContra(r, "tls_ua_vendor_mismatch") {
		t.Fatalf("expected tls_ua_vendor_mismatch contradiction")
	}
}

func TestWebdriverIsAutomated(t *testing.T) {
	e := newEngine(t)
	ss := schema.SignalSet{Layer1: &schema.Layer1{
		AutomationFlags: schema.AutomationFlags{NavigatorWebdriver: true, WebdriverDescriptor: "native", ChromeRuntimePresent: true},
		Environment:     schema.Environment{UserAgent: chromeUA()},
	}}
	r := e.Score(ss)
	if r.Score.Band == "human" {
		t.Fatalf("navigator.webdriver=true should not be human")
	}
}

func TestScrollTeleportFlagged(t *testing.T) {
	e := newEngine(t)
	// clean env + teleport scroll ⇒ agentic contradiction
	ss := schema.SignalSet{
		Layer1: &schema.Layer1{AutomationFlags: schema.AutomationFlags{ChromeRuntimePresent: true, WebdriverDescriptor: "native"},
			Environment: schema.Environment{UserAgent: chromeUA()}},
		Layer3:       &schema.Layer3{Available: true, StackClass: "browser"},
		ScrollToLink: &schema.ScrollToLink{ReachedLink: true, Teleport: true, AnyUserGesture: false, LandedPixelAligned: true},
	}
	r := e.Score(ss)
	if !hasContra(r, "clean_env_agentic_behavior") {
		t.Fatalf("expected clean_env_agentic_behavior, got band=%s", r.Score.Band)
	}
}

func TestHumanScrollNotFlagged(t *testing.T) {
	e := newEngine(t)
	ss := schema.SignalSet{
		ScrollToLink: &schema.ScrollToLink{ReachedLink: true, Teleport: false, AnyUserGesture: true, WheelCount: 8},
	}
	r := e.Score(ss)
	for _, c := range r.Checks {
		if c.ID == "scroll_teleport" && c.Status == "fail" {
			t.Fatalf("human wheel scroll should not fire scroll_teleport")
		}
	}
}

func cleanLayer1() *schema.Layer1 {
	return &schema.Layer1{
		AutomationFlags: schema.AutomationFlags{ChromeRuntimePresent: true, WebdriverDescriptor: "native"},
		Headless:        schema.Headless{PluginsLength: 3, MimeTypesLength: 2},
		WebGL:           schema.WebGL{Supported: true, UnmaskedRenderer: "ANGLE (NVIDIA)"},
		Screen:          schema.Screen{Width: 2560, Height: 1440, InnerWidth: 1280, InnerHeight: 720, OuterWidth: 1280, OuterHeight: 800},
		Hardware:        schema.Hardware{HardwareConcurrency: 8, DeviceMemory: 8},
		Environment:     schema.Environment{UserAgent: chromeUA()},
	}
}

// An open DevTools panel fires the Runtime.enable bait on a real human — that
// alone must not convict.
func TestDevToolsOpenAloneIsNotAutomated(t *testing.T) {
	e := newEngine(t)
	l1 := cleanLayer1()
	l1.AutomationFlags.CdpRuntimeEnableLeak = true
	r := e.Score(schema.SignalSet{Layer1: l1})
	if r.Score.Band == "automated" {
		t.Fatalf("CDP leak alone should not be automated, got %s (%.2f)", r.Score.Band, r.Score.AutomationProbability)
	}
}

// Enter/Space on a focused link produces a trusted click at the element center
// with no pointer trail — a human input path, not an injected click.
func TestKeyboardLinkActivationIsHuman(t *testing.T) {
	e := newEngine(t)
	ss := schema.SignalSet{
		Layer1: cleanLayer1(),
		LinkClick: &schema.LinkClick{Occurred: true, IsTrusted: true, KeyboardActivated: true,
			AtExactIntegerCenter: true, ApproachPoints: 0},
	}
	r := e.Score(ss)
	for _, c := range r.Checks {
		if c.ID == "click_no_trail" && c.Status == "fail" {
			t.Fatalf("keyboard activation should not fire click_no_trail")
		}
	}
	if hasContra(r, "clean_env_agentic_behavior") {
		t.Fatalf("keyboard activation should not trigger clean_env_agentic_behavior")
	}
	if r.Score.Band != "human" {
		t.Fatalf("keyboard user should be human, got %s (%.2f)", r.Score.Band, r.Score.AutomationProbability)
	}
}

func TestUntrustedClickIsFlagged(t *testing.T) {
	e := newEngine(t)
	ss := schema.SignalSet{
		Layer1:    cleanLayer1(),
		LinkClick: &schema.LinkClick{Occurred: true, IsTrusted: false, ApproachPoints: 5},
	}
	r := e.Score(ss)
	found := false
	for _, c := range r.Checks {
		if c.ID == "click_no_trail" && c.Status == "fail" {
			found = true
		}
	}
	if !found {
		t.Fatalf("isTrusted=false click should fire click_no_trail")
	}
}

func hasContra(r schema.Report, id string) bool {
	for _, c := range r.Contradictions {
		if c.ID == id {
			return true
		}
	}
	return false
}
