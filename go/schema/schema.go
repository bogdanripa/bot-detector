// Package schema defines the wire types shared between the client library,
// the honeypot server, and the scoring engine. See docs/03.
package schema

// ClientPayload is what @botdetect/client POSTs to /api/analyze, per step.
type ClientPayload struct {
	ReportVersion string        `json:"reportVersion"`
	SessionID     string        `json:"sessionId"`
	Step          string        `json:"step"` // "landing" | "form" | "result"
	CollectedAtMs int64         `json:"collectedAtMs"`
	Layer1        *Layer1       `json:"layer1,omitempty"`
	ScrollToLink  *ScrollToLink `json:"scrollToLink,omitempty"`
	LinkClick     *LinkClick    `json:"linkClick,omitempty"`
	Behavior      *Behavior     `json:"behavior,omitempty"`
	Traps         *Traps        `json:"traps,omitempty"`
	ClickPattern  *ClickPattern `json:"clickPattern,omitempty"`
	Typing        *Typing       `json:"typing,omitempty"`
}

// Layer1 — client-asserted browser-environment signals (claims, checked by the engine).
type Layer1 struct {
	AutomationFlags AutomationFlags `json:"automationFlags"`
	Headless        Headless        `json:"headless"`
	WebGL           WebGL           `json:"webgl"`
	Canvas          Canvas          `json:"canvas"`
	Hardware        Hardware        `json:"hardware"`
	Screen          Screen          `json:"screen"`
	Locale          Locale          `json:"locale"`
	Environment     Environment     `json:"environment"`
}

type AutomationFlags struct {
	NavigatorWebdriver   bool     `json:"navigatorWebdriver"`
	InjectedGlobals      []string `json:"injectedGlobals"`
	CdcArtifacts         []string `json:"cdcArtifacts"`
	SeleniumAttributes   []string `json:"seleniumAttributes"`
	PlaywrightBindings   []string `json:"playwrightBindings"`
	NodeGlobals          []string `json:"nodeGlobals"`
	ChromeRuntimePresent bool     `json:"chromeRuntimePresent"`
	WebdriverDescriptor  string   `json:"webdriverDescriptor"` // "native" | "patched-getter" | "instance-override"
	CdpRuntimeEnableLeak bool     `json:"cdpRuntimeEnableLeak"`
	AntiTamperPatched    bool     `json:"antiTamperPatched"`
}

type Headless struct {
	UaHasHeadlessChrome      bool `json:"uaHasHeadlessChrome"`
	PluginsLength            int  `json:"pluginsLength"`
	MimeTypesLength          int  `json:"mimeTypesLength"`
	LanguagesEmpty           bool `json:"languagesEmpty"`
	PermissionsContradiction bool `json:"permissionsContradiction"`
}

type WebGL struct {
	Supported        bool   `json:"supported"`
	UnmaskedVendor   string `json:"unmaskedVendor"`
	UnmaskedRenderer string `json:"unmaskedRenderer"`
	IsSoftware       bool   `json:"isSoftware"`
}

type Canvas struct {
	Supported bool `json:"supported"`
	Blocked   bool `json:"blocked"`
}

type Hardware struct {
	HardwareConcurrency int `json:"hardwareConcurrency"`
	DeviceMemory        int `json:"deviceMemory"`
	MaxTouchPoints      int `json:"maxTouchPoints"`
}

type Screen struct {
	Width       int `json:"width"`
	Height      int `json:"height"`
	InnerWidth  int `json:"innerWidth"`
	InnerHeight int `json:"innerHeight"`
	OuterWidth  int `json:"outerWidth"`
	OuterHeight int `json:"outerHeight"`
}

type Locale struct {
	IntlTimeZone string   `json:"intlTimeZone"`
	Language     string   `json:"language"`
	Languages    []string `json:"languages"`
}

type Environment struct {
	UserAgent string `json:"userAgent"`
	Vendor    string `json:"vendor"`
	Platform  string `json:"platform"`
}

// ScrollToLink — scroll provenance to the below-fold Page-1 link (docs/14 §4.2).
type ScrollToLink struct {
	ReachedLink        bool `json:"reachedLink"`
	WheelCount         int  `json:"wheelCount"`
	WheelFractional    bool `json:"wheelFractional"`
	TouchScroll        bool `json:"touchScroll"`
	KeyboardScroll     bool `json:"keyboardScroll"`
	ScrollbarDrag      bool `json:"scrollbarDrag"`
	AnyUserGesture     bool `json:"anyUserGesture"`
	Teleport           bool `json:"teleport"`
	LandedPixelAligned bool `json:"landedPixelAligned"`
	ScrollEvents       int  `json:"scrollEvents"`
}

// LinkClick — input provenance of the Page-1 link click (docs/14 §4).
type LinkClick struct {
	Occurred                  bool `json:"occurred"`
	IsTrusted                 bool `json:"isTrusted"`
	ApproachPoints            int  `json:"approachPoints"`
	CoalescedNearby           int  `json:"coalescedNearby"`
	AtExactIntegerCenter      bool `json:"atExactIntegerCenter"`
	KeyboardActivated         bool `json:"keyboardActivated"` // click event with detail=0: Enter/Space on a focused link
	DwellBeforeClickMs        int  `json:"dwellBeforeClickMs"`
	SourceCapabilitiesPresent bool `json:"sourceCapabilitiesPresent"`
}

// Typing — keystroke dynamics accumulated across ALL pages in the session (not
// per-form), so the signal keeps growing as the user uses a multi-page app.
type Typing struct {
	Keys          int      `json:"keys"`          // printing keystrokes (session total)
	EditKeys      int      `json:"editKeys"`      // non-printing edit keys (Shift/Tab/Backspace/arrows/Ctrl)
	EditKeyKinds  []string `json:"editKeyKinds"`  // distinct edit-key groups seen
	InterKeyStdev float64  `json:"interKeyStdev"` // cadence variance over the session
	Intervals     int      `json:"intervals"`     // number of inter-key intervals measured
	NoKeyFill     bool     `json:"noKeyFill"`     // a text field got a value with no keystrokes (bot .value set)
}

// ClickPattern — WHERE clicks land within their target, accumulated across all
// clicks in the session (cross-page). Bots often click a fixed relative offset
// (e.g. always dead-center) — low variance across many clicks is the tell.
type ClickPattern struct {
	Count            int     `json:"count"`            // clicks observed
	StdevX           float64 `json:"stdevX"`           // stdev of relative x-offset (0..1) within targets
	StdevY           float64 `json:"stdevY"`           // stdev of relative y-offset
	MeanX            float64 `json:"meanX"`            // mean relative x-offset
	MeanY            float64 `json:"meanY"`            // mean relative y-offset
	ExactCenterCount int     `json:"exactCenterCount"` // clicks landing at exact 50%/50%
}

// Behavior — form-fill dynamics (docs/04 §2.8). Dynamics only, never field values.
type Behavior struct {
	DurationMs            int         `json:"durationMs"`
	FillToSubmitMs        int         `json:"fillToSubmitMs"`
	Fields                []FormField `json:"fields"`
	FocusOrder            []string    `json:"focusOrder"`
	TabKeyUsed            bool        `json:"tabKeyUsed"`
	MouseMoveEvents       int         `json:"mouseMoveEvents"`
	StraightSegmentsRatio float64     `json:"straightSegmentsRatio"`
	GlobalInterKeyStdev   float64     `json:"globalInterKeyStdev"`
}

type FormField struct {
	Name              string  `json:"name"`
	Keydowns          int     `json:"keydowns"`
	InterKeyStdev     float64 `json:"interKeyStdev"`
	Backspaces        int     `json:"backspaces"`
	PasteEvents       int     `json:"pasteEvents"`
	FilledWithoutKeys bool    `json:"filledWithoutKeys"`
	AutofillPseudo    bool    `json:"autofillPseudo"`
}

// Traps — active honeypot outcomes (docs/14 §8B).
type Traps struct {
	DomHoneypotFilled    bool `json:"domHoneypotFilled"`
	VisionTrapTripped    bool `json:"visionTrapTripped"`
	SmoothPursuitTracked bool `json:"smoothPursuitTracked"`
	FillFasterThanHuman  bool `json:"fillFasterThanHuman"`
}

// ---- Server-captured signals ----

// Layer2 — HTTP signals captured server-side (docs/05).
type Layer2 struct {
	UserAgent        string   `json:"userAgent"`
	SecChUa          string   `json:"secChUa"`
	SecFetchMode     string   `json:"secFetchMode"`
	SecFetchSite     string   `json:"secFetchSite"`
	SecFetchUser     string   `json:"secFetchUser"`
	Accept           string   `json:"accept"`
	AcceptEncoding   string   `json:"acceptEncoding"`
	AcceptLanguage   string   `json:"acceptLanguage"`
	HeaderOrder      []string `json:"headerOrder"`
	HeaderOrderMatch string   `json:"headerOrderMatch"` // "browser" | "library:<name>" | "unknown" | ""
	Referer          string   `json:"referer"`
}

// Layer3 — transport signals captured server-side (docs/06).
type Layer3 struct {
	Available    bool     `json:"available"`
	TLSVersion   string   `json:"tlsVersion"`
	JA3          string   `json:"ja3"`
	JA3Hash      string   `json:"ja3Hash"`
	JA4          string   `json:"ja4"`
	ALPN         []string `json:"alpn"`
	StackClass   string   `json:"stackClass"` // "browser" | "library" | "unknown"
	MatchedStack string   `json:"matchedStack"`
	IP           string   `json:"ip"`
	ASN          int      `json:"asn"`
	Org          string   `json:"org"`
	IPType       string   `json:"ipType"` // "hosting" | "isp" | "mobile" | "unknown" | "private"
	IsDatacenter bool     `json:"isDatacenter"`
}

// FunnelState — cross-navigation funnel integrity (docs/02 §3).
type FunnelState struct {
	StepsSeen           []string `json:"stepsSeen"`
	ReachedInOrder      bool     `json:"reachedInOrder"`
	LinkClickWasTrusted bool     `json:"linkClickWasTrusted"`
	CrossNavConsistent  bool     `json:"crossNavConsistent"`
	TotalFunnelMs       int64    `json:"totalFunnelMs"`
}

// SignalSet — the (possibly partial) input to the engine.
type SignalSet struct {
	Layer1       *Layer1
	Layer2       *Layer2
	Layer3       *Layer3
	ScrollToLink *ScrollToLink
	LinkClick    *LinkClick
	Behavior     *Behavior
	Traps        *Traps
	Funnel       *FunnelState
	ClickPattern *ClickPattern
	Typing       *Typing
}

// ---- Report (engine output, docs/03 §5) ----

type Report struct {
	ReportVersion  string            `json:"reportVersion"`
	Step           string            `json:"step"`
	GeneratedAtMs  int64             `json:"generatedAtMs"`
	Funnel         *FunnelState      `json:"funnel,omitempty"`
	Score          Score             `json:"score"`
	Contradictions []Finding         `json:"contradictions"`
	Checks         []Finding         `json:"checks"`
	Coverage       map[string]string `json:"coverage"`
	Raw            map[string]any    `json:"raw,omitempty"`
	// Allow is set (with a human reason) when the client is on the allowlist —
	// a verified good bot or a trusted User-Agent — and enforcement is bypassed.
	Allow string `json:"allow,omitempty"`
}

type Score struct {
	AutomationProbability float64 `json:"automationProbability"`
	Percent               int     `json:"percent"`
	Band                  string  `json:"band"`
	AutomationType        string  `json:"automationType"`
	Pass                  bool    `json:"pass"`
	Confidence            float64 `json:"confidence"`
	WeightedEvidence      float64 `json:"weightedEvidence"`
}

type Finding struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Explanation string  `json:"explanation"`
	Severity    string  `json:"severity,omitempty"`
	Status      string  `json:"status,omitempty"` // pass|fail|warn|pending|inconclusive|unavailable
	Weight      float64 `json:"weight"`
	Value       string  `json:"value,omitempty"`
	// Index orders checks in the UI: lower = server-side (transport/IP/TLS),
	// higher = client-side (browser env, then live behavior). Shown desc.
	Index int `json:"index"`
	// Confidence (0..1) is how much evidence backs this check's status. It is
	// 1.0 for deterministic checks and grows with observations for the live
	// behavioral ones, which start pending and cross thresholds as the user acts.
	Confidence float64 `json:"confidence"`
	Group      string  `json:"group,omitempty"`
}
