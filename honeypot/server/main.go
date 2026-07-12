// Command honeypot is the reference integration: a self-hosted, TLS-terminating
// Go server that composes the detection libraries into the 3-step funnel.
// See docs/02.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"html/template"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	botdetector "github.com/bogdanripa/bot-detector"
	"github.com/bogdanripa/bot-detector/go/engine"
	"github.com/bogdanripa/bot-detector/go/httpcapture"
	"github.com/bogdanripa/bot-detector/go/ipasn"
	"github.com/bogdanripa/bot-detector/go/schema"
	"github.com/bogdanripa/bot-detector/go/tlscapture"
	"golang.org/x/crypto/acme/autocert"
)

var (
	capt        = tlscapture.New()
	classifier  = ipasn.New()
	eng         *engine.Engine
	webDir      = os.Getenv("BD_WEB_DIR")   // "" ⇒ embedded assets
	clientJS    = os.Getenv("BD_CLIENT_JS") // "" ⇒ embedded
	scoringPath = os.Getenv("BD_SCORING")   // "" ⇒ embedded
	addr        = envOr("BD_ADDR", ":8443")
	// enforceBand is the /test blocking threshold. "suspicious" (default) is
	// aggressive: block anything not clearly human. "automated" is conservative.
	enforceBand = envOr("BD_ENFORCE_BAND", "suspicious")
)

func bandRank(b string) int {
	switch b {
	case "automated":
		return 2
	case "suspicious":
		return 1
	}
	return 0
}

func main() {
	cfg, err := readScoring()
	must(err)
	eng, err = engine.New(cfg)
	must(err)

	// Optional: load the free iptoasn table for full IP coverage (BD_IPASN_TSV).
	if p := os.Getenv("BD_IPASN_TSV"); p != "" {
		if err := classifier.LoadTSV(p); err != nil {
			log.Printf("ipasn: could not load %s: %v (using built-in ranges)", p, err)
		} else {
			n4, n6 := classifier.Size()
			log.Printf("ipasn: loaded %d IPv4 + %d IPv6 ranges from %s", n4, n6, p)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	for _, mode := range []string{"test", "debug"} {
		mux.HandleFunc("/"+mode, funnelHandler(mode, "landing"))
		mux.HandleFunc("/"+mode+"/form", funnelHandler(mode, "form"))
		mux.HandleFunc("/"+mode+"/result", funnelHandler(mode, "result"))
		mux.HandleFunc("/"+mode+"/submit", submitHandler(mode))
	}
	mux.HandleFunc("/test/forbidden", handleForbidden)
	mux.HandleFunc("/api/analyze", handleAnalyze)
	mux.HandleFunc("/botdetect.js", handleClientJS)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	// http/1.1 only ⇒ reliable header-order capture. We terminate TLS ourselves
	// (no proxy in front) so the ClientHello reaches tlscapture.
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	domain := os.Getenv("BD_DOMAIN")
	certFile, keyFile := os.Getenv("BD_CERT"), os.Getenv("BD_KEY")
	switch {
	case domain != "":
		// Let's Encrypt, in-process (auto-issue + auto-renew). Needs :80 for the
		// HTTP-01 challenge and a writable cache dir.
		mgr := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(strings.Split(domain, ",")...),
			Cache:      autocert.DirCache(envOr("BD_CERT_CACHE", "certs")),
		}
		tlsCfg.GetCertificate = mgr.GetCertificate
		go func() {
			log.Printf("acme/redirect http listener on :80")
			log.Fatal(http.ListenAndServe(":80", mgr.HTTPHandler(http.HandlerFunc(redirectHTTPS))))
		}()
		log.Printf("TLS: Let's Encrypt autocert for %q", domain)
	case certFile != "" && keyFile != "":
		crt, err := tls.LoadX509KeyPair(certFile, keyFile)
		must(err)
		tlsCfg.Certificates = []tls.Certificate{crt}
		log.Printf("TLS: cert files %s / %s", certFile, keyFile)
	default:
		tlsCfg.Certificates = []tls.Certificate{selfSigned()}
		log.Printf("TLS: self-signed (dev)")
	}

	rawLn, err := net.Listen("tcp", addr)
	must(err)
	ln := capt.InstrumentListener(rawLn, tlsCfg)

	srv := &http.Server{
		Handler:     logMiddleware(mux),
		ReadTimeout: 15 * time.Second,
		IdleTimeout: 30 * time.Second,
	}
	go sweepSessions()
	log.Printf("honeypot listening on %s (https, http/1.1)", addr)
	log.Fatal(srv.Serve(ln))
}

func redirectHTTPS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
}

// ---- asset loading: embedded by default, disk override for dev ----

func readScoring() ([]byte, error) {
	if scoringPath != "" {
		return os.ReadFile(scoringPath)
	}
	return botdetector.ScoringJSON, nil
}
func readWeb(name string) ([]byte, error) {
	if webDir != "" {
		return os.ReadFile(webDir + "/" + name)
	}
	return botdetector.WebFS.ReadFile("honeypot/web/" + name)
}
func readClient() ([]byte, error) {
	if clientJS != "" {
		return os.ReadFile(clientJS)
	}
	return botdetector.ClientJS, nil
}

// ---- sessions ----

type snapshot struct {
	ja4, ua, ip string
}
type session struct {
	ID               string
	Mode             string
	CreatedMs        int64
	StepOrder        []string
	seen             map[string]bool
	Snapshots        []snapshot
	Layer2           *schema.Layer2
	Layer3           *schema.Layer3
	Layer1           *schema.Layer1
	ScrollToLink     *schema.ScrollToLink
	LinkClick        *schema.LinkClick
	Behavior         *schema.Behavior
	Traps            *schema.Traps
	Token            string
	TokenActivated   bool
	LastSecFetchUser string
	LastReferer      string
}

var (
	sessMu   sync.Mutex
	sessions = map[string]*session{}
)

func getSession(w http.ResponseWriter, r *http.Request, create bool) *session {
	sessMu.Lock()
	defer sessMu.Unlock()
	if c, err := r.Cookie("bd_sid"); err == nil {
		if s := sessions[c.Value]; s != nil {
			return s
		}
	}
	if !create {
		return nil
	}
	id := randHex(16)
	s := &session{ID: id, CreatedMs: nowMs(), seen: map[string]bool{}, Token: randHex(12)}
	sessions[id] = s
	http.SetCookie(w, &http.Cookie{Name: "bd_sid", Value: id, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	return s
}

func sweepSessions() {
	for range time.Tick(time.Minute) {
		cutoff := nowMs() - 10*60*1000
		sessMu.Lock()
		for id, s := range sessions {
			if s.CreatedMs < cutoff {
				delete(sessions, id)
			}
		}
		sessMu.Unlock()
	}
}

// captureConn records the connection-level Layer 2/3 for this navigation.
func captureConn(s *session, r *http.Request, step string) {
	order := capt.HeaderOrderFor(r.RemoteAddr)
	l2 := httpcapture.FromRequest(r, order)
	s.Layer2 = l2

	l3 := &schema.Layer3{IP: hostOnly(r.RemoteAddr)}
	info := classifier.Classify(r.RemoteAddr)
	l3.IP, l3.ASN, l3.Org, l3.IPType, l3.IsDatacenter = info.IP, info.ASN, info.Org, info.Type, info.IsDatacenter
	if t := capt.TLSFor(r.RemoteAddr); t != nil {
		l3.Available = true
		l3.TLSVersion, l3.JA3, l3.JA3Hash, l3.JA4 = t.Version, t.JA3, t.JA3Hash, t.JA4
		l3.ALPN, l3.StackClass, l3.MatchedStack = t.ALPN, t.StackClass, t.StackClass
	}
	s.Layer3 = l3

	if !s.seen[step] {
		s.seen[step] = true
		s.StepOrder = append(s.StepOrder, step)
	}
	s.Snapshots = append(s.Snapshots, snapshot{ja4: l3.JA4, ua: l2.UserAgent, ip: l3.IP})
	s.LastSecFetchUser = l2.SecFetchUser
	s.LastReferer = l2.Referer
}

func (s *session) funnel() *schema.FunnelState {
	f := &schema.FunnelState{StepsSeen: s.StepOrder}
	// in order: for whichever is the current furthest step, the prior must be seen
	f.ReachedInOrder = true
	if s.seen["form"] && !s.seen["landing"] {
		f.ReachedInOrder = false
	}
	if s.seen["result"] && !s.seen["form"] {
		f.ReachedInOrder = false
	}
	f.LinkClickWasTrusted = s.LinkClick != nil && s.LinkClick.IsTrusted && s.LinkClick.Occurred
	// cross-nav consistency across snapshots
	f.CrossNavConsistent = true
	var ja4, ua, ip string
	for _, sn := range s.Snapshots {
		if sn.ja4 != "" {
			if ja4 == "" {
				ja4 = sn.ja4
			} else if ja4 != sn.ja4 {
				f.CrossNavConsistent = false
			}
		}
		if sn.ua != "" {
			if ua == "" {
				ua = sn.ua
			} else if ua != sn.ua {
				f.CrossNavConsistent = false
			}
		}
		if sn.ip != "" {
			if ip == "" {
				ip = sn.ip
			} else if ip != sn.ip {
				f.CrossNavConsistent = false
			}
		}
	}
	if len(s.StepOrder) > 0 {
		f.TotalFunnelMs = nowMs() - s.CreatedMs
	}
	return f
}

func (s *session) signalSet() schema.SignalSet {
	return schema.SignalSet{
		Layer1: s.Layer1, Layer2: s.Layer2, Layer3: s.Layer3,
		ScrollToLink: s.ScrollToLink, LinkClick: s.LinkClick,
		Behavior: s.Behavior, Traps: s.Traps, Funnel: s.funnel(),
	}
}

// ---- handlers ----

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	servePage(w, "index.html", map[string]any{}, "")
}

func handleForbidden(w http.ResponseWriter, r *http.Request) {
	// Visited directly (after a client redirect) → 200 explanation page.
	serveForbidden(w, http.StatusOK, "visited")
}

// funnelHandler serves one step of the funnel for a given mode.
//   - test mode: server-side 403 when server-only signals are conclusively a bot;
//     the result step 403s when the full verdict is automated, else shows success.
//   - debug mode: never blocks; the result step renders the full report inline.
func funnelHandler(mode, step string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := getSession(w, r, true)
		s.Mode = mode
		captureConn(s, r, step)

		// TEST MODE — server-side gate (before any client JS runs).
		if mode == "test" && serverOnlyBot(s) {
			log.Printf("403 %s (server-only bot) ua=%q", r.URL.Path, short(r.Header.Get("User-Agent")))
			serveForbidden(w, http.StatusForbidden, "server-only")
			return
		}

		boot := map[string]any{"reportVersion": "1", "sessionId": s.ID, "step": step, "mode": mode,
			"enforceBand": enforceBand,
			"next":        "/" + mode + "/form", "submit": "/" + mode + "/submit", "forbidden": "/test/forbidden"}
		if step == "landing" {
			boot["funnelToken"] = s.Token
		}

		// DEBUG MODE — every page carries the cumulative report, rendered
		// server-side. On the first hit it holds server-only checks; it grows
		// as the client posts Layer 1 / provenance / behavior between pages.
		checksHTML := ""
		if mode == "debug" {
			report := eng.Score(s.signalSet())
			report.Step = step
			checksHTML = renderChecksHTML(report)
		}

		switch step {
		case "landing":
			servePage(w, "landing.html", boot, checksHTML)
		case "form":
			servePage(w, "form.html", boot, checksHTML)
		case "result":
			report := eng.Score(s.signalSet())
			report.Step = "result"
			report.GeneratedAtMs = nowMs()
			report.Raw = rawEcho(s)
			boot["report"] = report
			if mode == "test" {
				if bandRank(report.Score.Band) >= bandRank(enforceBand) {
					serveForbidden(w, http.StatusForbidden, "final-verdict")
					return
				}
				servePage(w, "test-result.html", boot, "")
			} else {
				servePage(w, "result.html", boot, checksHTML)
			}
		}
	}
}

func submitHandler(mode string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/"+mode+"/result", http.StatusSeeOther)
	}
}

// serverOnlyBot scores using only server-captured signals (no client Layer 1 /
// behavior). "Sure it's a bot" = the server-only verdict is automated.
func serverOnlyBot(s *session) bool {
	ss := schema.SignalSet{Layer2: s.Layer2, Layer3: s.Layer3, Funnel: s.funnel()}
	return bandRank(eng.Score(ss).Score.Band) >= bandRank(enforceBand)
}

func serveForbidden(w http.ResponseWriter, status int, reason string) {
	b, err := readWeb("forbidden.html")
	if err != nil {
		http.Error(w, "Forbidden — automated traffic is not allowed here.", status)
		return
	}
	boot := map[string]any{"reason": reason}
	bj, _ := json.Marshal(boot)
	html := strings.ReplaceAll(string(b), "__BD_BOOTSTRAP__", string(bj))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	w.Write([]byte(html))
}

func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var p schema.ClientPayload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&p); err != nil {
		http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
		return
	}
	sessMu.Lock()
	s := sessions[p.SessionID]
	sessMu.Unlock()
	if s == nil {
		http.Error(w, `{"error":"session_expired"}`, http.StatusNotFound)
		return
	}
	if p.Layer1 != nil {
		s.Layer1 = p.Layer1
	}
	if p.ScrollToLink != nil {
		s.ScrollToLink = p.ScrollToLink
	}
	if p.LinkClick != nil {
		s.LinkClick = p.LinkClick
		if p.LinkClick.IsTrusted && p.LinkClick.Occurred {
			s.TokenActivated = true
		}
	}
	if p.Behavior != nil {
		s.Behavior = p.Behavior
	}
	if p.Traps != nil {
		s.Traps = p.Traps
	}
	report := eng.Score(s.signalSet())
	report.Step = p.Step
	report.GeneratedAtMs = nowMs()
	writeJSON(w, report)
}

func handleClientJS(w http.ResponseWriter, r *http.Request) {
	b, err := readClient()
	if err != nil {
		http.Error(w, "client not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

// ---- server-rendered debug panel ----
// In debug mode every funnel page carries a "report so far" panel rendered
// server-side: /debug shows the server-only checks (headers, TLS, IP) and the
// list grows as the client JS posts Layer 1 / scroll / click / form behavior.

type checksView struct {
	Percent, ConfidencePct int
	Band, AutomationType   string
	BandColor, Icon        string
	Contradictions         []schema.Finding
	Captured, Pending      []string
}

// The panel is a fixed right sidebar on wide screens (it stays put while you
// scroll — the scroll IS part of the check). A custom checklist-icon button
// toggles it (state persists in localStorage), and the left edge is a drag
// handle to resize it (both wired in botdetect.js). Class names are bds-* to
// avoid colliding with the result page's own bd-* report styles.
var checksTmpl = template.Must(template.New("checks").Parse(`
<style>
  .bds-toggle { position: fixed; top: 12px; right: 12px; z-index: 10001; width: 40px; height: 40px;
              display: inline-flex; align-items: center; justify-content: center; padding: 0;
              border: 1px solid #8886; border-radius: 9px; background: #fff; color: #333;
              cursor: pointer; box-shadow: 0 1px 4px #0002; }
  .bds-toggle:hover { background: #f0f0f0; }
  @media (prefers-color-scheme: dark) { .bds-toggle { background: #222; color: #ddd; border-color: #fff3; }
              .bds-toggle:hover { background: #2c2c2c; } }
  .bds-side { position: fixed; top: 0; right: 0; bottom: 0; width: var(--bds-w, 400px); max-width: 92vw;
              box-sizing: border-box; overflow-y: auto; padding: 3.4rem 1.1rem 2rem;
              border-left: 1px solid #8884; background: #fafafa; font-size: .9rem; line-height: 1.45;
              transition: transform .2s ease; z-index: 10000; }
  @media (prefers-color-scheme: dark) { .bds-side { background: #161616; } }
  body.bds-collapsed .bds-side { transform: translateX(100%); }
  /* drag handle: grab the left edge to resize (botdetect.js) */
  .bds-side::before { content: ""; position: fixed; top: 0; bottom: 0; right: calc(var(--bds-w, 400px) - 5px);
              width: 10px; cursor: ew-resize; z-index: 10000; }
  body.bds-collapsed .bds-side::before { display: none; }
  .bds-side h2 { font-size: 1.02rem; margin: .2rem 0 .8rem; }
  .bds-banner { display: flex; align-items: center; gap: .8rem; border: 3px solid; border-radius: 10px;
              padding: .45rem .8rem; margin-bottom: .8rem; }
  .bds-pct { font-size: 1.9rem; font-weight: 800; }
  .bds-sub { color: #777; font-size: .78rem; }
  .bds-contra { padding-left: 1.1rem; margin: .4rem 0; }
  .bds-contra li { margin: .25rem 0; }
  .bds-checks { border-collapse: collapse; width: 100%; }
  .bds-checks td { border-top: 1px solid #8883; padding: .35rem .25rem; vertical-align: top; }
  .bds-badge { color: #fff; font-size: .62rem; font-weight: 700; padding: .1rem .35rem; border-radius: 4px; }
  .bds-exp { color: #888; font-size: .78rem; }
  .bds-val { font-family: ui-monospace, monospace; font-size: .7rem; color: #777;
              overflow-wrap: anywhere; width: 32%; }
  .bds-note { color: #888; font-size: .78rem; margin-bottom: 0; }
</style>
<aside class="bds-side">
  <h2>Live report — checks so far</h2>
  <div class="bds-banner" style="border-color:{{.BandColor}}">
    <div class="bds-pct" style="color:{{.BandColor}}">{{.Percent}}%</div>
    <div>
      <div style="font-weight:700;color:{{.BandColor}}">{{.Icon}} {{.Band}}</div>
      <div class="bds-sub">automation probability {{.Percent}}% &middot; confidence {{.ConfidencePct}}%{{if ne .AutomationType "none"}} &middot; type: <code>{{.AutomationType}}</code>{{end}}</div>
    </div>
  </div>
  {{if .Contradictions}}<ul class="bds-contra">
  {{range .Contradictions}}<li><b style="color:#cf222e">{{.Title}}</b> — {{.Explanation}}{{if .Value}} <code style="font-size:.75rem">{{.Value}}</code>{{end}}</li>{{end}}
  </ul>{{end}}
  <table class="bds-checks">
  {{range .Checks}}<tr>
    <td><span class="bds-badge" style="background:{{.Color}}">{{.Badge}}</span></td>
    <td><b>{{.Title}}</b><br><span class="bds-exp">{{.Explanation}}</span></td>
    <td class="bds-val">{{.Value}}</td>
  </tr>{{end}}
  </table>
  <p class="bds-note">Captured so far: {{range $i, $c := .Captured}}{{if $i}}, {{end}}<b>{{$c}}</b>{{end}}.
  {{if .Pending}}Still to come: {{range $i, $c := .Pending}}{{if $i}}, {{end}}{{$c}}{{end}} — continue through the pages and this list grows.{{end}}</p>
</aside>
<button class="bds-toggle" type="button" aria-label="Toggle detection checks panel" aria-expanded="true" title="Show/hide detection checks">
  <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <polyline points="2 6 3.5 7.5 6 4.5"/><line x1="9.5" y1="6" x2="21" y2="6"/>
    <polyline points="2 12 3.5 13.5 6 10.5"/><line x1="9.5" y1="12" x2="21" y2="12"/>
    <polyline points="2 18 3.5 19.5 6 16.5"/><line x1="9.5" y1="18" x2="21" y2="18"/>
  </svg>
</button>`))

// Badge/Color are derived per finding for the template.
type findingView struct {
	schema.Finding
	Badge, Color string
}

func renderChecksHTML(report schema.Report) string {
	bandColor := map[string]string{"human": "#1a7f37", "suspicious": "#bf8700", "automated": "#cf222e"}
	icon := map[string]string{"human": "✓", "suspicious": "⚠", "automated": "✗"}
	labels := []struct{ key, label string }{
		{"layer2", "HTTP headers"}, {"layer3Tls", "TLS fingerprint"}, {"layer3Ip", "IP/ASN"},
		{"layer1", "browser environment (JS)"}, {"behavior", "behavior (scroll/click/typing)"},
	}
	var captured, pending []string
	for _, l := range labels {
		if report.Coverage[l.key] == "captured" {
			captured = append(captured, l.label)
		} else {
			pending = append(pending, l.label)
		}
	}
	v := struct {
		checksView
		Checks []findingView
	}{
		checksView: checksView{
			Percent:        report.Score.Percent,
			ConfidencePct:  int(math.Round(report.Score.Confidence * 100)),
			Band:           strings.ToUpper(report.Score.Band),
			AutomationType: report.Score.AutomationType,
			BandColor:      bandColor[report.Score.Band],
			Icon:           icon[report.Score.Band],
			Contradictions: report.Contradictions,
			Captured:       captured,
			Pending:        pending,
		},
	}
	badge := map[string]string{"pass": "PASS", "warn": "WARN", "fail": "FAIL", "unavailable": "N/A", "pending": "PENDING"}
	col := map[string]string{"pass": "#1a7f37", "warn": "#bf8700", "fail": "#cf222e", "unavailable": "#888", "pending": "#57606a"}
	for _, c := range report.Checks {
		b, cl := badge[c.Status], col[c.Status]
		if b == "" {
			b, cl = c.Status, "#555"
		}
		v.Checks = append(v.Checks, findingView{Finding: c, Badge: b, Color: cl})
	}
	var buf bytes.Buffer
	if err := checksTmpl.Execute(&buf, v); err != nil {
		log.Printf("checks template: %v", err)
		return ""
	}
	return buf.String()
}

func rawEcho(s *session) map[string]any {
	return map[string]any{"layer1": s.Layer1, "layer2": s.Layer2, "layer3": s.Layer3,
		"scrollToLink": s.ScrollToLink, "linkClick": s.LinkClick, "behavior": s.Behavior, "traps": s.Traps}
}

func servePage(w http.ResponseWriter, name string, boot map[string]any, checksHTML string) {
	b, err := readWeb(name)
	if err != nil {
		http.Error(w, "page not found: "+name, http.StatusInternalServerError)
		return
	}
	bj, _ := json.Marshal(boot)
	html := strings.ReplaceAll(string(b), "__BD_BOOTSTRAP__", string(bj))
	html = strings.ReplaceAll(html, "__BD_CHECKS__", checksHTML)
	for _, k := range []string{"next", "submit", "forbidden"} {
		if v, ok := boot[k].(string); ok {
			html = strings.ReplaceAll(html, "__"+strings.ToUpper(k)+"__", v)
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'")
	w.Write([]byte(html))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		if !strings.HasPrefix(r.URL.Path, "/botdetect") && !strings.HasPrefix(r.URL.Path, "/app") {
			log.Printf("%s %s ua=%q", r.Method, r.URL.Path, short(r.Header.Get("User-Agent")))
		}
	})
}

// ---- helpers ----

func selfSigned() tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost", "app.localtest.me"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	crt, err := tls.X509KeyPair(certPEM, keyPEM)
	must(err)
	return crt
}

func randHex(nbytes int) string {
	b := make([]byte, nbytes)
	rand.Read(b)
	const hexd = "0123456789abcdef"
	out := make([]byte, nbytes*2)
	for i, x := range b {
		out[i*2] = hexd[x>>4]
		out[i*2+1] = hexd[x&0xf]
	}
	return string(out)
}
func nowMs() int64 { return time.Now().UnixMilli() }
func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}
func short(s string) string {
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}
func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
