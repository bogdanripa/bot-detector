// Command honeypot is the reference integration: a self-hosted, TLS-terminating
// Go server that composes the detection libraries into the 3-step funnel.
// See docs/02.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bogdanripa/bot-detector/go/engine"
	"github.com/bogdanripa/bot-detector/go/httpcapture"
	"github.com/bogdanripa/bot-detector/go/ipasn"
	"github.com/bogdanripa/bot-detector/go/schema"
	"github.com/bogdanripa/bot-detector/go/tlscapture"
)

var (
	capt        = tlscapture.New()
	classifier  = ipasn.New()
	eng         *engine.Engine
	webDir      = envOr("BD_WEB_DIR", "honeypot/web")
	clientJS    = envOr("BD_CLIENT_JS", "packages/client/botdetect.js")
	scoringPath = envOr("BD_SCORING", "config/scoring.json")
	addr        = envOr("BD_ADDR", ":8443")
)

func main() {
	cfg, err := os.ReadFile(scoringPath)
	must(err)
	eng, err = engine.New(cfg)
	must(err)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleLanding)
	mux.HandleFunc("/step-2", handleForm)
	mux.HandleFunc("/result", handleResult)
	mux.HandleFunc("/api/analyze", handleAnalyze)
	mux.HandleFunc("/api/submit", handleSubmit)
	mux.HandleFunc("/botdetect.js", handleClientJS)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{selfSigned()},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"}, // http/1.1 only ⇒ reliable header-order capture
	}
	rawLn, err := net.Listen("tcp", addr)
	must(err)
	ln := capt.InstrumentListener(rawLn, tlsCfg)

	srv := &http.Server{
		Handler:     logMiddleware(mux),
		ReadTimeout: 15 * time.Second,
		IdleTimeout: 30 * time.Second,
		ConnContext: nil,
	}
	go sweepSessions()
	log.Printf("honeypot listening on https://localhost%s  (self-signed TLS, http/1.1)", addr)
	log.Fatal(srv.Serve(ln))
}

// ---- sessions ----

type snapshot struct {
	ja4, ua, ip string
}
type session struct {
	ID               string
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
	l3.IP, l3.ASN, l3.Org, l3.IsDatacenter = info.IP, info.ASN, info.Org, info.IsDatacenter
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

func handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s := getSession(w, r, true)
	captureConn(s, r, "landing")
	boot := map[string]any{"reportVersion": "1", "sessionId": s.ID, "step": "landing",
		"funnelToken": s.Token, "captureMode": "self-hosted"}
	servePage(w, "landing.html", boot)
}

func handleForm(w http.ResponseWriter, r *http.Request) {
	s := getSession(w, r, true)
	captureConn(s, r, "form")
	boot := map[string]any{"reportVersion": "1", "sessionId": s.ID, "step": "form"}
	servePage(w, "form.html", boot)
}

func handleResult(w http.ResponseWriter, r *http.Request) {
	s := getSession(w, r, true)
	captureConn(s, r, "result")
	report := eng.Score(s.signalSet())
	report.Step = "result"
	report.GeneratedAtMs = nowMs()
	report.Raw = rawEcho(s)
	boot := map[string]any{"reportVersion": "1", "sessionId": s.ID, "step": "result", "report": report}
	servePage(w, "result.html", boot)
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

func handleSubmit(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/result", http.StatusSeeOther)
}

func handleClientJS(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(clientJS)
	if err != nil {
		http.Error(w, "client not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

func rawEcho(s *session) map[string]any {
	return map[string]any{"layer1": s.Layer1, "layer2": s.Layer2, "layer3": s.Layer3,
		"scrollToLink": s.ScrollToLink, "linkClick": s.LinkClick, "behavior": s.Behavior, "traps": s.Traps}
}

func servePage(w http.ResponseWriter, name string, boot map[string]any) {
	b, err := os.ReadFile(webDir + "/" + name)
	if err != nil {
		http.Error(w, "page not found: "+name, http.StatusInternalServerError)
		return
	}
	bj, _ := json.Marshal(boot)
	html := strings.Replace(string(b), "__BD_BOOTSTRAP__", string(bj), 1)
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
