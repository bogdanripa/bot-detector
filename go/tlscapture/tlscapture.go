// Package tlscapture terminates TLS itself so it can fingerprint the client's
// ClientHello (→ JA3/JA4) and capture the decrypted request's header order.
// It works only when this process owns the socket. See docs/06.
package tlscapture

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

// TLSInfo is the parsed ClientHello fingerprint.
type TLSInfo struct {
	Version    string
	JA3        string
	JA3Hash    string
	JA4        string
	ALPN       []string
	CipherN    int
	ExtN       int
	HasGREASE  bool
	StackClass string // "browser" | "library" | "unknown"
}

type Capture struct {
	mu        sync.Mutex
	tlsByAddr map[string]*TLSInfo
	hdrByAddr map[string][]string
}

func New() *Capture {
	return &Capture{tlsByAddr: map[string]*TLSInfo{}, hdrByAddr: map[string][]string{}}
}

func (c *Capture) TLSFor(remoteAddr string) *TLSInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tlsByAddr[remoteAddr]
}

func (c *Capture) HeaderOrderFor(remoteAddr string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hdrByAddr[remoteAddr]
}

func (c *Capture) storeTLS(addr string, t *TLSInfo) {
	c.mu.Lock()
	c.tlsByAddr[addr] = t
	c.mu.Unlock()
}
func (c *Capture) storeHdr(addr string, order []string) {
	c.mu.Lock()
	c.hdrByAddr[addr] = order
	c.mu.Unlock()
}
func (c *Capture) forget(addr string) {
	c.mu.Lock()
	delete(c.tlsByAddr, addr)
	delete(c.hdrByAddr, addr)
	c.mu.Unlock()
}

// InstrumentListener wraps a raw TCP listener: it sniffs each connection's
// ClientHello, terminates TLS, and tees the decrypted request head. The returned
// listener yields plain (already-TLS-terminated) conns — serve it with an
// http.Server that has NO TLSConfig set.
func (c *Capture) InstrumentListener(raw net.Listener, cfg *tls.Config) net.Listener {
	return &capListener{Listener: raw, cfg: cfg, cap: c}
}

type capListener struct {
	net.Listener
	cfg *tls.Config
	cap *Capture
}

func (l *capListener) Accept() (net.Conn, error) {
	rc, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	addr := rc.RemoteAddr().String()
	sniff := &helloSniffer{Conn: rc, cap: l.cap, addr: addr}
	tlsConn := tls.Server(sniff, l.cfg)
	return &headSniffer{Conn: tlsConn, cap: l.cap, addr: addr}, nil
}

// helloSniffer tees the first TLS record (the ClientHello) off the raw socket.
type helloSniffer struct {
	net.Conn
	cap  *Capture
	addr string
	buf  []byte
	done bool
}

func (s *helloSniffer) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	if !s.done && n > 0 {
		s.buf = append(s.buf, p[:n]...)
		if len(s.buf) >= 5 {
			recLen := int(binary.BigEndian.Uint16(s.buf[3:5])) + 5
			if s.buf[0] == 0x16 && len(s.buf) >= recLen {
				if info := parseClientHello(s.buf[:recLen]); info != nil {
					s.cap.storeTLS(s.addr, info)
				}
				s.done = true
				s.buf = nil
			} else if s.buf[0] != 0x16 || len(s.buf) > 16384 {
				s.done = true
				s.buf = nil
			}
		}
	}
	return n, err
}

func (s *helloSniffer) Close() error { return s.Conn.Close() }

// headSniffer tees decrypted bytes until the request head ends, for header order.
type headSniffer struct {
	net.Conn
	cap  *Capture
	addr string
	buf  []byte
	done bool
}

func (s *headSniffer) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	if !s.done && n > 0 {
		s.buf = append(s.buf, p[:n]...)
		if i := indexCRLFCRLF(s.buf); i >= 0 {
			s.cap.storeHdr(s.addr, parseHeaderOrder(s.buf[:i]))
			s.done = true
			s.buf = nil
		} else if len(s.buf) > 32768 {
			s.done = true
			s.buf = nil
		}
	}
	return n, err
}

func (s *headSniffer) Close() error {
	s.cap.forget(s.addr)
	return s.Conn.Close()
}

func indexCRLFCRLF(b []byte) int {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n' {
			return i
		}
	}
	return -1
}

func parseHeaderOrder(head []byte) []string {
	lines := strings.Split(string(head), "\r\n")
	var order []string
	for i, ln := range lines {
		if i == 0 {
			continue // request line
		}
		if c := strings.IndexByte(ln, ':'); c > 0 {
			order = append(order, strings.ToLower(strings.TrimSpace(ln[:c])))
		}
	}
	return order
}

// ---- ClientHello parsing → JA3/JA4 ----

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a }

func parseClientHello(rec []byte) *TLSInfo {
	defer func() { _ = recover() }() // never crash the connection on a malformed hello
	if len(rec) < 5 || rec[0] != 0x16 {
		return nil
	}
	b := rec[5:] // handshake
	if len(b) < 4 || b[0] != 0x01 {
		return nil
	}
	p := 4                 // skip handshake type + 3-byte length
	legacyVer := u16(b, p) // client_version (JA3 SSLVersion)
	p += 2
	p += 32 // random
	if p >= len(b) {
		return nil
	}
	sidLen := int(b[p])
	p += 1 + sidLen
	if p+2 > len(b) {
		return nil
	}
	csLen := int(u16(b, p))
	p += 2
	var ciphers []uint16
	hasGREASE := false
	for i := 0; i+1 < csLen && p+1 < len(b); i += 2 {
		v := u16(b, p+i)
		if isGREASE(v) {
			hasGREASE = true
			continue
		}
		ciphers = append(ciphers, v)
	}
	p += csLen
	if p >= len(b) {
		return nil
	}
	compLen := int(b[p])
	p += 1 + compLen
	if p+2 > len(b) {
		return finish(legacyVer, ciphers, nil, nil, nil, nil, nil, false, hasGREASE)
	}
	extTotal := int(u16(b, p))
	p += 2
	end := p + extTotal
	var extTypes, curves, points, sigAlgs []uint16
	var alpn []string
	sni := false
	var supportedVersions []uint16
	for p+4 <= end && p+4 <= len(b) {
		et := u16(b, p)
		el := int(u16(b, p+2))
		p += 4
		if p+el > len(b) {
			break
		}
		data := b[p : p+el]
		if isGREASE(et) {
			hasGREASE = true
		} else {
			extTypes = append(extTypes, et)
		}
		switch et {
		case 0x0000: // SNI
			sni = true
		case 0x000a: // supported_groups
			curves = readU16List(data, 2)
		case 0x000b: // ec_point_formats
			if len(data) >= 1 {
				points = readBytesAsU16(data[1 : 1+min(int(data[0]), len(data)-1)])
			}
		case 0x000d: // signature_algorithms
			sigAlgs = readU16List(data, 2)
		case 0x0010: // ALPN
			alpn = readALPN(data)
		case 0x002b: // supported_versions
			if len(data) >= 1 {
				supportedVersions = readBytesAsU16List(data[1:])
			}
		}
		p += el
	}
	return finish(legacyVer, ciphers, extTypes, curves, points, sigAlgs, alpn, sni, hasGREASE, supportedVersions...)
}

func finish(legacyVer uint16, ciphers, exts, curves, points, sigAlgs []uint16, alpn []string, sni, grease bool, supported ...uint16) *TLSInfo {
	// JA3
	ja3 := fmt.Sprintf("%d,%s,%s,%s,%s", legacyVer,
		joinU16(ciphers, "-"), joinU16(exts, "-"), joinU16(curves, "-"), joinU16(points, "-"))
	sum := md5.Sum([]byte(ja3))
	ja3hash := hex.EncodeToString(sum[:])

	// Effective TLS version for JA4 (highest non-GREASE from supported_versions, else legacy)
	ver := legacyVer
	for _, v := range supported {
		if !isGREASE(v) && v > ver {
			ver = v
		}
	}
	verStr := "00"
	switch ver {
	case 0x0304:
		verStr = "13"
	case 0x0303:
		verStr = "12"
	case 0x0302:
		verStr = "11"
	case 0x0301:
		verStr = "10"
	}
	sniChar := "i"
	if sni {
		sniChar = "d"
	}
	alpnCode := "00"
	if len(alpn) > 0 && len(alpn[0]) > 0 {
		a := alpn[0]
		alpnCode = string(a[0]) + string(a[len(a)-1])
	}
	ja4a := fmt.Sprintf("t%s%s%02d%02d%s", verStr, sniChar, cap99(len(ciphers)), cap99(len(exts)), alpnCode)

	cipherHex := sortedHex(ciphers)
	ja4b := sha12(strings.Join(cipherHex, ","))

	// exts for ja4_c exclude SNI(0) and ALPN(16), sorted; then "_" + sig algs in order
	var extForC []uint16
	for _, e := range exts {
		if e == 0x0000 || e == 0x0010 {
			continue
		}
		extForC = append(extForC, e)
	}
	extHex := sortedHex(extForC)
	sigHex := hexList(sigAlgs) // in-order
	ja4c := sha12(strings.Join(extHex, ",") + "_" + strings.Join(sigHex, ","))
	ja4 := ja4a + "_" + ja4b + "_" + ja4c

	stack := "unknown"
	if grease && len(exts) >= 8 {
		stack = "browser"
	} else if !grease && len(ciphers) <= 40 {
		stack = "library"
	}

	return &TLSInfo{
		Version: tlsVerName(ver), JA3: ja3, JA3Hash: ja3hash, JA4: ja4,
		ALPN: alpn, CipherN: len(ciphers), ExtN: len(exts), HasGREASE: grease, StackClass: stack,
	}
}

func tlsVerName(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	}
	return fmt.Sprintf("0x%04x", v)
}

// small helpers
func u16(b []byte, i int) uint16 {
	if i+1 >= len(b) {
		return 0
	}
	return binary.BigEndian.Uint16(b[i:])
}
func readU16List(data []byte, offset int) []uint16 {
	if len(data) < offset {
		return nil
	}
	body := data[offset:]
	return readBytesAsU16List(body)
}
func readBytesAsU16List(body []byte) []uint16 {
	var out []uint16
	for i := 0; i+1 < len(body); i += 2 {
		v := binary.BigEndian.Uint16(body[i:])
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}
func readBytesAsU16(body []byte) []uint16 {
	var out []uint16
	for _, x := range body {
		out = append(out, uint16(x))
	}
	return out
}
func readALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	p := 2 // ALPN protocol list length
	var out []string
	for p < len(data) {
		l := int(data[p])
		p++
		if p+l > len(data) {
			break
		}
		out = append(out, string(data[p:p+l]))
		p += l
	}
	return out
}
func joinU16(v []uint16, sep string) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprintf("%d", x)
	}
	return strings.Join(parts, sep)
}
func sortedHex(v []uint16) []string {
	cp := append([]uint16(nil), v...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return hexList(cp)
}
func hexList(v []uint16) []string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = fmt.Sprintf("%04x", x)
	}
	return out
}
func sha12(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:12]
}
func cap99(n int) int {
	if n > 99 {
		return 99
	}
	return n
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
