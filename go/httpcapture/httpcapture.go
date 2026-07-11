// Package httpcapture extracts Layer-2 HTTP signals (header values + order) from a
// request. Header values work from any *http.Request; header *order* must be
// supplied from a raw read (see go/tlscapture). See docs/05.
package httpcapture

import (
	"net/http"
	"strings"

	"github.com/bogdanripa/bot-detector/go/schema"
)

// FromRequest builds Layer2 from a request. headerOrder is the raw, lower-cased
// header-name sequence captured off the connection (nil ⇒ order unavailable).
func FromRequest(r *http.Request, headerOrder []string) *schema.Layer2 {
	l2 := &schema.Layer2{
		UserAgent:      r.Header.Get("User-Agent"),
		SecChUa:        r.Header.Get("Sec-Ch-Ua"),
		SecFetchMode:   r.Header.Get("Sec-Fetch-Mode"),
		SecFetchSite:   r.Header.Get("Sec-Fetch-Site"),
		SecFetchUser:   r.Header.Get("Sec-Fetch-User"),
		Accept:         r.Header.Get("Accept"),
		AcceptEncoding: r.Header.Get("Accept-Encoding"),
		AcceptLanguage: r.Header.Get("Accept-Language"),
		Referer:        r.Header.Get("Referer"),
		HeaderOrder:    headerOrder,
	}
	l2.HeaderOrderMatch = matchHeaderOrder(headerOrder)
	return l2
}

// HasWebBotAuth reports whether the request carries Web Bot Auth signature headers
// (RFC 9421). Full verification against the key directory is left for production.
func HasWebBotAuth(r *http.Request) bool {
	return r.Header.Get("Signature") != "" && r.Header.Get("Signature-Agent") != ""
}

// matchHeaderOrder classifies a captured header-name sequence.
func matchHeaderOrder(order []string) string {
	if len(order) == 0 {
		return ""
	}
	// Drop the leading "host" for comparison stability.
	seq := make([]string, 0, len(order))
	for _, h := range order {
		if h == "host" {
			continue
		}
		seq = append(seq, h)
	}
	joined := strings.Join(seq, ",")

	// Known HTTP-library shapes (very few headers, no sec-*).
	hasSec := false
	for _, h := range seq {
		if strings.HasPrefix(h, "sec-") {
			hasSec = true
			break
		}
	}
	switch {
	case joined == "user-agent,accept":
		return "library:curl"
	case strings.HasPrefix(joined, "user-agent,accept-encoding") && len(seq) <= 3:
		return "library:go-nethttp"
	case strings.HasPrefix(joined, "accept-encoding,user-agent") && len(seq) <= 3:
		return "library:go-nethttp"
	case containsInOrder(seq, "user-agent", "accept-encoding", "accept", "connection") && !hasSec:
		return "library:python-requests"
	case len(seq) <= 3 && !hasSec:
		return "library:unknown"
	}
	// Browser-like: has sec-fetch / sec-ch-ua and a rich header set.
	if hasSec || len(seq) >= 6 {
		return "browser"
	}
	return "unknown"
}

func containsInOrder(seq []string, want ...string) bool {
	i := 0
	for _, s := range seq {
		if i < len(want) && s == want[i] {
			i++
		}
	}
	return i == len(want)
}
