// Package ipasn classifies a client IP as datacenter/cloud vs. residential.
// Offline by default: a curated set of representative cloud CIDR ranges. Swap in
// a real IP-to-ASN source (MaxMind/IPinfo/Team Cymru) via Provider for production.
// See docs/06 §4.
package ipasn

import "net"

type Info struct {
	IP           string `json:"ip"`
	ASN          int    `json:"asn"`
	Org          string `json:"org"`
	IsDatacenter bool   `json:"isDatacenter"`
}

// Provider is an optional richer lookup (MaxMind/IPinfo/...). Nil ⇒ offline only.
type Provider interface {
	Lookup(ip net.IP) (Info, bool)
}

type entry struct {
	net      *net.IPNet
	provider string
	asn      int
}

type Classifier struct {
	ranges   []entry
	provider Provider
}

func New() *Classifier {
	c := &Classifier{}
	for _, r := range rawRanges {
		if _, n, err := net.ParseCIDR(r.cidr); err == nil {
			c.ranges = append(c.ranges, entry{net: n, provider: r.org, asn: r.asn})
		}
	}
	return c
}

// WithProvider adds a richer IP-to-ASN source, consulted before the static list.
func (c *Classifier) WithProvider(p Provider) *Classifier { c.provider = p; return c }

func (c *Classifier) Classify(ipStr string) Info {
	ip := net.ParseIP(hostOnly(ipStr))
	if ip == nil {
		return Info{IP: ipStr, Org: "unknown"}
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return Info{IP: ip.String(), Org: "private/local", IsDatacenter: false}
	}
	if c.provider != nil {
		if info, ok := c.provider.Lookup(ip); ok {
			return info
		}
	}
	for _, e := range c.ranges {
		if e.net.Contains(ip) {
			return Info{IP: ip.String(), ASN: e.asn, Org: e.provider, IsDatacenter: true}
		}
	}
	return Info{IP: ip.String(), Org: "residential/unknown", IsDatacenter: false}
}

func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

// Representative public cloud ranges. Not exhaustive — extend with a real provider.
var rawRanges = []struct {
	cidr string
	org  string
	asn  int
}{
	{"34.0.0.0/9", "GOOGLE-CLOUD", 396982},
	{"35.184.0.0/13", "GOOGLE-CLOUD", 396982},
	{"104.196.0.0/14", "GOOGLE-CLOUD", 396982},
	{"3.0.0.0/9", "AWS", 16509},
	{"18.128.0.0/9", "AWS", 16509},
	{"52.0.0.0/11", "AWS", 16509},
	{"54.144.0.0/12", "AWS", 14618},
	{"20.33.0.0/16", "MICROSOFT-AZURE", 8075},
	{"40.64.0.0/10", "MICROSOFT-AZURE", 8075},
	{"104.131.0.0/16", "DIGITALOCEAN", 14061},
	{"159.65.0.0/16", "DIGITALOCEAN", 14061},
	{"165.227.0.0/16", "DIGITALOCEAN", 14061},
	{"167.99.0.0/16", "DIGITALOCEAN", 14061},
	{"5.9.0.0/16", "HETZNER", 24940},
	{"88.99.0.0/16", "HETZNER", 24940},
	{"116.202.0.0/16", "HETZNER", 24940},
	{"168.119.0.0/16", "HETZNER", 24940},
	{"51.68.0.0/14", "OVH", 16276},
	{"137.74.0.0/16", "OVH", 16276},
	{"45.33.0.0/16", "LINODE", 63949},
	{"139.144.0.0/16", "LINODE", 63949},
	{"172.104.0.0/15", "LINODE", 63949},
	{"45.32.0.0/16", "VULTR", 20473},
	{"108.61.0.0/16", "VULTR", 20473},
	{"149.28.0.0/16", "VULTR", 20473},
}
