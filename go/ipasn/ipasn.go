// Package ipasn classifies a client IP as hosting/datacenter vs. residential/ISP.
//
// Lookups are blazing fast: the table is a sorted array of IP ranges searched by
// binary search (O(log n), no allocations) — ~tens of nanoseconds even over the
// full internet routing table. Data is pluggable:
//
//   - Built-in: a curated set of cloud ranges, compiled in, zero-config.
//   - LoadTSV: the free, public-domain iptoasn.com dataset (ip2asn-v4/combined,
//     .tsv or .tsv.gz) for full coverage of every routed IP. No license.
//
// A MaxMind .mmdb can be plugged in via Provider if you have a license, but the
// iptoasn table gives the same speed for free. See docs/06 §4.
package ipasn

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type Info struct {
	IP           string `json:"ip"`
	ASN          int    `json:"asn"`
	Org          string `json:"org"`
	Type         string `json:"type"` // "hosting" | "isp" | "mobile" | "unknown" | "private"
	IsDatacenter bool   `json:"isDatacenter"`
}

// Provider is an optional richer lookup (e.g. a MaxMind .mmdb reader).
type Provider interface {
	Lookup(ip netip.Addr) (Info, bool)
}

type v4Range struct {
	start, end uint32
	asn        int
	org        string
}
type v6Range struct {
	start, end netip.Addr
	asn        int
	org        string
}

type Classifier struct {
	mu       sync.RWMutex
	v4       []v4Range // sorted by start
	v6       []v6Range // sorted by start
	provider Provider
}

func New() *Classifier {
	c := &Classifier{}
	c.loadBuiltin()
	return c
}

func (c *Classifier) WithProvider(p Provider) *Classifier { c.provider = p; return c }

// Classify resolves an IP (or host:port) to its ASN/org and hosting type.
func (c *Classifier) Classify(ipStr string) Info {
	addr, err := netip.ParseAddr(hostOnly(ipStr))
	if err != nil {
		return Info{IP: ipStr, Type: "unknown", Org: "unknown"}
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return Info{IP: addr.String(), Type: "private", Org: "private/local"}
	}
	if c.provider != nil {
		if info, ok := c.provider.Lookup(addr); ok {
			return info
		}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	var asn int
	var org string
	if addr.Is4() {
		v := ip4ToU32(addr)
		i := sort.Search(len(c.v4), func(i int) bool { return c.v4[i].end >= v })
		if i < len(c.v4) && c.v4[i].start <= v && v <= c.v4[i].end {
			asn, org = c.v4[i].asn, c.v4[i].org
		}
	} else {
		i := sort.Search(len(c.v6), func(i int) bool { return c.v6[i].end.Compare(addr) >= 0 })
		if i < len(c.v6) && c.v6[i].start.Compare(addr) <= 0 && addr.Compare(c.v6[i].end) <= 0 {
			asn, org = c.v6[i].asn, c.v6[i].org
		}
	}
	if asn == 0 && org == "" {
		return Info{IP: addr.String(), Type: "unknown", Org: "unknown"}
	}
	typ := classifyOrg(asn, org)
	return Info{IP: addr.String(), ASN: asn, Org: org, Type: typ, IsDatacenter: typ == "hosting"}
}

// LoadTSV replaces the table from an iptoasn-format file:
//
//	range_start<TAB>range_end<TAB>AS_number<TAB>country<TAB>AS_description
//
// Accepts .tsv or .tsv.gz. Call once at startup.
func (c *Classifier) LoadTSV(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}
	var v4 []v4Range
	var v6 []v6Range
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 5 {
			continue
		}
		asn, _ := strconv.Atoi(f[2])
		if asn == 0 {
			continue // AS0 = not routed
		}
		org := f[4]
		s, err1 := netip.ParseAddr(f[0])
		e, err2 := netip.ParseAddr(f[1])
		if err1 != nil || err2 != nil {
			continue
		}
		if s.Is4() && e.Is4() {
			v4 = append(v4, v4Range{start: ip4ToU32(s), end: ip4ToU32(e), asn: asn, org: org})
		} else if s.Is6() && e.Is6() {
			v6 = append(v6, v6Range{start: s, end: e, asn: asn, org: org})
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	sort.Slice(v4, func(i, j int) bool { return v4[i].start < v4[j].start })
	sort.Slice(v6, func(i, j int) bool { return v6[i].start.Compare(v6[j].start) < 0 })

	c.mu.Lock()
	c.v4, c.v6 = v4, v6
	c.mu.Unlock()
	return nil
}

// Size reports the number of loaded ranges (v4, v6).
func (c *Classifier) Size() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.v4), len(c.v6)
}

// ---- classification of an ASN/org into a network type ----

var hostingASNs = map[int]bool{
	16509: true, 14618: true, 8987: true, // AWS
	15169: true, 396982: true, 19527: true, // Google
	8075: true, 8068: true, // Azure/Microsoft
	16276: true, 35540: true, // OVH
	24940: true, 213230: true, // Hetzner
	14061: true,              // DigitalOcean
	20473: true, 64515: true, // Vultr
	63949: true, 48447: true, // Linode
	20940: true,              // Akamai
	12876: true,              // Scaleway
	31898: true,              // Oracle
	51167: true,              // Contabo
	9009:  true, 60068: true, // M247
	45102: true, 37963: true, // Alibaba
	132203: true, 45090: true, // Tencent
	60781:  true,               // LeaseWeb
	62240:  true,               // Clouvider
	3223:   true,               // Voxility
	199524: true, 202422: true, // G-Core
	49981:  true, // WorldStream
	53667:  true, // FranTech / BuyVM
	36352:  true, // ColoCrossing
	40676:  true, // Psychz
	46844:  true, // Sharktech
	29802:  true, // Hivelocity
	8100:   true, // QuadraNet
	51852:  true, // Private Layer
	212238: true, // Datacamp / CDN77
}

var hostingKeywords = []string{
	"amazon", "aws", "google", "cloud", "microsoft", "azure", "ovh", "hetzner",
	"digitalocean", "linode", "akamai", "vultr", "choopa", "scaleway", "oracle",
	"alibaba", "tencent", "contabo", "leaseweb", "m247", "hosting", "datacenter",
	"data center", "vps", "dedicated server", "colo", "server", "host",
	"clouvider", "voxility", "g-core", "gcore", "worldstream", "buyvm", "frantech",
	"colocation", "vpn", "proxy", "cdn",
}
var mobileKeywords = []string{"mobile", "wireless", "cellular", "gsm", "lte"}

func classifyOrg(asn int, org string) string {
	if hostingASNs[asn] {
		return "hosting"
	}
	lo := strings.ToLower(org)
	for _, k := range hostingKeywords {
		if strings.Contains(lo, k) {
			return "hosting"
		}
	}
	for _, k := range mobileKeywords {
		if strings.Contains(lo, k) {
			return "mobile"
		}
	}
	return "isp"
}

// ---- helpers ----

func ip4ToU32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func hostOnly(s string) string {
	if i := strings.LastIndexByte(s, ':'); i > 0 && strings.Count(s, ":") == 1 {
		return s[:i] // host:port (v4)
	}
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 0 {
			return s[1:i] // [v6]:port
		}
	}
	return s
}

// loadBuiltin seeds a zero-config table of representative cloud ranges (v4).
func (c *Classifier) loadBuiltin() {
	type raw struct {
		cidr string
		asn  int
		org  string
	}
	ranges := []raw{
		{"34.0.0.0/9", 396982, "GOOGLE-CLOUD"}, {"35.184.0.0/13", 396982, "GOOGLE-CLOUD"},
		{"104.196.0.0/14", 396982, "GOOGLE-CLOUD"},
		{"3.0.0.0/9", 16509, "AWS"}, {"18.128.0.0/9", 16509, "AWS"}, {"52.0.0.0/11", 16509, "AWS"},
		{"54.144.0.0/12", 14618, "AWS"},
		{"20.33.0.0/16", 8075, "MICROSOFT-AZURE"}, {"40.64.0.0/10", 8075, "MICROSOFT-AZURE"},
		{"104.131.0.0/16", 14061, "DIGITALOCEAN"}, {"159.65.0.0/16", 14061, "DIGITALOCEAN"},
		{"165.227.0.0/16", 14061, "DIGITALOCEAN"}, {"167.99.0.0/16", 14061, "DIGITALOCEAN"},
		{"5.9.0.0/16", 24940, "HETZNER"}, {"88.99.0.0/16", 24940, "HETZNER"},
		{"116.202.0.0/16", 24940, "HETZNER"}, {"168.119.0.0/16", 24940, "HETZNER"},
		{"51.68.0.0/14", 16276, "OVH"}, {"137.74.0.0/16", 16276, "OVH"},
		{"45.33.0.0/16", 63949, "LINODE"}, {"139.144.0.0/16", 63949, "LINODE"},
		{"172.104.0.0/15", 63949, "LINODE"},
		{"45.32.0.0/16", 20473, "VULTR"}, {"108.61.0.0/16", 20473, "VULTR"}, {"149.28.0.0/16", 20473, "VULTR"},
	}
	var v4 []v4Range
	for _, r := range ranges {
		p, err := netip.ParsePrefix(r.cidr)
		if err != nil {
			continue
		}
		lo := p.Masked().Addr()
		bits := p.Bits()
		start := ip4ToU32(lo)
		end := start | (0xffffffff >> bits)
		v4 = append(v4, v4Range{start: start, end: end, asn: r.asn, org: r.org})
	}
	sort.Slice(v4, func(i, j int) bool { return v4[i].start < v4[j].start })
	c.v4 = v4
}
