package ipasn

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltinAndPrivate(t *testing.T) {
	c := New()
	if got := c.Classify("34.1.2.3"); got.Type != "hosting" || !got.IsDatacenter {
		t.Fatalf("34.1.2.3 should be hosting, got %+v", got)
	}
	if got := c.Classify("192.168.1.5"); got.Type != "private" {
		t.Fatalf("private IP should be private, got %+v", got)
	}
	if got := c.Classify("198.51.100.7"); got.Type != "unknown" {
		t.Fatalf("unlisted IP should be unknown (not residential), got %+v", got)
	}
	if got := c.Classify("not-an-ip"); got.Type != "unknown" {
		t.Fatalf("garbage should be unknown, got %+v", got)
	}
}

func TestLoadTSV(t *testing.T) {
	// synthetic iptoasn-format table: start,end,asn,cc,org
	tsv := "" +
		"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
		"73.0.0.0\t73.255.255.255\t7922\tUS\tCOMCAST-7922\n" + // residential ISP
		"5.9.0.0\t5.9.255.255\t24940\tDE\tHETZNER-AS\n" + // hosting by ASN
		"203.0.113.0\t203.0.113.255\t64500\tAU\tExample Broadband Pty\n" + // isp by name
		"212.100.0.0\t212.100.255.255\t65001\tNL\tSuper Cloud Hosting BV\n" // hosting by keyword
	path := filepath.Join(t.TempDir(), "ip2asn.tsv")
	if err := os.WriteFile(path, []byte(tsv), 0o644); err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.LoadTSV(path); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip, typ string
		dc      bool
		asn     int
	}{
		{"73.100.5.9", "isp", false, 7922},       // Comcast → residential
		{"5.9.100.200", "hosting", true, 24940},  // Hetzner ASN → hosting
		{"203.0.113.9", "isp", false, 64500},     // named broadband → isp
		{"212.100.50.1", "hosting", true, 65001}, // "Cloud Hosting" keyword → hosting
		{"9.9.9.9", "unknown", false, 0},         // not in table → unknown
	}
	for _, tc := range cases {
		got := c.Classify(tc.ip)
		if got.Type != tc.typ || got.IsDatacenter != tc.dc || got.ASN != tc.asn {
			t.Errorf("Classify(%s) = %+v; want type=%s dc=%v asn=%d", tc.ip, got, tc.typ, tc.dc, tc.asn)
		}
	}
}

// BenchmarkClassify proves the lookup is O(log n) fast over a large table.
func BenchmarkClassify(b *testing.B) {
	// build ~250k contiguous /24 ranges → a big sorted table
	var sb []byte
	n := 250000
	for i := 0; i < n; i++ {
		a := (i >> 16) & 0xff
		bb := (i >> 8) & 0xff
		cc := i & 0xff
		org := "isp"
		if i%7 == 0 {
			org = "Cloud Hosting"
		}
		sb = append(sb, []byte(fmt.Sprintf("%d.%d.%d.0\t%d.%d.%d.255\t%d\tXX\t%s\n", a+1, bb, cc, a+1, bb, cc, 1000+i, org))...)
	}
	path := filepath.Join(b.TempDir(), "big.tsv")
	os.WriteFile(path, sb, 0o644)
	c := New()
	if err := c.LoadTSV(path); err != nil {
		b.Fatal(err)
	}
	n4, _ := c.Size()
	b.ReportMetric(float64(n4), "ranges")
	ips := []string{"1.10.20.30", "50.40.30.20", "200.1.2.3", "128.99.88.77", "3.3.3.3"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Classify(ips[i%len(ips)])
	}
}
