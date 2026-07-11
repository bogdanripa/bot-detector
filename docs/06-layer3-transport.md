# 06 — Layer 3: Transport Fingerprinting

> **This is the spec for two libraries:** `go/tlscapture` (TLS ClientHello →
> JA3/JA4 + HTTP/2 fingerprint, [docs/13 §3.4](13-libraries-and-packaging.md#34-gotlscapture-go--layer-3-transport))
> and `go/ipasn` (IP → ASN + datacenter classification,
> [docs/13 §3.5](13-libraries-and-packaging.md#35-goipasn-go--layer-3-ipasn)).
> `tlscapture` only works when the consumer terminates its own TLS; behind a proxy
> it reports `unavailable`. `ipasn` is independent and works wherever a client IP
> is known.

The strongest layer, because it is the hardest to fake from a scripting client
and the client controls it least directly: TLS ClientHello (→ JA3/JA4), the
HTTP/2 fingerprint, and IP/ASN reputation.

> **This whole layer is why we self-host.** Layer 3 requires that **our own code
> terminates TLS**. A managed serverless front end (Cloud Function/Run behind the
> Google Front End) terminates TLS and opens a fresh connection to your container,
> so the ClientHello and HTTP/2 fingerprint never reach you (see
> [docs/01 §2](01-architecture-and-hosting.md#2-why-we-do-not-deploy-on-a-google-cloud-function)).
> On the self-hosted server, all of it is captured on the page-navigation
> connection and joined to the session.

---

## 1. What we capture

| Signal | Source | Available on the self-hosted server |
|--------|--------|:-----------------------------------:|
| TLS JA3 / JA4 | ClientHello (`GetConfigForClient`) | ✅ |
| TLS version, ALPN, cipher/curve/extension order | ClientHello | ✅ |
| HTTP/2 SETTINGS, WINDOW_UPDATE, pseudo-header order | H2 preface/frames | ✅ |
| IP / ASN / datacenter | socket `RemoteAddr` | ✅ |

---

## 2. JA3 & JA4

Both are fingerprints of the TLS ClientHello. **JA4 is preferred** (robust to
extension shuffling, human-readable, versioned); **JA3 is kept for
compatibility** with existing fingerprint databases.

### 2.1 JA3 (legacy)

JA3 concatenates, comma-joined then hyphen-joined within fields:

```
SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
```

…then takes the **MD5** of that string. GREASE values (0x0a0a, 0x1a1a, …) are
removed. Example string and hash:

```
769,4865-4866-4867-49195-49199-…,0-23-65281-10-11-…,29-23-24,0
→ md5 → e7d705a3286e19ea42f587b344ee6865
```

In Go, `tls.ClientHelloInfo` gives you `CipherSuites`, `SupportedCurves`,
`SupportedPoints`, and `SupportedVersions`; the extension list requires reading
the raw ClientHello (see §2.3).

### 2.2 JA4 (current)

JA4 for TLS is a structured string `JA4 = (a)_(b)_(c)`:

- **`a`** — meta: protocol (`t`=TLS/`q`=QUIC) + TLS version + SNI present (`d`)/absent (`i`) + cipher count (2 digits) + extension count (2 digits) + first ALPN value.
  e.g. `t13d1516h2` = TLS1.3, SNI, 15 ciphers, 16 extensions, ALPN `h2`.
- **`b`** — truncated SHA-256 of the **sorted** cipher list (hex, no GREASE).
- **`c`** — truncated SHA-256 of the **sorted** extension list + the signature
  algorithms.

Because JA4 **sorts** the ciphers/extensions, it is stable against
order-shuffling libraries and is the more reliable discriminator. Also compute the
JA4 variants where useful (`JA4H` for HTTP, `JA4T`/`JA4TS` for TCP, `JA4L` for
latency) but JA4 (TLS) is the core one.

### 2.3 Capturing the ClientHello in Go

```go
// GetConfigForClient exposes the parsed ClientHello. For extension ORDER (JA4
// needs the set; JA3 needs the raw list incl. order), tee the raw bytes.
tlsCfg := &tls.Config{
    GetCertificate: certManager.GetCertificate,
    NextProtos:     []string{"h2", "http/1.1"},
    GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
        fp := Fingerprint{
            Version:   pickVersion(h.SupportedVersions),
            Ciphers:   stripGREASE(h.CipherSuites),
            Curves:    stripGREASE16(h.SupportedCurves),
            Points:    h.SupportedPoints,
            ALPN:      h.SupportedProtos,
            SNIExists: h.ServerName != "",
        }
        // Extensions: read from a raw-ClientHello tee (net.Listener wrapper) or utls.
        fp.Extensions = rawExtensionsFor(h.Conn.RemoteAddr())
        fp.JA3, fp.JA3Hash = computeJA3(fp)
        fp.JA4 = computeJA4(fp)
        store.putTLS(h.Conn.RemoteAddr(), fp)
        return nil, nil
    },
}
```

For the extension **list including order**, the cleanest approach is a
`net.Listener` wrapper that reads the first TLS record (the ClientHello) off the
socket, parses the extension TLV sequence, then replays the bytes into Go's TLS
stack via a buffered `net.Conn`. Alternatively, `utls` exposes ClientHello
internals. Document whichever you pick with a pointer to the parsing code.

### 2.4 Classification & the key contradiction

Maintain a small lookup (see [docs/09](09-reference-data.md)) mapping JA4 (and
JA3) values to client stacks: recent Chrome/Firefox/Safari per-OS, plus the
distinctive fingerprints of `curl`, Go `net/http`, Python `requests`/`urllib3`,
`okhttp`, `node fetch`/`undici`.

The highest-value output of the whole tool:

> **TLS/H2 fingerprint vendor ≠ User-Agent vendor.**
> The ClientHello says `go-nethttp` / `python-requests` / `curl`, but the UA says
> `Chrome/124`. A genuine Chrome browser *cannot* produce a Go TLS ClientHello.
> This is the **single strongest cross-layer contradiction** and is weighted
> highest by the coherence engine.

Because JA4 sorts its inputs, a stealth client that merely reorders extensions
won't escape it; to match Chrome's JA4 the client must replicate Chrome's *actual
cipher and extension set*, which most scripting stacks don't.

---

## 3. HTTP/2 fingerprint

If ALPN negotiated `h2`, capture the client's H2 preamble. Browsers have stable,
distinctive H2 fingerprints; scripted H2 clients (Go's `http2`, Python `httpx`,
`nghttp2`, `curl --http2`) differ.

### 3.1 What to capture

| Element | Notes |
|---------|-------|
| SETTINGS frame | The list of `(id, value)` pairs **in the order sent**: `HEADER_TABLE_SIZE`, `ENABLE_PUSH`, `MAX_CONCURRENT_STREAMS`, `INITIAL_WINDOW_SIZE`, `MAX_FRAME_SIZE`, `MAX_HEADER_LIST_SIZE`. Chrome, Firefox, Safari each pick different values and order. |
| WINDOW_UPDATE | The connection-level initial window increment. |
| PRIORITY frames | Whether/how the client sends stream priorities (Firefox historically sent a distinctive priority tree). |
| Pseudo-header order | The order of `:method`, `:authority`, `:scheme`, `:path`. Chrome uses `m,a,s,p`; some libraries differ. |
| Header-table size updates | Dynamic table sizing behavior. |

### 3.2 The Akamai-style fingerprint string

A compact, comparable representation:

```
SETTINGS(id:value;…)|WINDOW_UPDATE|PRIORITY(…)|PSEUDO_HEADER_ORDER
e.g.  1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p
```

Store it and classify against the reference DB. A mismatch between the H2-implied
stack and the UA is a contradiction (corroborating the TLS one).

### 3.3 Capturing it in Go

Go's stock `http2.Server` abstracts frames away, so read them explicitly:

- Accept the TLS conn, confirm ALPN `h2`, read the **client connection preface**
  (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), then use `golang.org/x/net/http2` frame
  reader (`http2.NewFramer`) to read the initial `SETTINGS` and `WINDOW_UPDATE`
  frames and the first `HEADERS` frame (for pseudo-header order via an HPACK
  decoder) before either serving the request minimally or resetting the stream.
- This is the same connection as the TLS capture, so it's one code path on the
  self-hosted server.

---

## 4. IP reputation / ASN

Resolve the visitor IP → ASN and organization; flag datacenter/cloud ranges.

### 4.1 Getting the IP

- On the self-hosted server the socket `RemoteAddr` **is** the client's egress IP —
  no `X-Forwarded-For` trust problem. Validate it parses and isn't
  private/reserved.
- If you deliberately front the box with an L4 proxy, honor `PROXY protocol` or a
  single trusted `X-Forwarded-For` hop; otherwise use `RemoteAddr`.

### 4.2 ASN classification

- Ship a **static datacenter-ASN list** for the obvious clouds so the tool works
  with zero external dependencies: AWS (16509, 14618), GCP (15169, 396982),
  Azure (8075), OVH (16276), Hetzner (24940), DigitalOcean (14061), Linode/Akamai
  (63949, 20940), Vultr (20473), Scaleway (12876), Oracle Cloud (31898), plus
  common VPN/hosting ranges. (Full seed list in [docs/09](09-reference-data.md).)
- Optionally integrate a reputation source (MaxmMind GeoLite2 ASN, IPinfo,
  Team Cymru IP-to-ASN via DNS) behind an interface, so the static list is the
  offline default and a richer source can be swapped in.
- **Status:** datacenter/cloud/hosting ASN → `warn` (a solid contributor,
  +0.9 log-odds — see [docs/07 §2.5](07-coherence-engine.md#25-transport-layer-3)),
  not a `fail` on its own. Real users are mostly on residential/mobile ASNs, but
  developers browse from cloud shells and users route through VPNs, so a datacenter
  IP is a **red flag, not proof**. It becomes decisive only in the classic cluster
  (datacenter IP + `UTC`/mismatched timezone + `en-US` + a scripting-stack TLS
  fingerprint), which the `lang_tz_ip_cluster` contradiction captures.

### 4.3 Geolocation join

Geolocate the IP (country/region/timezone) and hand it to the coherence engine to
compare against the client-reported `Intl` timezone and `Accept-Language`. A
datacenter IP in `us-east-1` with a client timezone of `Europe/Bucharest` and
`Accept-Language: en-US` is a recognizable pattern.

---

## 5. Output block

```jsonc
"layer3": {
  "available": true,
  "capturedBy": "navigation",       // captured at GET / on the self-hosted server
  "tls": {
    "version": "TLS 1.3",
    "ja3": "769,4865-4866-…", "ja3Hash": "e7d705a3286e19ea42f587b344ee6865",
    "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
    "alpn": ["h2","http/1.1"], "cipherCount": 15, "extensionCount": 16,
    "matchedStack": "chrome-124-windows", "matchConfidence": 0.9
  },
  "http2": {
    "akamaiFingerprint": "1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p",
    "matchedStack": "chrome", "pseudoHeaderOrder": [":method",":authority",":scheme",":path"]
  },
  "ip": { "addr": "203.0.113.9", "asn": 7922, "org": "COMCAST-7922", "isDatacenter": false,
          "country": "US", "geoTimezone": "America/New_York" }
}
```

If a specific transport probe can't run (e.g. the client negotiated HTTP/1.1 so
there's no H2 fingerprint), that field renders `unavailable` and is excluded from
scoring — but TLS/JA4 and IP/ASN are always available on the self-hosted server.
