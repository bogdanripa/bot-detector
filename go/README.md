# Server libraries — Go ✅ (reference implementation)

The Go implementation of the detection **server** libraries. This is the language
we implement **first** and the reference the Node/Python ports mirror. See
[docs/13](../docs/13-libraries-and-packaging.md) for the full library design and
[docs/13 §2.1](../docs/13-libraries-and-packaging.md#21-language-support-go-first)
for why Go leads.

## Why Go is first

Layer 3. Capturing the client's TLS ClientHello (→ JA3/JA4), the HTTP/2
fingerprint, and raw header order requires owning the socket, and Go is the only
target where that is clean:

- `crypto/tls` `GetConfigForClient(*tls.ClientHelloInfo)` exposes the parsed
  ClientHello (cipher suites, curves, ALPN, versions, SNI);
- `github.com/refraction-networking/utls` exposes extension order for JA4;
- `golang.org/x/net/http2`'s `Framer` reads the client SETTINGS / WINDOW_UPDATE /
  HEADERS frames for the HTTP/2 fingerprint;
- mature community JA3/JA4 packages exist.

Node and Python `tls`/`ssl` do not surface the ClientHello at all.

## Packages

| Package | Layer | Responsibility | Spec |
|---------|-------|----------------|------|
| `httpcapture` | 2 | Header values + order from a request (net/http middleware); Web Bot Auth signature check | [docs/05](../docs/05-layer2-http.md), [docs/14 §8](../docs/14-agentic-and-cdp-detection.md) |
| `tlscapture` | 3 | TLS ClientHello → JA3/JA4; HTTP/2 fingerprint | [docs/06 §1–3](../docs/06-layer3-transport.md) |
| `ipasn` | 3 | IP → ASN/org; datacenter/cloud classification | [docs/06 §4](../docs/06-layer3-transport.md#4-ip-reputation--asn) |
| `engine` | — | Pure `SignalSet → Report` scoring (authoritative); reads `config/scoring.json` | [docs/07](../docs/07-coherence-engine.md) |
| `schema` | — | Wire types generated from `schema/` (JSON Schema) | [docs/03](../docs/03-api-contract.md) |

## Public API

The `SignalSet → Report` engine and the capture middlewares follow the shapes in
[docs/13 §3](../docs/13-libraries-and-packaging.md#3-the-packages). The Node and
Python ports **must match these signatures** (adjusted for language idiom) so a
consumer's mental model is portable across languages.

## Consumed by

The honeypot server (`honeypot/server`) composes all four capture/scoring packages
into the 3-step funnel ([docs/02](../docs/02-deployment-topology.md)). A
third-party Go backend can embed any subset (server-only, Layer-3-absent, etc. —
[docs/13 §5](../docs/13-libraries-and-packaging.md#5-integration-recipes)).

## Status

Implemented first, per the roadmap ([docs/12](../docs/12-roadmap.md)): `tlscapture`
JA4 capture is the critical-path milestone (M2).
