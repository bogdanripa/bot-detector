# Server libraries — Node 🚧 (to be implemented)

Planned Node/TypeScript port of the detection **server** libraries, mirroring the
Go reference implementation in [`../go/`](../go/README.md). **Not yet implemented** —
this README is the spec for whoever builds it.

Implement Go first ([docs/13 §2.1](../docs/13-libraries-and-packaging.md#21-language-support-go-first)).
Start this port only once `go/` is the settled reference.

## What to build (mirror `go/`)

| Package | Difficulty in Node | Notes |
|---------|--------------------|-------|
| `httpcapture` | ✅ easy | `http`/`connect`/Express/Fastify middleware. Header **values** trivially; header **order** via `req.rawHeaders` (preserved for HTTP/1.1; HTTP/2 order is harder — document the limitation). Web Bot Auth signature verification via a WebCrypto Ed25519 check. |
| `ipasn` | ✅ easy | Same static datacenter-ASN list (share `config/reference/`); optional MaxMind/IPinfo behind an interface. |
| `engine` | ✅ **reuse, don't port** | A Node server should import **`@botdetect/engine`** (the JS engine in `../packages/engine-js`), which already reads `config/scoring.json`. No separate Node engine needed. |
| `tlscapture` | ❌ **hard — the blocker** | Node's `tls` module does **not** expose the client ClientHello. Options below. |

## The Layer-3 problem (and the three ways out)

Node cannot see the TLS ClientHello through the standard `tls` server. To get
JA3/JA4 + the HTTP/2 fingerprint, pick one:

1. **Raw-TCP peek then hand off to TLS.** Put a `net.Server` in front, read the
   first TLS record (the ClientHello) off the socket, parse the extension TLV
   yourself for JA3/JA4, then pass the buffered connection to a `tls.TLSSocket`.
   Feasible but fiddly; H2 frame capture adds more.
2. **Native addon / FFI.** Bind a Rust or C JA4 core, or link the Go `tlscapture`
   as a shared library. Fastest at runtime, heaviest to build/maintain.
3. **Go `tlscapture` sidecar (recommended).** Front the Node app with the Go
   TLS-terminating capture proxy on the same host (L4-style), which computes
   JA3/JA4 + H2 and passes them to Node via a trusted header/socket. Reuses the
   already-built Go code; keeps Node simple.

Whichever you choose, if Layer 3 isn't captured the engine already degrades
gracefully — `layer3Tls: unavailable`, reduced confidence, no crash
([docs/13 §4](../docs/13-libraries-and-packaging.md#4-the-capability-model-flexibility)).

## Contract

Match the public API shapes in
[docs/13 §3](../docs/13-libraries-and-packaging.md#3-the-packages) and the wire
schema in [docs/03](../docs/03-api-contract.md). Cross-check the reused
`@botdetect/engine` against the Go engine on the shared `SignalSet` fixtures
([docs/11 §2.1](../docs/11-testing.md)).
