# Server libraries — Python 🚧 (to be implemented)

Planned Python port of the detection **server** libraries, mirroring the Go
reference implementation in [`../go/`](../go/README.md). **Not yet implemented** —
this README is the spec for whoever builds it.

Implement Go first ([docs/13 §2.1](../docs/13-libraries-and-packaging.md#21-language-support-go-first)).
Start this port only once `go/` is the settled reference.

## What to build (mirror `go/`)

| Package | Difficulty in Python | Notes |
|---------|----------------------|-------|
| `httpcapture` | ✅ easy | ASGI/WSGI middleware (FastAPI/Starlette/Flask/Django). Header **values** trivially; header **order** is framework-dependent (ASGI preserves the raw header list — good; WSGI normalizes — worse). Web Bot Auth (RFC 9421) via `cryptography` Ed25519. |
| `ipasn` | ✅ easy | Same static datacenter-ASN list (share `config/reference/`); optional MaxMind/IPinfo behind an interface. |
| `engine` | ⚠️ light port | Port the pure `SignalSet → Report` scorer; it just **interprets `config/scoring.json`** (weights, rules, logistic), so it's a thin interpreter + a rule registry, not new logic. Cross-check against the Go engine on shared fixtures. |
| `tlscapture` | ❌ **hard — the blocker** | Python's `ssl` does **not** expose the client ClientHello. Options below. |

## The Layer-3 problem (and the three ways out)

Python can't see the TLS ClientHello through the standard `ssl` server. To get
JA3/JA4 + the HTTP/2 fingerprint, pick one:

1. **Raw-socket ClientHello parse.** Accept the raw TCP connection, read and parse
   the first TLS record (ClientHello) for JA3/JA4, then wrap with
   `ssl.SSLContext.wrap_socket`. Use the `h2` library's frame reader for the HTTP/2
   SETTINGS/pseudo-header fingerprint. Feasible; most work is in the parsing.
2. **FFI.** Bind a Rust/C JA4 core (e.g. via `cffi`/`PyO3`), or call the Go
   `tlscapture` as a shared library.
3. **Go `tlscapture` sidecar (recommended).** Front the Python app with the Go
   TLS-terminating capture proxy on the same host; it computes JA3/JA4 + H2 and
   passes them to Python via a trusted header/socket. Reuses the built Go code.

If Layer 3 isn't captured the engine degrades gracefully — `layer3Tls:
unavailable`, reduced confidence, no crash
([docs/13 §4](../docs/13-libraries-and-packaging.md#4-the-capability-model-flexibility)).

## Contract

Match the public API shapes in
[docs/13 §3](../docs/13-libraries-and-packaging.md#3-the-packages) and the wire
schema in [docs/03](../docs/03-api-contract.md). The Python engine must agree with
the Go and JS engines on the shared `SignalSet` fixtures
([docs/11 §2.1](../docs/11-testing.md)) — same `scoring.json`, same probability
within tolerance.
