# 09 — Reference Fingerprint Data

The coherence engine compares captured values against known-good and known-bad
references. This document defines those reference sets, how they're stored, and
how they're kept current. Ship them as versioned JSON in the repo
(`data/reference/*.json`), loaded at startup, with a `referenceVersion` and
`generatedAt` so the report can show data freshness.

> **Maintenance reality.** Browser fingerprints drift every release (roughly every
> 4 weeks for Chrome). Treat this data as **perishable**: version it, date it, and
> build the matching logic to degrade to "unknown stack" gracefully rather than
> mis-classifying when it sees something newer than its tables. A stale table
> should produce `matchedStack: "unknown"`, never a false positive.

---

## 1. Matching philosophy

- **Exact-hash matches** (JA3 MD5, canvas hashes) are brittle — one Chrome point
  release changes them. Use them as *hints*, and prefer structural matches.
- **JA4** is designed to be more stable (it sorts inputs and encodes structure),
  so prefer JA4-prefix/structural matching for stack classification.
- **Header order** and **H2 settings** are matched by *distance to* a reference
  sequence (LCS / tuple-equality), not exact string equality, so minor variation
  doesn't break the match.
- Always output a **match confidence** and fall back to `unknown` below a
  threshold. `unknown` is safe (contributes no penalty); a *wrong* match is not.

---

## 2. Header order references

Store per browser family + major version, lower-cased names, navigation vs.
fetch context. Illustrative (verify against real captures before shipping — see
[docs/11](11-testing.md)):

```jsonc
{
  "chrome_desktop_nav": ["host","connection","cache-control","sec-ch-ua","sec-ch-ua-mobile",
    "sec-ch-ua-platform","upgrade-insecure-requests","user-agent","accept","sec-fetch-site",
    "sec-fetch-mode","sec-fetch-user","sec-fetch-dest","accept-encoding","accept-language"],
  "firefox_desktop_nav": ["host","user-agent","accept","accept-language","accept-encoding",
    "connection","upgrade-insecure-requests","sec-fetch-dest","sec-fetch-mode","sec-fetch-site",
    "sec-fetch-user"],
  "safari_desktop_nav": ["host","accept","accept-encoding","accept-language","connection",
    "user-agent"]
}
```

Known **HTTP-library** orders (the ones that should fire `header_order_is_library`):

```jsonc
{
  "curl": ["host","user-agent","accept"],
  "python_requests": ["user-agent","accept-encoding","accept","connection","host"],
  "go_nethttp": ["host","user-agent","accept-encoding"],
  "node_undici": ["host","connection","user-agent","accept","accept-language","accept-encoding"],
  "axios": ["accept","user-agent","accept-encoding","host","connection"],
  "okhttp": ["user-agent","host","connection","accept-encoding"]
}
```

> These are *illustrative shapes*, not authoritative — capture the real orderings
> from live clients during the testing milestone and replace these. The curl/Go
> minimalism (very few headers, no `sec-*`) is the durable tell, not the exact
> permutation.

---

## 3. TLS JA3/JA4 references

Store a compact table keyed by stack, with both JA4 (preferred) and a few JA3
hashes for legacy matching:

```jsonc
[
  { "stack": "chrome-desktop", "ja4Prefix": "t13d15", "alpn": "h2",
    "cipherCount": [15,16], "extensionCount": [15,17], "class": "browser" },
  { "stack": "firefox-desktop", "ja4Prefix": "t13d17", "class": "browser" },
  { "stack": "safari-desktop", "ja4Prefix": "t13d", "class": "browser", "note": "no client hints" },
  { "stack": "go-nethttp", "ja3Hash": ["<capture>"], "class": "library" },
  { "stack": "python-requests", "ja3Hash": ["<capture>"], "class": "library" },
  { "stack": "curl", "ja3Hash": ["<capture>"], "class": "library" },
  { "stack": "okhttp", "class": "library" },
  { "stack": "node-undici", "class": "library" }
]
```

The engine only needs `class ∈ {browser, library}` for the decisive
`tls_ua_vendor_mismatch` rule: if `class == library` while the UA claims a
browser, fire the contradiction. Per-stack granularity is a nice-to-have for the
report's "matched stack" label. **Capture the real JA3/JA4 values during testing**
— do not ship guessed hashes.

---

## 4. HTTP/2 fingerprint references

Akamai-style strings per stack:

```jsonc
{
  "chrome":  { "settings": [[1,65536],[3,1000],[4,6291456],[6,262144]], "windowUpdate": 15663105, "pseudo": "m,a,s,p", "priority": true },
  "firefox": { "settings": [[1,65536],[4,131072],[5,16384]], "windowUpdate": 12517377, "pseudo": "m,p,a,s", "priority": true },
  "safari":  { "settings": [[4,4194304],[3,100]], "pseudo": "m,s,p,a" },
  "go":      { "settings": [[3,250],[4,65535],[5,16384]], "pseudo": "m,a,s,p" },
  "curl_nghttp2": { "settings": [[3,100],[4,33554432],[2,0]], "pseudo": "m,a,s,p" }
}
```

Match by tuple-set + pseudo-order. Again: **capture real values**; the exact
numbers drift and vary by version/OS.

---

## 5. Datacenter / cloud ASN seed list

Ship as the offline default so IP classification works with zero external
dependencies. Non-exhaustive seed:

```jsonc
{
  "datacenter_asns": {
    "16509": "AWS", "14618": "AWS",
    "15169": "GOOGLE", "396982": "GOOGLE-CLOUD",
    "8075": "MICROSOFT-AZURE",
    "16276": "OVH", "24940": "HETZNER", "14061": "DIGITALOCEAN",
    "20473": "VULTR/CHOOPA", "63949": "AKAMAI-LINODE", "20940": "AKAMAI",
    "12876": "SCALEWAY-ONLINE", "31898": "ORACLE-CLOUD", "51167": "CONTABO",
    "9009": "M247", "45102": "ALIBABA", "132203": "TENCENT", "37963": "ALIBABA-CN"
  }
}
```

Interface it behind an `ASNLookup` so a richer source (MaxMind GeoLite2 ASN,
IPinfo, Team Cymru DNS) can replace the static map without touching the engine.
Include common **VPN/hosting** ASNs too, but weight datacenter ASNs mild
(`suspicious`, weight ~10) — developers and VPN users are legitimate.

---

## 6. Canvas/audio known-default hashes

A small deny-list of canvas/audio hashes produced by **stock automation images**
(headless Chrome on a fresh Debian VM, default GitHub Actions runner, common
Docker base images). These recur across "different" clients because the
environment is identical.

```jsonc
{
  "canvas_automation_defaults": ["<hash-from-headless-debian>", "<hash-from-gha-runner>"],
  "audio_automation_defaults": ["<hash>"]
}
```

Populate by actually running the tool from those environments during testing.
Match here yields a mild `suspicious`, never a hard `automation` — a shared hash
is evidence of a common environment, not proof of a bot.

---

## 7. OS-signature fonts

Used by the font-set OS inference in [docs/04 §2.6](04-layer1-browser.md#26-fonts)
and the `os_triangulation_mismatch` rule:

```jsonc
{
  "windows": ["Segoe UI","Calibri","Cambria","Consolas","Tahoma","MS Gothic","Segoe UI Emoji"],
  "macos":   ["Helvetica Neue","Menlo","Geneva",".SF NS","Apple Color Emoji","Avenir"],
  "linux":   ["DejaVu Sans","Liberation Sans","Ubuntu","Noto Sans","FreeSans","Cantarell"],
  "android": ["Roboto","Droid Sans","Noto Color Emoji"]
}
```

If the detected set contains signature fonts of OS X but the `Sec-CH-UA-Platform`
/ UA claims OS Y, that's a triangulation mismatch.

---

## 8. Data freshness & governance

- `data/reference/` carries `referenceVersion` (semver) + `generatedAt` (ISO
  date). The `/api/reference` endpoint and the report footer surface these.
- A short doc / script records **how each table was captured** (which browser
  versions, which capture host) so refreshes are reproducible.
- CI includes a "reference sanity" test: the shipped reference values must at
  least parse, be internally consistent (no duplicate stack ids), and the
  library-vs-browser classes must be present for the core stacks.
- Plan a **quarterly refresh** cadence for browser fingerprints; libraries drift
  slower. Until refreshed, unknown-but-newer clients fall back to `unknown`
  (no false positives), which is the safe failure mode.
