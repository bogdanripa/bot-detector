// Package botdetector embeds the honeypot's web assets, client library, and
// scoring config so the server ships as a single self-contained binary.
// (This file lives at the module root because go:embed cannot reference paths
// above its own directory.)
package botdetector

import "embed"

//go:embed honeypot/web
var WebFS embed.FS

//go:embed packages/client/botdetect.js
var ClientJS []byte

//go:embed config/scoring.json
var ScoringJSON []byte
