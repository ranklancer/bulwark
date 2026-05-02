// Package ui hosts the embedded web dashboard. The dashboard is a single
// self-contained HTML file with vanilla JavaScript and no external CDN
// dependencies — same constraint as the rest of the project.
//
// The dashboard talks to the existing /api/v1/* endpoints, so it adds no
// new API surface; it's purely a presentation layer over what's already
// there. A future React/Tailwind dashboard will swap in here without
// changing any callers.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed index.html
var embedded embed.FS

// FS returns the embedded UI assets as a read-only fs.FS rooted at the
// directory containing index.html (so callers can serve "/" → index.html
// without prefix manipulation).
func FS() fs.FS {
	return embedded
}
