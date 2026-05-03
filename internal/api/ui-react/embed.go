// Package uireact hosts the embedded Vite/React build of the dashboard.
// The dist/ directory is populated by `cd web && npm run build`; a tiny
// placeholder ships in git so `go build ./...` works on machines
// without a Node toolchain (operators get the legacy vanilla
// dashboard until they build the SPA).
//
// Detection of "real build vs. placeholder" is signalled by the
// placeholder marker comment IsBuilt searches for. The server uses
// IsBuilt to decide whether to mount the React SPA at "/" + the
// vanilla dashboard at "/legacy/", or to keep serving the vanilla
// dashboard at "/" exclusively.
package uireact

import (
	"bytes"
	"embed"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

// placeholderMarker is the sentinel string the placeholder index.html
// carries so IsBuilt can distinguish it from a real Vite build. Vite
// emits hashed asset paths under /assets/ and never writes this string,
// so a real build naturally lacks the marker.
const placeholderMarker = "BULWARK_REACT_PLACEHOLDER"

// FS returns the embedded dist tree, rooted at dist/. Callers that want
// to serve the SPA's bundled assets (assets/*.js, assets/*.css) under
// "/assets/" can fs.Sub(FS(), "dist") first.
func FS() fs.FS {
	return embedded
}

// IsBuilt reports whether a real Vite-built artifact is present. False
// means dist/ contains only the placeholder, in which case the server
// should keep the legacy vanilla dashboard mounted at "/".
//
// Detection is by reading dist/index.html and searching for the
// placeholder marker. A read failure (no embedded index at all,
// shouldn't happen given //go:embed all:dist + the committed
// placeholder) is treated as "not built" — fail closed.
func IsBuilt() bool {
	data, err := fs.ReadFile(embedded, "dist/index.html")
	if err != nil {
		return false
	}
	return !bytes.Contains(data, []byte(placeholderMarker))
}

// Sub returns the dist directory as an fs.FS rooted at dist/, suitable
// for handing to http.FileServer. Returns nil + error if the embed is
// somehow malformed.
func Sub() (fs.FS, error) {
	return fs.Sub(embedded, "dist")
}
