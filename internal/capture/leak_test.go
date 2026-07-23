package capture

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs goleak after the package's tests. As of this snapshot the
// capture adapters (compose/dockge/komodo/portainer/quadlet/unraid) are all
// synchronous request/response and file-write code paths -- none of them
// spawn goroutines, tickers, or background watchers (verified by grepping
// for "go func(", time.Ticker/NewTicker, context.WithCancel, and watch/poll
// loops across every non-test file in this package). This TestMain is added
// as the safety net an internal audit a hardening tier calls out by name for "capture watchers" so
// that if a future phase adds a watcher/poller here, a leak is caught
// immediately rather than needing a follow-up patch to wire up detection.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
