package scanner

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs goleak after the package's tests to catch goroutines (and the
// resources they hold) that outlive the test that spawned them — the kind of
// leak that only shows up in a long-running daemon, never in a single unit test.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
