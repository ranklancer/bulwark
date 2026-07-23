package scheduler

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs goleak after the package's tests to catch goroutines (and
// the resources they hold, e.g. tickers/timers) that outlive the test that
// spawned them. The scheduler's Run/runCron loops are launched in a
// goroutine by every caller (the daemon, tests here); every scheduler_test.go
// case already synchronises on a done channel after cancelling its context,
// so no ignores are needed -- a leak here would mean Run failed to return
// promptly on ctx cancellation.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
