package main

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs goleak after this package's tests. The relay's run()
// spawns exactly one goroutine (srv.ListenAndServe), and every code path
// out of run() -- normal error, or context cancellation followed by
// srv.Shutdown -- waits on errCh before returning, so the listener
// goroutine is always joined before run() returns. No ignores needed.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
