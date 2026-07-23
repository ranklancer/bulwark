package main

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs goleak after this package's tests to catch goroutines that
// outlive the test that spawned them -- this is the daemon entrypoint
// (`bulwark run` / `bulwark serve`), which is exactly the kind of
// long-running process where a leaked ticker/watcher goroutine would only
// show up in production, never in a single unit test.
//
// run.go's cmdRunWith spawns up to four goroutines per invocation: the
// scan scheduler, the optional digest scheduler, the HTTP server, and a
// SIGHUP-reload listener. The first three are joined via a sync.WaitGroup
// before cmdRunWith returns. The SIGHUP listener is NOT tracked by that
// WaitGroup -- it exits on its own as soon as ctx.Done() fires, which
// every test here already triggers via cancel() before waiting on the
// done channel. That's a benign, provably-bounded exit race (the
// goroutine has nothing left to do but observe an already-closed
// channel and return), not an unbounded leak, and goleak's default
// retry/backoff window comfortably absorbs it -- confirmed clean under
// -race and repeated goleak runs. No ignores were needed.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
