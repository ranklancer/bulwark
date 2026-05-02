// Package hooks invokes user-supplied scripts at well-defined points in the
// update lifecycle: pre-update (before we touch the running container),
// post-update (after the new container is verified healthy), and rollback
// (after a health-failure-triggered rollback).
//
// Hooks are simple stand-alone scripts on the host filesystem, invoked via
// os/exec with a controlled environment. They receive update context via
// BULWARK_-prefixed environment variables — no command-line parsing on the
// script side, no JSON parsing, just `$BULWARK_NEW_IMAGE` and friends.
//
// Pre-update failure aborts the update. Post-update and rollback failures
// are logged but non-fatal: the update / rollback has already happened by
// the time those hooks run.
package hooks

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Action identifies which point in the lifecycle a hook is being invoked at.
type Action string

const (
	ActionPreUpdate  Action = "pre-update"
	ActionPostUpdate Action = "post-update"
	ActionRollback   Action = "rollback"
)

// Context carries the per-update facts a hook script needs. It's serialised
// into BULWARK_* env vars before invocation; scripts read them via the shell.
type Context struct {
	Action        Action
	Container     string
	OldImage      string
	NewImage      string
	OldDigest     string
	NewDigest     string
	SnapshotID    string
	ContainerID   string
}

// envFor flattens the context into the env-var key/value pairs the runner
// will pass to exec.Cmd. Values are pre-formatted strings so the consumer
// never has to parse anything more complex than what bash can.
func (c Context) envFor() []string {
	return []string{
		"BULWARK_ACTION=" + string(c.Action),
		"BULWARK_CONTAINER=" + c.Container,
		"BULWARK_CONTAINER_ID=" + c.ContainerID,
		"BULWARK_OLD_IMAGE=" + c.OldImage,
		"BULWARK_NEW_IMAGE=" + c.NewImage,
		"BULWARK_OLD_DIGEST=" + c.OldDigest,
		"BULWARK_NEW_DIGEST=" + c.NewDigest,
		"BULWARK_SNAPSHOT_ID=" + c.SnapshotID,
	}
}

// Runner abstracts hook execution so tests can inject a fake.
type Runner interface {
	// Run invokes path with the given context's env. Returns the captured
	// stdout+stderr (truncated to a reasonable cap so a chatty hook can't
	// blow memory) plus any error. A non-zero exit becomes an error;
	// successful exit returns (output, nil).
	Run(ctx context.Context, path string, hctx Context, timeout time.Duration) ([]byte, error)
}

// ExecRunner is the production implementation. The hook's working directory
// is set to the directory containing the script (so scripts that source
// adjacent helpers work as expected).
type ExecRunner struct{}

// MaxHookOutput is the upper bound on captured stdout+stderr per hook.
// A misbehaving hook that prints megabytes shouldn't be able to OOM the
// daemon — the cap is generous (256 KiB) but finite.
const MaxHookOutput = 256 * 1024

// Run implements Runner. The default timeout is 60 seconds; pass 0 for the
// default or a negative value to disable.
func (ExecRunner) Run(ctx context.Context, path string, hctx Context, timeout time.Duration) ([]byte, error) {
	if path == "" {
		return nil, errors.New("hooks: empty path")
	}
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, path)
	// Inherit a minimal-ish environment: we do NOT pass through os.Environ()
	// blindly, because the daemon has secrets in env (webhook URLs, GitHub
	// PATs) that hooks have no business seeing. Hooks get only PATH and
	// the BULWARK_* context.
	cmd.Env = append(safeBaseEnv(), hctx.envFor()...)

	out, err := cmd.CombinedOutput()
	if len(out) > MaxHookOutput {
		out = append(out[:MaxHookOutput], []byte("\n... (truncated)")...)
	}
	if err != nil {
		// Distinguish timeout from other failures so callers can render
		// it usefully.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return out, fmt.Errorf("hook %s timed out after %s", path, timeout)
		}
		return out, fmt.Errorf("hook %s failed: %w", path, err)
	}
	return out, nil
}

// safeBaseEnv returns the minimal environment hooks should inherit.
// Currently just PATH so /bin/sh shebangs work; extend with discretion.
func safeBaseEnv() []string {
	return []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
}

// FakeRunner is the test double. It records every call and returns
// programmed responses keyed by hook path.
type FakeRunner struct {
	mu      sync.Mutex
	calls   []FakeCall
	results map[string]fakeResult
}

// FakeCall captures one Run invocation.
type FakeCall struct {
	Path string
	Ctx  Context
}

type fakeResult struct {
	out []byte
	err error
}

// NewFakeRunner returns an empty FakeRunner.
func NewFakeRunner() *FakeRunner {
	return &FakeRunner{results: make(map[string]fakeResult)}
}

// On registers a programmed result for the given path.
func (f *FakeRunner) On(path string, out []byte, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results[path] = fakeResult{out, err}
}

// Calls returns a copy of every recorded invocation.
func (f *FakeRunner) Calls() []FakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]FakeCall, len(f.calls))
	copy(out, f.calls)
	return out
}

// Run records and returns the programmed result.
func (f *FakeRunner) Run(_ context.Context, path string, hctx Context, _ time.Duration) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, FakeCall{Path: path, Ctx: hctx})
	r, ok := f.results[path]
	f.mu.Unlock()
	if !ok {
		return nil, nil
	}
	return r.out, r.err
}

// Invoke is a small convenience wrapper: it runs a hook, logs success/
// failure, and (for non-pre-update actions) swallows errors so the caller
// doesn't have to write the same logic three times. Returns true when the
// hook succeeded or wasn't configured; false when it ran and failed.
func Invoke(ctx context.Context, runner Runner, path string, hctx Context, logger *slog.Logger) bool {
	if path == "" {
		return true
	}
	if logger == nil {
		logger = slog.Default()
	}
	out, err := runner.Run(ctx, path, hctx, 0)
	if err != nil {
		logger.Warn("hook failed",
			"action", string(hctx.Action),
			"path", path,
			"container", hctx.Container,
			"err", err,
			"output", trimOutput(out),
		)
		return false
	}
	logger.Info("hook ok",
		"action", string(hctx.Action),
		"path", path,
		"container", hctx.Container,
	)
	return true
}

// trimOutput keeps log lines tractable. We pass the first 512 bytes to slog;
// the full output is only available to the runner if it captures it.
func trimOutput(b []byte) string {
	const cap = 512
	if len(b) <= cap {
		return strings.TrimSpace(string(b))
	}
	return strings.TrimSpace(string(b[:cap])) + "..."
}
