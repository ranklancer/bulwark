package snapshot

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// Runner abstracts command execution so backends can be tested without
// shelling out to real binaries. Implementations return (stdout, error);
// stderr is folded into the error message.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	Available(ctx context.Context, name string) bool
}

// ExecRunner is the production Runner. It uses os/exec.CommandContext.
type ExecRunner struct{}

// Run invokes name with args and returns combined stdout. On non-zero exit,
// the error message includes both the underlying error and stderr.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = strings.TrimSpace(string(ee.Stderr))
		}
		if stderr != "" {
			return out, fmt.Errorf("%s %s: %w — %s", name, strings.Join(args, " "), err, stderr)
		}
		return out, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}

// Available reports whether the named binary is on PATH.
func (ExecRunner) Available(_ context.Context, name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// FakeRunner is the test double. It records every invocation and returns
// programmed responses keyed by command-line. Calls without a registered
// response return (nil, nil) so tests can ignore uninteresting commands.
type FakeRunner struct {
	mu        sync.Mutex
	calls     []string
	responses map[string]fakeResponse
	available map[string]bool // command → reported availability
}

type fakeResponse struct {
	out []byte
	err error
}

// NewFakeRunner returns a FakeRunner with no programmed responses.
func NewFakeRunner() *FakeRunner {
	return &FakeRunner{
		responses: make(map[string]fakeResponse),
		available: make(map[string]bool),
	}
}

// On records a programmed response for a specific invocation. The key is
// "name args..." with single-space separation.
func (f *FakeRunner) On(invocation string, out []byte, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[invocation] = fakeResponse{out: out, err: err}
}

// SetAvailable controls what Available reports for a given binary.
func (f *FakeRunner) SetAvailable(name string, available bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.available[name] = available
}

// Calls returns a copy of every invocation recorded so far.
func (f *FakeRunner) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

// Run records the invocation, returns the programmed response (or zero
// values when none).
func (f *FakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name
	if len(args) > 0 {
		key = name + " " + strings.Join(args, " ")
	}
	f.mu.Lock()
	f.calls = append(f.calls, key)
	resp, ok := f.responses[key]
	f.mu.Unlock()
	if !ok {
		return nil, nil
	}
	return resp.out, resp.err
}

// Available returns the configured availability for the binary; defaults
// to true so tests don't have to opt in for every backend constructor call.
func (f *FakeRunner) Available(_ context.Context, name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.available[name]; ok {
		return v
	}
	return true
}
