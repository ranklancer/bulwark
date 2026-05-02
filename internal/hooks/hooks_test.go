package hooks

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestContext_Env(t *testing.T) {
	c := Context{
		Action:      ActionPreUpdate,
		Container:   "sonarr",
		ContainerID: "abc123",
		OldImage:    "lscr.io/.../sonarr:1",
		NewImage:    "lscr.io/.../sonarr:2",
		OldDigest:   "sha256:old",
		NewDigest:   "sha256:new",
		SnapshotID:  "tank/data@bulwark-x",
	}
	env := c.envFor()
	want := map[string]string{
		"BULWARK_ACTION":       "pre-update",
		"BULWARK_CONTAINER":    "sonarr",
		"BULWARK_CONTAINER_ID": "abc123",
		"BULWARK_OLD_IMAGE":    "lscr.io/.../sonarr:1",
		"BULWARK_NEW_IMAGE":    "lscr.io/.../sonarr:2",
		"BULWARK_OLD_DIGEST":   "sha256:old",
		"BULWARK_NEW_DIGEST":   "sha256:new",
		"BULWARK_SNAPSHOT_ID":  "tank/data@bulwark-x",
	}
	got := make(map[string]string, len(env))
	for _, kv := range env {
		eq := strings.IndexByte(kv, '=')
		got[kv[:eq]] = kv[eq+1:]
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestExecRunner_RunsHookAndCapturesOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hook.sh")
	script := `#!/bin/sh
echo "container=$BULWARK_CONTAINER action=$BULWARK_ACTION new=$BULWARK_NEW_IMAGE"
exit 0
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	runner := ExecRunner{}
	out, err := runner.Run(context.Background(), path, Context{
		Action:    ActionPreUpdate,
		Container: "sonarr",
		NewImage:  "x:1.2",
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("Run: %v\noutput: %s", err, out)
	}
	if !strings.Contains(string(out), "container=sonarr action=pre-update new=x:1.2") {
		t.Errorf("env vars not propagated; got: %s", out)
	}
}

func TestExecRunner_NonZeroExitIsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hook.sh")
	script := `#!/bin/sh
echo "boom" >&2
exit 7
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := ExecRunner{}.Run(context.Background(), path, Context{Action: ActionPreUpdate}, 5*time.Second)
	if err == nil {
		t.Fatal("expected error on exit code 7")
	}
	if !strings.Contains(string(out), "boom") {
		t.Errorf("expected 'boom' in captured output, got %q", out)
	}
}

func TestExecRunner_TimeoutMessage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hook.sh")
	script := `#!/bin/sh
sleep 5
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := ExecRunner{}.Run(context.Background(), path, Context{}, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err message should mention timeout: %v", err)
	}
}

func TestExecRunner_OutputIsCappedNotInfiniteMemory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hook.sh")
	// Generate ~1MB of output (4x the cap).
	script := `#!/bin/sh
yes "x" | head -c 1048576
exit 0
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := ExecRunner{}.Run(context.Background(), path, Context{}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) <= MaxHookOutput {
		t.Errorf("output not truncated; got %d bytes (cap is %d)", len(out), MaxHookOutput)
	}
	if !bytes.Contains(out, []byte("(truncated)")) {
		t.Errorf("expected truncation marker in output")
	}
}

func TestExecRunner_DoesNotInheritDaemonEnv(t *testing.T) {
	t.Setenv("BULWARK_SLACK_WEBHOOK", "https://hooks.example.com/secret-from-daemon")
	dir := t.TempDir()
	path := filepath.Join(dir, "hook.sh")
	script := `#!/bin/sh
env | grep BULWARK_SLACK_WEBHOOK || echo "not-leaked"
exit 0
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out, _ := ExecRunner{}.Run(context.Background(), path, Context{Action: ActionPreUpdate}, 5*time.Second)
	if !strings.Contains(string(out), "not-leaked") {
		t.Errorf("daemon BULWARK_SLACK_WEBHOOK leaked into hook env: %s", out)
	}
}

func TestFakeRunner_RecordsCalls(t *testing.T) {
	r := NewFakeRunner()
	r.On("/path/to/hook.sh", []byte("ok"), nil)
	out, err := r.Run(context.Background(), "/path/to/hook.sh", Context{
		Action:    ActionPreUpdate,
		Container: "sonarr",
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "ok" {
		t.Errorf("out = %q", out)
	}
	calls := r.Calls()
	if len(calls) != 1 {
		t.Fatalf("len = %d", len(calls))
	}
	if calls[0].Path != "/path/to/hook.sh" || calls[0].Ctx.Container != "sonarr" {
		t.Errorf("call = %+v", calls[0])
	}
}

func TestInvoke_NoPathIsTrue(t *testing.T) {
	r := NewFakeRunner()
	if !Invoke(context.Background(), r, "", Context{}, slog.Default()) {
		t.Error("empty path should return true (no hook configured)")
	}
	if len(r.Calls()) != 0 {
		t.Error("empty path should not invoke runner")
	}
}

func TestInvoke_ErrorReturnsFalse(t *testing.T) {
	r := NewFakeRunner()
	r.On("/h.sh", []byte("err output"), errors.New("exit 1"))
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	if Invoke(context.Background(), r, "/h.sh", Context{Action: ActionPostUpdate}, logger) {
		t.Error("Invoke should return false on hook failure")
	}
}

func TestInvoke_SuccessReturnsTrue(t *testing.T) {
	r := NewFakeRunner()
	r.On("/h.sh", []byte("ok"), nil)
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	if !Invoke(context.Background(), r, "/h.sh", Context{Action: ActionPreUpdate}, logger) {
		t.Error("Invoke should return true on hook success")
	}
}

func TestTrimOutput(t *testing.T) {
	short := trimOutput([]byte("hello"))
	if short != "hello" {
		t.Errorf("short = %q", short)
	}
	long := trimOutput(bytes.Repeat([]byte("a"), 1024))
	if !strings.HasSuffix(long, "...") {
		t.Errorf("long output not marked as truncated: ends in %q", long[len(long)-10:])
	}
}
