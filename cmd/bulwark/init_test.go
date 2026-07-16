package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/internal/config"
)

func TestCmdInit_WritesValidConfig(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bulwark.yaml")
	var stdout, stderr bytes.Buffer

	if err := cmdInit([]string{"--output", out}, &stdout, &stderr); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}

	// File exists at mode 0o600 (skip the perms check on Windows
	// where the bit-for-bit translation differs from POSIX).
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("mode = %o, want 0600", got)
		}
	}

	// File round-trips through config.Load without env-var
	// substitution — the literal token is sufficient.
	cfg, err := config.Load(out)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.API.Auth.Type != "bearer" {
		t.Errorf("API.Auth.Type = %q, want bearer", cfg.API.Auth.Type)
	}
	if len(cfg.API.Auth.Token) != 64 {
		t.Errorf("token length = %d, want 64 hex chars", len(cfg.API.Auth.Token))
	}

	// Stdout includes the token + the next-step instructions.
	out1 := stdout.String()
	if !strings.Contains(out1, cfg.API.Auth.Token) {
		t.Error("stdout missing the bearer token")
	}
	if !strings.Contains(out1, "bulwark run") {
		t.Error("stdout missing next-step run command")
	}
	if !strings.Contains(out1, "/login") {
		t.Error("stdout missing dashboard login pointer")
	}
}

func TestCmdInit_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bulwark.yaml")
	if err := os.WriteFile(out, []byte("existing: yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := cmdInit([]string{"--output", out}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error overwriting existing file")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("err = %q, want 'already exists'", err.Error())
	}

	// File untouched.
	body, _ := os.ReadFile(out)
	if string(body) != "existing: yes\n" {
		t.Errorf("file overwritten despite no --force: %q", body)
	}
}

func TestCmdInit_ForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bulwark.yaml")
	if err := os.WriteFile(out, []byte("existing: yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if err := cmdInit([]string{"--output", out, "--force"}, &stdout, &stderr); err != nil {
		t.Fatalf("cmdInit --force: %v", err)
	}
	body, _ := os.ReadFile(out)
	if strings.Contains(string(body), "existing: yes") {
		t.Error("--force did not overwrite the existing file")
	}
}

func TestCmdInit_TokensAreUnique(t *testing.T) {
	// Two consecutive runs must produce different tokens — a regression
	// here would mean we'd accidentally introduced a fixed seed.
	dir := t.TempDir()
	a := filepath.Join(dir, "a.yaml")
	b := filepath.Join(dir, "b.yaml")
	var stdout, stderr bytes.Buffer

	if err := cmdInit([]string{"--output", a}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if err := cmdInit([]string{"--output", b}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}

	cfgA, _ := config.Load(a)
	cfgB, _ := config.Load(b)
	if cfgA.API.Auth.Token == cfgB.API.Auth.Token {
		t.Error("two init runs produced the same token")
	}
}

func TestCmdInit_RejectsPositionalArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := cmdInit([]string{"unexpected"}, &stdout, &stderr)
	if err == nil {
		t.Error("expected error for unexpected positional argument")
	}
}
