package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/ranklancer/bulwark/internal/api"
	"github.com/ranklancer/bulwark/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestIsLoopbackListen(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080":  true,
		"localhost:8080":  true,
		"[::1]:8080":      true,
		"127.0.0.1":       true,
		":8080":           false,
		"0.0.0.0:8080":    false,
		"[::]:8080":       false,
		"192.0.2.10:8080": false,
		"":                false,
	}
	for in, want := range cases {
		if got := isLoopbackListen(in); got != want {
			t.Errorf("isLoopbackListen(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestEnforceAnonymousBinding(t *testing.T) {
	log := discardLogger()
	if err := enforceAnonymousBinding(api.AnonymousAuth{}, ":8080", nil, log); err == nil {
		t.Error("anonymous on :8080 (all interfaces) must be refused")
	}
	if err := enforceAnonymousBinding(api.AnonymousAuth{}, "127.0.0.1:8080", nil, log); err != nil {
		t.Errorf("anonymous on loopback must be allowed, got %v", err)
	}
	cfg := &config.Config{}
	cfg.API.Auth.AllowAnonymous = true
	if err := enforceAnonymousBinding(api.AnonymousAuth{}, "0.0.0.0:8080", cfg, log); err != nil {
		t.Errorf("allow_anonymous override must permit non-loopback, got %v", err)
	}
	if err := enforceAnonymousBinding(api.BearerAuth{Token: "x"}, ":8080", nil, log); err != nil {
		t.Errorf("non-anonymous auth must always pass, got %v", err)
	}
}

func TestEnforceSnapshotApply(t *testing.T) {
	if err := enforceSnapshotApply(false, nil); err != nil {
		t.Errorf("no --apply must pass, got %v", err)
	}
	if err := enforceSnapshotApply(true, nil); err == nil {
		t.Error("--apply with nil config (backend none) must be refused")
	}
	none := &config.Config{}
	none.Snapshots.Backend = "none"
	if err := enforceSnapshotApply(true, none); err == nil {
		t.Error("--apply with backend=none must be refused")
	}
	override := &config.Config{}
	override.Snapshots.Backend = "none"
	override.Snapshots.AllowApplyWithoutBackend = true
	if err := enforceSnapshotApply(true, override); err != nil {
		t.Errorf("allow_apply_without_backend override must permit, got %v", err)
	}
	zfs := &config.Config{}
	zfs.Snapshots.Backend = "zfs"
	if err := enforceSnapshotApply(true, zfs); err != nil {
		t.Errorf("--apply with a real backend must pass, got %v", err)
	}
}
