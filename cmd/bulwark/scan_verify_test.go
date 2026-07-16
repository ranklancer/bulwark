package main

import (
	"testing"

	"github.com/ranklancer/bulwark/internal/config"
	"github.com/ranklancer/bulwark/internal/updater"
)

func TestAttachVerifyGate(t *testing.T) {
	enabled := &config.Config{Verify: config.VerifyConfig{
		Enabled:    true,
		Signature:  config.VerifySignatureConfig{Mode: "off"},
		Provenance: config.VerifyProvenanceConfig{Mode: "off"},
	}}
	disabled := &config.Config{Verify: config.VerifyConfig{Enabled: false}}

	t.Run("enabled wires the gate", func(t *testing.T) {
		u := &updater.Updater{}
		if err := attachVerifyGate(u, enabled); err != nil {
			t.Fatalf("attachVerifyGate: %v", err)
		}
		if u.Verify == nil {
			t.Fatal("scan --apply must wire verify-before-pull when verification is enabled")
		}
	})
	t.Run("disabled is a no-op", func(t *testing.T) {
		u := &updater.Updater{}
		if err := attachVerifyGate(u, disabled); err != nil {
			t.Fatalf("attachVerifyGate: %v", err)
		}
		if u.Verify != nil {
			t.Fatal("must not wire a gate when verification is disabled")
		}
	})
	t.Run("nil loaded is a no-op", func(t *testing.T) {
		u := &updater.Updater{}
		if err := attachVerifyGate(u, nil); err != nil {
			t.Fatalf("attachVerifyGate: %v", err)
		}
		if u.Verify != nil {
			t.Fatal("must not wire a gate for a nil config")
		}
	})
	t.Run("nil updater is a safe no-op", func(t *testing.T) {
		if err := attachVerifyGate(nil, enabled); err != nil {
			t.Fatalf("attachVerifyGate(nil,...): %v", err)
		}
	})
}
