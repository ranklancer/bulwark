package docker

import (
	"testing"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

func TestParseLabels_DefaultsToEnabled(t *testing.T) {
	got := ParseLabels(nil)
	if !got.Enabled {
		t.Error("expected default Enabled=true (opt-out model)")
	}
	if got.RiskOverride != types.RiskUnknown {
		t.Errorf("RiskOverride = %v, want Unknown", got.RiskOverride)
	}
}

func TestParseLabels_OptOut(t *testing.T) {
	got := ParseLabels(map[string]string{"bulwark.enable": "false"})
	if got.Enabled {
		t.Error("bulwark.enable=false should disable")
	}
	got = ParseLabels(map[string]string{"bulwark.enable": "no"})
	if got.Enabled {
		t.Error("bulwark.enable=no should disable")
	}
	got = ParseLabels(map[string]string{"bulwark.enable": "garbage"})
	if !got.Enabled {
		t.Error("unparseable bulwark.enable should fall back to enabled (opt-out)")
	}
}

func TestParseLabels_AllOverrides(t *testing.T) {
	in := map[string]string{
		"bulwark.enable":           "true",
		"bulwark.risk":             "review",
		"bulwark.schedule":         "0 3 * * 0",
		"bulwark.hook.pre-update":  "/hooks/pre.sh",
		"bulwark.hook.post-update": "/hooks/post.sh",
		"bulwark.hook.rollback":    "/hooks/rb.sh",
		"bulwark.health.timeout":   "300s",
		"bulwark.snapshot.dataset": "pool/docker/myapp",
		"bulwark.policy.patch":     "safe",
		"bulwark.policy.minor":     "review",
		"bulwark.policy.major":     "breaking",
		"bulwark.unrecognized":     "something",
		"unrelated":                "ignored",
	}
	got := ParseLabels(in)
	if got.RiskOverride != types.RiskReview {
		t.Errorf("RiskOverride = %v", got.RiskOverride)
	}
	if got.Schedule != "0 3 * * 0" {
		t.Errorf("Schedule = %q", got.Schedule)
	}
	if got.PreUpdateHook != "/hooks/pre.sh" || got.PostUpdateHook != "/hooks/post.sh" || got.RollbackHook != "/hooks/rb.sh" {
		t.Errorf("hooks = %+v", got)
	}
	if got.HealthTimeout != "300s" {
		t.Errorf("HealthTimeout = %q", got.HealthTimeout)
	}
	if got.SnapshotDataset != "pool/docker/myapp" {
		t.Errorf("SnapshotDataset = %q", got.SnapshotDataset)
	}
	if got.PolicyPatch != types.RiskSafe || got.PolicyMinor != types.RiskReview || got.PolicyMajor != types.RiskBreaking {
		t.Errorf("policy overrides = %+v", got)
	}
	if got.Extra["unrecognized"] != "something" {
		t.Errorf("Extra missing unrecognized label: %+v", got.Extra)
	}
	if _, present := got.Extra["unrelated"]; present {
		t.Errorf("non-bulwark label leaked into Extra: %+v", got.Extra)
	}
}
