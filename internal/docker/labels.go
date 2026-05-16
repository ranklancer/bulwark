package docker

import (
	"strings"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

// Bulwark labels follow the convention "bulwark.<key>". The full set is
// documented in configs/bulwark.example.yaml; only the labels we already act
// on are parsed here. Unknown bulwark.* labels are returned in Extra so the
// scanner can warn about typos without having to enumerate them in code.
const labelPrefix = "bulwark."

// LabelOverrides is the parsed view of a container's bulwark.* labels.
type LabelOverrides struct {
	// Enabled is true unless an explicit "bulwark.enable=false" label exists.
	// Bulwark's policy is opt-out: containers participate by default.
	Enabled bool

	// RiskOverride is the parsed value of "bulwark.risk", or RiskUnknown if
	// the label is absent or unparseable.
	RiskOverride types.RiskLevel

	// Schedule is the cron expression from "bulwark.schedule", or "" if absent.
	Schedule string

	// PreUpdateHook / PostUpdateHook / RollbackHook are command paths from
	// the bulwark.hook.* labels.
	PreUpdateHook  string
	PostUpdateHook string
	RollbackHook   string

	// HealthTimeout is the value of "bulwark.health.timeout", e.g. "300s".
	// Validation as a time.Duration happens at the consumer.
	HealthTimeout string

	// SnapshotDataset is the value of "bulwark.snapshot.dataset".
	SnapshotDataset string

	// SnapshotAuto is true when "bulwark.snapshot.auto" is set to a
	// truthy value. Tells the apply pipeline to infer the snapshot
	// target from the container's bind mounts + host mount table when
	// SnapshotDataset is empty. Explicit SnapshotDataset always wins.
	SnapshotAuto bool

	// PolicyPatch / PolicyMinor / PolicyMajor are per-container policy
	// overrides from "bulwark.policy.<kind>" labels. RiskUnknown when absent.
	PolicyPatch types.RiskLevel
	PolicyMinor types.RiskLevel
	PolicyMajor types.RiskLevel

	// Extra contains every "bulwark.*" label not matched above. Useful for
	// surfacing typos in CLI output.
	Extra map[string]string
}

// ParseLabels extracts bulwark.* overrides from a container's labels. The
// returned LabelOverrides is always populated; callers don't need a nil check.
func ParseLabels(labels map[string]string) LabelOverrides {
	out := LabelOverrides{
		Enabled: true,
		Extra:   map[string]string{},
	}
	for k, v := range labels {
		if !strings.HasPrefix(k, labelPrefix) {
			continue
		}
		key := strings.TrimPrefix(k, labelPrefix)
		switch key {
		case "enable":
			out.Enabled = parseBool(v, true)
		case "risk":
			out.RiskOverride = types.ParseRiskLevel(v)
		case "schedule":
			out.Schedule = v
		case "hook.pre-update":
			out.PreUpdateHook = v
		case "hook.post-update":
			out.PostUpdateHook = v
		case "hook.rollback":
			out.RollbackHook = v
		case "health.timeout":
			out.HealthTimeout = v
		case "snapshot.dataset":
			out.SnapshotDataset = v
		case "snapshot.auto":
			out.SnapshotAuto = parseBool(v, false)
		case "policy.patch":
			out.PolicyPatch = types.ParseRiskLevel(v)
		case "policy.minor":
			out.PolicyMinor = types.ParseRiskLevel(v)
		case "policy.major":
			out.PolicyMajor = types.ParseRiskLevel(v)
		default:
			out.Extra[key] = v
		}
	}
	return out
}

func parseBool(v string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
