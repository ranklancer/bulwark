package configstore

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ContainerOverride is per-container UI-driven settings the dashboard
// can edit without touching Docker labels (which require a container
// recreate). Each field is a pointer so unset = fall back to label.
//
// Keyed by stable container name (which Compose preserves across
// recreates). The container ID would survive in-place updates but
// breaks the moment Compose removes + re-adds a service, so name is
// the right granularity here.
type ContainerOverride struct {
	// SnapshotAuto, when non-nil, controls auto-snapshot inference at
	// apply time. true forces auto-infer; false disables it even when
	// the bulwark.snapshot.auto label is set. nil = use the label.
	SnapshotAuto *bool `json:"snapshot_auto,omitempty"`

	// SnapshotDataset, when non-nil, overrides the
	// bulwark.snapshot.dataset label. Empty string disables snapshot
	// for that container regardless of label; nil = use the label.
	SnapshotDataset *string `json:"snapshot_dataset,omitempty"`

	UpdatedAt time.Time `json:"updated_at"`
}

// ContainerOverride returns the override for the given container
// name. Second return value reports whether a record exists.
func (s *Store) ContainerOverride(name string) (ContainerOverride, bool) {
	if s == nil || name == "" {
		return ContainerOverride{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.data.Containers[name]
	return o, ok
}

// ContainerOverrides returns a copy of every persisted container
// override. The dashboard's Containers page uses this to merge with
// the live scan-derived container list.
func (s *Store) ContainerOverrides() map[string]ContainerOverride {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]ContainerOverride, len(s.data.Containers))
	for k, v := range s.data.Containers {
		out[k] = v
	}
	return out
}

// SetContainerOverride persists a per-container override. Empty name
// is rejected; SnapshotAuto and SnapshotDataset are optional. To clear
// every override for a container, call DeleteContainerOverride.
func (s *Store) SetContainerOverride(name string, o ContainerOverride) error {
	if s == nil {
		return errors.New("configstore: nil store")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("configstore: container name is required")
	}
	o.UpdatedAt = time.Now().UTC()
	if o.SnapshotDataset != nil {
		trimmed := strings.TrimSpace(*o.SnapshotDataset)
		o.SnapshotDataset = &trimmed
	}
	_, err := s.Mutate(func(d *Data) error {
		if d.Containers == nil {
			d.Containers = map[string]ContainerOverride{}
		}
		d.Containers[name] = o
		return nil
	})
	return err
}

// DeleteContainerOverride removes the persisted override for name.
// Missing names return nil (idempotent — the dashboard's "reset" button
// shouldn't 404 just because nothing's recorded).
func (s *Store) DeleteContainerOverride(name string) error {
	if s == nil {
		return errors.New("configstore: nil store")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("configstore: container name is required")
	}
	_, err := s.Mutate(func(d *Data) error {
		delete(d.Containers, name)
		return nil
	})
	return err
}

// EffectiveSnapshotPlan combines the operator's labels with the
// configstore override to produce a single decision for the apply
// pipeline. Returns the dataset to snapshot (empty if none), whether
// auto-inference should run (when dataset is empty), and a reason
// string suitable for logging.
//
// Precedence:
//
//  1. override.SnapshotDataset != nil       → use it verbatim
//  2. override.SnapshotAuto != nil          → use it (true / false)
//  3. label "bulwark.snapshot.dataset" set  → use it
//  4. label "bulwark.snapshot.auto" truthy  → auto = true
//  5. otherwise                              → no snapshot
//
// Returns the same shape regardless of the rule that fired so callers
// don't have to re-check precedence.
type EffectiveSnapshotPlan struct {
	Dataset string
	Auto    bool
	Reason  string
}

func ComputeEffectiveSnapshot(labels map[string]string, override ContainerOverride) EffectiveSnapshotPlan {
	if override.SnapshotDataset != nil {
		ds := strings.TrimSpace(*override.SnapshotDataset)
		if ds != "" {
			return EffectiveSnapshotPlan{Dataset: ds, Reason: "override-dataset"}
		}
		// Explicit empty override = "no snapshot, ignore label".
		return EffectiveSnapshotPlan{Reason: "override-disabled"}
	}
	if override.SnapshotAuto != nil {
		if *override.SnapshotAuto {
			return EffectiveSnapshotPlan{Auto: true, Reason: "override-auto"}
		}
		return EffectiveSnapshotPlan{Reason: "override-no-auto"}
	}
	if ds := strings.TrimSpace(labels["bulwark.snapshot.dataset"]); ds != "" {
		return EffectiveSnapshotPlan{Dataset: ds, Reason: "label-dataset"}
	}
	if isTruthyLabel(labels["bulwark.snapshot.auto"]) {
		return EffectiveSnapshotPlan{Auto: true, Reason: "label-auto"}
	}
	return EffectiveSnapshotPlan{Reason: "none"}
}

func isTruthyLabel(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// validateContainerOverride checks the override's shape. Empty strings
// for SnapshotDataset are legal (they mean "explicit no-snapshot").
func validateContainerOverride(o ContainerOverride) error {
	if o.SnapshotDataset != nil && len(*o.SnapshotDataset) > 256 {
		return fmt.Errorf("snapshot_dataset is unreasonably long (%d chars)", len(*o.SnapshotDataset))
	}
	return nil
}
