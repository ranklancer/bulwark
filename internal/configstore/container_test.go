package configstore

import (
	"testing"
)

func TestStore_ContainerOverride_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	auto := true
	ds := "tank/services/sonarr"
	if err := s.SetContainerOverride("sonarr", ContainerOverride{
		SnapshotAuto:    &auto,
		SnapshotDataset: &ds,
	}); err != nil {
		t.Fatal(err)
	}

	// Reopen and confirm persistence.
	s2, _ := Open(dir)
	got, ok := s2.ContainerOverride("sonarr")
	if !ok {
		t.Fatal("expected stored override after reopen")
	}
	if got.SnapshotAuto == nil || !*got.SnapshotAuto {
		t.Errorf("snapshot_auto did not round-trip: %+v", got)
	}
	if got.SnapshotDataset == nil || *got.SnapshotDataset != ds {
		t.Errorf("snapshot_dataset did not round-trip: %+v", got)
	}
	if got.UpdatedAt.IsZero() {
		t.Errorf("updated_at was not set")
	}
}

func TestStore_DeleteContainerOverride_Idempotent(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	if err := s.DeleteContainerOverride("never-existed"); err != nil {
		t.Errorf("DeleteContainerOverride should be idempotent: %v", err)
	}
	auto := true
	_ = s.SetContainerOverride("x", ContainerOverride{SnapshotAuto: &auto})
	if err := s.DeleteContainerOverride("x"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ContainerOverride("x"); ok {
		t.Error("override still present after delete")
	}
}

func TestComputeEffectiveSnapshot(t *testing.T) {
	str := func(s string) *string { return &s }
	bo := func(b bool) *bool { return &b }
	cases := []struct {
		name         string
		labels       map[string]string
		override     ContainerOverride
		wantDataset  string
		wantAuto     bool
		wantReason   string
	}{
		{
			"override-dataset wins over everything",
			map[string]string{"bulwark.snapshot.dataset": "label/ds", "bulwark.snapshot.auto": "true"},
			ContainerOverride{SnapshotDataset: str("override/ds")},
			"override/ds", false, "override-dataset",
		},
		{
			"override-dataset empty string = explicit disable",
			map[string]string{"bulwark.snapshot.dataset": "label/ds"},
			ContainerOverride{SnapshotDataset: str("")},
			"", false, "override-disabled",
		},
		{
			"override-auto true overrides label",
			map[string]string{"bulwark.snapshot.auto": "false"},
			ContainerOverride{SnapshotAuto: bo(true)},
			"", true, "override-auto",
		},
		{
			"override-auto false overrides label",
			map[string]string{"bulwark.snapshot.auto": "true"},
			ContainerOverride{SnapshotAuto: bo(false)},
			"", false, "override-no-auto",
		},
		{
			"label dataset",
			map[string]string{"bulwark.snapshot.dataset": "tank/x"},
			ContainerOverride{},
			"tank/x", false, "label-dataset",
		},
		{
			"label auto",
			map[string]string{"bulwark.snapshot.auto": "yes"},
			ContainerOverride{},
			"", true, "label-auto",
		},
		{
			"no signal",
			nil,
			ContainerOverride{},
			"", false, "none",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ComputeEffectiveSnapshot(c.labels, c.override)
			if got.Dataset != c.wantDataset || got.Auto != c.wantAuto || got.Reason != c.wantReason {
				t.Errorf("got %+v, want {Dataset:%q Auto:%v Reason:%q}", got, c.wantDataset, c.wantAuto, c.wantReason)
			}
		})
	}
}
