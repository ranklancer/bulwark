package snapshot

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// --- snapshot name encoding -------------------------------------------------

func TestSnapshotName_RoundTrip(t *testing.T) {
	when := time.Date(2026, 5, 1, 9, 30, 45, 0, time.UTC)
	cases := []struct {
		label string
		want  string
	}{
		{"", "bulwark-20260501T093045Z"},
		{"sonarr", "bulwark-sonarr-20260501T093045Z"},
		{"with spaces!", "bulwark-withspaces-20260501T093045Z"},
		{"keep-dots.ok", "bulwark-keep-dots.ok-20260501T093045Z"},
	}
	for _, tc := range cases {
		got := snapshotName(tc.label, when)
		if got != tc.want {
			t.Errorf("snapshotName(%q) = %q, want %q", tc.label, got, tc.want)
		}
	}
}

func TestParseSnapshotName(t *testing.T) {
	when := time.Date(2026, 5, 1, 9, 30, 45, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		wantLabel string
		ok        bool
	}{
		{"bulwark-20260501T093045Z", "", true},
		{"bulwark-sonarr-20260501T093045Z", "sonarr", true},
		{"bulwark-radarr-with-dashes-20260501T093045Z", "radarr-with-dashes", true},
		{"snapshot-mine", "", false},
		{"bulwark-bad", "", false},
		{"bulwark-foo-not-a-time", "", false},
	} {
		gotLabel, gotTime, ok := parseSnapshotName(tc.name)
		if ok != tc.ok {
			t.Errorf("parseSnapshotName(%q) ok = %v, want %v", tc.name, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if gotLabel != tc.wantLabel {
			t.Errorf("parseSnapshotName(%q) label = %q, want %q", tc.name, gotLabel, tc.wantLabel)
		}
		if !gotTime.Equal(when) {
			t.Errorf("parseSnapshotName(%q) time = %s, want %s", tc.name, gotTime, when)
		}
	}
}

// --- New() factory ----------------------------------------------------------

func TestNew_KnownBackends(t *testing.T) {
	for _, name := range []string{"zfs", "btrfs"} {
		b, err := New(name)
		if err != nil {
			t.Errorf("New(%q): %v", name, err)
		}
		if b == nil {
			t.Errorf("New(%q) returned nil backend", name)
		}
		if b != nil && b.Name() != name {
			t.Errorf("backend %q reports name %q", name, b.Name())
		}
	}
}

func TestNew_NoneReturnsNil(t *testing.T) {
	b, err := New("none")
	if err != nil || b != nil {
		t.Errorf("New(\"none\") = (%v, %v), want (nil, nil)", b, err)
	}
	b, err = New("")
	if err != nil || b != nil {
		t.Errorf("New(\"\") = (%v, %v), want (nil, nil)", b, err)
	}
}

func TestNew_UnknownErrors(t *testing.T) {
	if _, err := New("magic"); err == nil {
		t.Error("expected error for unknown backend")
	}
}

// --- ZFS backend ------------------------------------------------------------

func TestZFS_SnapshotEmitsCorrectCommand(t *testing.T) {
	r := NewFakeRunner()
	b := &ZFSBackend{
		Runner: r,
		Now:    func() time.Time { return time.Date(2026, 5, 1, 9, 30, 45, 0, time.UTC) },
	}
	id, err := b.Snapshot(context.Background(), "tank/docker/sonarr", "pre-update")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	want := "tank/docker/sonarr@bulwark-pre-update-20260501T093045Z"
	if id != want {
		t.Errorf("id = %q, want %q", id, want)
	}
	if calls := r.Calls(); len(calls) != 1 || calls[0] != "zfs snapshot "+want {
		t.Errorf("calls = %v", calls)
	}
}

func TestZFS_RestoreEmitsRollback(t *testing.T) {
	r := NewFakeRunner()
	b := &ZFSBackend{Runner: r}
	if err := b.Restore(context.Background(), "tank/data@bulwark-x-20260501T000000Z"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	wanted := "zfs rollback -r tank/data@bulwark-x-20260501T000000Z"
	if calls := r.Calls(); len(calls) != 1 || calls[0] != wanted {
		t.Errorf("calls = %v, want [%q]", calls, wanted)
	}
}

func TestZFS_DestroyEmitsDestroy(t *testing.T) {
	r := NewFakeRunner()
	b := &ZFSBackend{Runner: r}
	if err := b.Destroy(context.Background(), "tank/data@bulwark-x-20260501T000000Z"); err != nil {
		t.Fatal(err)
	}
	wanted := "zfs destroy tank/data@bulwark-x-20260501T000000Z"
	if calls := r.Calls(); calls[0] != wanted {
		t.Errorf("call = %q, want %q", calls[0], wanted)
	}
}

func TestZFS_ListParsesAndFiltersForeignSnapshots(t *testing.T) {
	r := NewFakeRunner()
	r.On(
		"zfs list -H -p -d 1 -o name,creation -t snapshot tank/data",
		[]byte(
			"tank/data@bulwark-pre-20260501T093045Z\t1714555845\n"+
				"tank/data@bulwark-pre-20260502T093045Z\t1714642245\n"+
				"tank/data@manual-by-user\t1714000000\n"+
				"tank/data@auto-snap-2026-05-01\t1714000000\n",
		),
		nil,
	)
	b := &ZFSBackend{Runner: r}
	got, err := b.List(context.Background(), "tank/data")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d snapshots, want 2 (foreign filtered)", len(got))
	}
	for _, s := range got {
		if s.Target != "tank/data" {
			t.Errorf("Target = %q", s.Target)
		}
		if s.Label != "pre" {
			t.Errorf("Label = %q", s.Label)
		}
		if s.CreatedAt.IsZero() {
			t.Errorf("CreatedAt is zero for %+v", s)
		}
	}
}

func TestZFS_SnapshotPropagatesError(t *testing.T) {
	r := NewFakeRunner()
	r.On("zfs snapshot tank/data@bulwark-x-20260501T000000Z",
		nil, errors.New("dataset does not exist"))
	b := &ZFSBackend{
		Runner: r,
		Now:    func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) },
	}
	_, err := b.Snapshot(context.Background(), "tank/data", "x")
	if err == nil || !strings.Contains(err.Error(), "dataset does not exist") {
		t.Errorf("err = %v, want dataset-not-exist", err)
	}
}

func TestZFS_RejectsEmptyTarget(t *testing.T) {
	b := &ZFSBackend{Runner: NewFakeRunner()}
	if _, err := b.Snapshot(context.Background(), "", "x"); err == nil {
		t.Error("expected error for empty target")
	}
}

// --- Btrfs backend ----------------------------------------------------------

func TestBtrfs_SnapshotCreatesUnderHiddenDir(t *testing.T) {
	r := NewFakeRunner()
	b := &BtrfsBackend{
		Runner: r,
		Now:    func() time.Time { return time.Date(2026, 5, 1, 9, 30, 45, 0, time.UTC) },
	}
	id, err := b.Snapshot(context.Background(), "/mnt/data/sonarr", "pre")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	wantID := "/mnt/data/.bulwark-snapshots/sonarr--bulwark-pre-20260501T093045Z"
	if id != wantID {
		t.Errorf("id = %q, want %q", id, wantID)
	}
	calls := r.Calls()
	if len(calls) < 2 {
		t.Fatalf("expected mkdir + snapshot calls, got %v", calls)
	}
	if calls[0] != "mkdir -p /mnt/data/.bulwark-snapshots" {
		t.Errorf("mkdir call = %q", calls[0])
	}
	if calls[1] != "btrfs subvolume snapshot -r /mnt/data/sonarr "+wantID {
		t.Errorf("snapshot call = %q", calls[1])
	}
}

func TestBtrfs_RestoreSwapDance(t *testing.T) {
	r := NewFakeRunner()
	b := &BtrfsBackend{
		Runner: r,
		Now:    func() time.Time { return time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC) },
	}
	id := "/mnt/data/.bulwark-snapshots/sonarr--bulwark-pre-20260501T093045Z"
	if err := b.Restore(context.Background(), id); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	calls := r.Calls()
	// Expected sequence:
	//   mv /mnt/data/sonarr /mnt/data/sonarr-bulwark-failed-...
	//   btrfs subvolume snapshot <id> /mnt/data/sonarr
	//   btrfs subvolume delete /mnt/data/sonarr-bulwark-failed-...
	if len(calls) != 3 {
		t.Fatalf("expected 3 calls, got %d: %v", len(calls), calls)
	}
	if !strings.HasPrefix(calls[0], "mv /mnt/data/sonarr ") || !strings.Contains(calls[0], "-bulwark-failed-") {
		t.Errorf("mv call = %q", calls[0])
	}
	if calls[1] != "btrfs subvolume snapshot "+id+" /mnt/data/sonarr" {
		t.Errorf("restore call = %q", calls[1])
	}
	if !strings.HasPrefix(calls[2], "btrfs subvolume delete /mnt/data/sonarr-bulwark-failed-") {
		t.Errorf("cleanup call = %q", calls[2])
	}
}

func TestBtrfs_RestoreRollsBackOnFailure(t *testing.T) {
	r := NewFakeRunner()
	id := "/mnt/data/.bulwark-snapshots/sonarr--bulwark-pre-20260501T093045Z"
	// Fail the snapshot-restore step. The mv-back step should follow.
	r.On("btrfs subvolume snapshot "+id+" /mnt/data/sonarr", nil, errors.New("EBUSY"))
	b := &BtrfsBackend{
		Runner: r,
		Now:    func() time.Time { return time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC) },
	}
	err := b.Restore(context.Background(), id)
	if err == nil {
		t.Fatal("expected error")
	}
	calls := r.Calls()
	// The 3rd call should be mv-back.
	if len(calls) < 3 {
		t.Fatalf("expected mv-back attempt, got calls: %v", calls)
	}
	if !strings.HasPrefix(calls[2], "mv /mnt/data/sonarr-bulwark-failed-") || !strings.HasSuffix(calls[2], "/mnt/data/sonarr") {
		t.Errorf("mv-back call = %q", calls[2])
	}
}

func TestBtrfs_DestroyEmitsDelete(t *testing.T) {
	r := NewFakeRunner()
	b := &BtrfsBackend{Runner: r}
	id := "/mnt/data/.bulwark-snapshots/sonarr--bulwark-x-20260501T000000Z"
	if err := b.Destroy(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	want := "btrfs subvolume delete " + id
	if calls := r.Calls(); calls[0] != want {
		t.Errorf("call = %q, want %q", calls[0], want)
	}
}

func TestBtrfs_ListParsesEntries(t *testing.T) {
	r := NewFakeRunner()
	r.On("ls -1 /mnt/data/.bulwark-snapshots", []byte(
		"sonarr--bulwark-pre-20260501T093045Z\n"+
			"sonarr--bulwark-pre-20260502T093045Z\n"+
			"radarr--bulwark-pre-20260501T093045Z\n"+ // different target — filtered
			"random-not-mine\n",
	), nil)
	b := &BtrfsBackend{Runner: r}
	got, err := b.List(context.Background(), "/mnt/data/sonarr")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d, want 2 (other targets and non-bulwark filtered)", len(got))
	}
}

func TestBtrfs_ListMissingDirIsNotError(t *testing.T) {
	r := NewFakeRunner()
	r.On("ls -1 /mnt/data/.bulwark-snapshots", nil,
		errors.New("ls: cannot access '/mnt/data/.bulwark-snapshots': No such file or directory"))
	b := &BtrfsBackend{Runner: r}
	got, err := b.List(context.Background(), "/mnt/data/sonarr")
	if err != nil {
		t.Fatalf("missing dir should not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
}

func TestTargetFromSnapshotID(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"/mnt/data/.bulwark-snapshots/sonarr--bulwark-x-20260501T000000Z", "/mnt/data/sonarr", true},
		{"/srv/.bulwark-snapshots/db--bulwark-pre-20260501T000000Z", "/srv/db", true},
		{"/elsewhere/sonarr--bulwark-x", "", false},
		{"/mnt/data/.bulwark-snapshots/no-double-dash", "", false},
	}
	for _, tc := range cases {
		got, err := targetFromSnapshotID(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("targetFromSnapshotID(%q) err=%v, ok=%v", tc.in, err, tc.ok)
			continue
		}
		if tc.ok && got != tc.want {
			t.Errorf("targetFromSnapshotID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --- Availability -----------------------------------------------------------

func TestZFS_AvailableDelegatesToRunner(t *testing.T) {
	r := NewFakeRunner()
	r.SetAvailable("zfs", false)
	b := &ZFSBackend{Runner: r}
	if b.Available(context.Background()) {
		t.Error("expected false when binary not available")
	}
	r.SetAvailable("zfs", true)
	if !b.Available(context.Background()) {
		t.Error("expected true when binary available")
	}
}

func TestBtrfs_AvailableDelegatesToRunner(t *testing.T) {
	r := NewFakeRunner()
	r.SetAvailable("btrfs", false)
	b := &BtrfsBackend{Runner: r}
	if b.Available(context.Background()) {
		t.Error("expected false")
	}
}
