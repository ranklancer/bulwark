package snapshot

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func newRestic(t *testing.T) (*ResticBackend, *FakeRunner) {
	t.Helper()
	fr := NewFakeRunner()
	r := NewRestic("/srv/backups/repo", "/etc/bulwark/restic.password", fr)
	r.Now = func() time.Time { return time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC) }
	return r, fr
}

func TestRestic_AvailableRequiresRepoAndPassword(t *testing.T) {
	fr := NewFakeRunner()
	fr.SetAvailable("restic", true)

	good := NewRestic("/repo", "/pw", fr)
	if !good.Available(context.Background()) {
		t.Error("expected available with repo + pw + binary")
	}

	missingRepo := NewRestic("", "/pw", fr)
	if missingRepo.Available(context.Background()) {
		t.Error("missing repo should report unavailable")
	}

	missingPw := NewRestic("/repo", "", fr)
	if missingPw.Available(context.Background()) {
		t.Error("missing password file should report unavailable")
	}

	// Binary missing.
	frNoBin := NewFakeRunner()
	frNoBin.SetAvailable("restic", false)
	noBin := NewRestic("/repo", "/pw", frNoBin)
	if noBin.Available(context.Background()) {
		t.Error("missing binary should report unavailable")
	}
}

func TestRestic_SnapshotParsesIDFromBackupJSON(t *testing.T) {
	r, fr := newRestic(t)
	// Tag formed from snapshotName at the fixed Now timestamp.
	expectedTag := snapshotName("sonarr", r.Now())
	invocation := strings.Join([]string{
		"restic", "--repo", "/srv/backups/repo",
		"--password-file", "/etc/bulwark/restic.password",
		"backup", "/var/lib/sonarr",
		"--tag", "bulwark",
		"--tag", expectedTag,
		"--json",
	}, " ")
	// Restic's --json output: line-delimited JSON; the summary line carries snapshot_id.
	output := `{"message_type":"status","percent_done":0.5}
{"message_type":"summary","files_new":3,"snapshot_id":"abc123def456"}
`
	fr.On(invocation, []byte(output), nil)

	id, err := r.Snapshot(context.Background(), "/var/lib/sonarr", "sonarr")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if id != "abc123def456" {
		t.Errorf("snapshot id = %q, want abc123def456", id)
	}
}

func TestRestic_SnapshotMissingTargetFails(t *testing.T) {
	r, _ := newRestic(t)
	if _, err := r.Snapshot(context.Background(), "", "sonarr"); err == nil {
		t.Error("empty target should fail")
	}
}

func TestRestic_SnapshotNoSummaryIDFails(t *testing.T) {
	r, fr := newRestic(t)
	tag := snapshotName("sonarr", r.Now())
	invocation := "restic --repo /srv/backups/repo --password-file /etc/bulwark/restic.password backup /var/lib/sonarr --tag bulwark --tag " + tag + " --json"
	// Output without summary message — defensive: shouldn't happen in
	// practice but Bulwark must not invent a snapshot ID.
	fr.On(invocation, []byte(`{"message_type":"status"}`), nil)

	if _, err := r.Snapshot(context.Background(), "/var/lib/sonarr", "sonarr"); err == nil {
		t.Error("missing snapshot_id should fail loudly")
	}
}

func TestRestic_RestoreFormsCorrectInvocation(t *testing.T) {
	r, fr := newRestic(t)
	invocation := "restic --repo /srv/backups/repo --password-file /etc/bulwark/restic.password restore abc123 --target / --delete"
	fr.On(invocation, []byte(""), nil)
	if err := r.Restore(context.Background(), "abc123"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	calls := fr.Calls()
	if len(calls) != 1 || calls[0] != invocation {
		t.Errorf("expected exactly one matching call; got %v", calls)
	}
}

func TestRestic_RestoreMissingIDFails(t *testing.T) {
	r, _ := newRestic(t)
	if err := r.Restore(context.Background(), ""); err == nil {
		t.Error("empty id should fail")
	}
}

func TestRestic_DestroyUsesForgetWithPrune(t *testing.T) {
	r, fr := newRestic(t)
	invocation := "restic --repo /srv/backups/repo --password-file /etc/bulwark/restic.password forget xyz999 --prune"
	fr.On(invocation, []byte(""), nil)
	if err := r.Destroy(context.Background(), "xyz999"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	calls := fr.Calls()
	if len(calls) != 1 || calls[0] != invocation {
		t.Errorf("expected forget --prune call; got %v", calls)
	}
}

func TestRestic_ListFiltersByPath(t *testing.T) {
	r, fr := newRestic(t)
	invocation := "restic --repo /srv/backups/repo --password-file /etc/bulwark/restic.password snapshots --tag bulwark --json"
	output := `[
		{"id":"abc","time":"2026-05-01T09:00:00Z","paths":["/var/lib/sonarr"],"tags":["bulwark","bulwark-sonarr-20260501T090000Z"]},
		{"id":"def","time":"2026-05-01T10:00:00Z","paths":["/var/lib/radarr"],"tags":["bulwark","bulwark-radarr-20260501T100000Z"]},
		{"id":"ghi","time":"2026-05-02T09:00:00Z","paths":["/var/lib/sonarr","/etc"],"tags":["bulwark"]}
	]`
	fr.On(invocation, []byte(output), nil)

	got, err := r.List(context.Background(), "/var/lib/sonarr")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[0].ID != "abc" || got[1].ID != "ghi" {
		t.Errorf("got = %+v", got)
	}
	if got[0].Label != "sonarr" {
		t.Errorf("got[0].Label = %q, want sonarr", got[0].Label)
	}
	if got[0].Target != "/var/lib/sonarr" {
		t.Errorf("got[0].Target = %q", got[0].Target)
	}
}

func TestRestic_ListMissingTargetFails(t *testing.T) {
	r, _ := newRestic(t)
	if _, err := r.List(context.Background(), ""); err == nil {
		t.Error("empty target should fail")
	}
}

func TestRestic_BackupErrorPropagates(t *testing.T) {
	r, fr := newRestic(t)
	tag := snapshotName("sonarr", r.Now())
	invocation := "restic --repo /srv/backups/repo --password-file /etc/bulwark/restic.password backup /var/lib/sonarr --tag bulwark --tag " + tag + " --json"
	fr.On(invocation, nil, errors.New("repository locked"))
	if _, err := r.Snapshot(context.Background(), "/var/lib/sonarr", "sonarr"); err == nil {
		t.Error("backup error should propagate")
	}
}
