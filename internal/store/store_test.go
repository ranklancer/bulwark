package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func TestOpen_CreatesDataDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !filepath.IsAbs(s.DataDir) {
		t.Errorf("DataDir should be absolute, got %q", s.DataDir)
	}
	if _, err := os.Stat(filepath.Join(s.DataDir, "history")); err != nil {
		t.Errorf("history dir not created: %v", err)
	}
}

func TestOpen_RejectsEmpty(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("expected error for empty data dir")
	}
}

// --- Notification dedup -----------------------------------------------------

func TestShouldNotify_NewKey_IsTrue(t *testing.T) {
	s := openTestStore(t)
	ok, err := s.ShouldNotify(NotificationKey{ContainerID: "abc", RegistryDigest: "sha256:x"},
		types.RiskReview, time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("ShouldNotify on new key should be true")
	}
}

func TestShouldNotify_WithinTTL_IsFalse(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	key := NotificationKey{ContainerID: "abc", RegistryDigest: "sha256:x"}
	if err := s.MarkNotified(key, NotificationRecord{Level: types.RiskReview}, now); err != nil {
		t.Fatal(err)
	}
	ok, err := s.ShouldNotify(key, types.RiskReview, now.Add(time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("ShouldNotify within TTL should be false")
	}
}

func TestShouldNotify_AfterTTL_IsTrue(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	key := NotificationKey{ContainerID: "abc", RegistryDigest: "sha256:x"}
	_ = s.MarkNotified(key, NotificationRecord{Level: types.RiskReview}, now)
	ok, _ := s.ShouldNotify(key, types.RiskReview, now.Add(25*time.Hour), 24*time.Hour)
	if !ok {
		t.Error("ShouldNotify after TTL should be true")
	}
}

func TestShouldNotify_EscalationBypassesTTL(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	key := NotificationKey{ContainerID: "abc", RegistryDigest: "sha256:x"}
	_ = s.MarkNotified(key, NotificationRecord{Level: types.RiskReview}, now)
	// 1 hour later, level escalated to BREAKING (e.g. release notes re-fetched
	// with a breaking keyword discovered): must re-notify even within TTL.
	ok, _ := s.ShouldNotify(key, types.RiskBreaking, now.Add(time.Hour), 24*time.Hour)
	if !ok {
		t.Error("escalation to higher risk must bypass TTL silencing")
	}
}

func TestMarkNotified_RatchetsLevelUpward(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	key := NotificationKey{ContainerID: "abc", RegistryDigest: "sha256:x"}
	if err := s.MarkNotified(key, NotificationRecord{Level: types.RiskReview, ContainerName: "app"}, now); err != nil {
		t.Fatal(err)
	}
	// Subsequent SAFE notification must NOT downgrade the recorded level.
	if err := s.MarkNotified(key, NotificationRecord{Level: types.RiskSafe}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	entries, err := s.ListNotifications()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Level != types.RiskReview {
		t.Errorf("Level = %v, want Review (must not downgrade)", entries[0].Level)
	}
	if entries[0].Count != 2 {
		t.Errorf("Count = %d, want 2", entries[0].Count)
	}
	if entries[0].ContainerName != "app" {
		t.Errorf("ContainerName lost: %q", entries[0].ContainerName)
	}
}

func TestForgetNotification_RemovesEntry(t *testing.T) {
	s := openTestStore(t)
	key := NotificationKey{ContainerID: "abc", RegistryDigest: "sha256:x"}
	_ = s.MarkNotified(key, NotificationRecord{Level: types.RiskReview}, time.Now())
	if err := s.ForgetNotification(key); err != nil {
		t.Fatalf("ForgetNotification: %v", err)
	}
	if err := s.ForgetNotification(key); err == nil {
		t.Error("expected ErrNotFound on second forget")
	}
}

func TestClearNotifications_EmptiesStore(t *testing.T) {
	s := openTestStore(t)
	_ = s.MarkNotified(NotificationKey{ContainerID: "a", RegistryDigest: "x"}, NotificationRecord{Level: types.RiskReview}, time.Now())
	_ = s.MarkNotified(NotificationKey{ContainerID: "b", RegistryDigest: "y"}, NotificationRecord{Level: types.RiskReview}, time.Now())
	if err := s.ClearNotifications(); err != nil {
		t.Fatal(err)
	}
	entries, _ := s.ListNotifications()
	if len(entries) != 0 {
		t.Errorf("Clear left %d entries", len(entries))
	}
}

func TestNotifications_PersistAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s1, _ := Open(dir)
	_ = s1.MarkNotified(NotificationKey{ContainerID: "x", RegistryDigest: "y"},
		NotificationRecord{Level: types.RiskReview}, time.Now())
	_ = s1.Close()

	s2, _ := Open(dir)
	entries, err := s2.ListNotifications()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("after reopen, entries = %d, want 1", len(entries))
	}
}

func TestShouldNotifyOrLegacy_HitsLegacyKey(t *testing.T) {
	// Simulate a pre-Phase-10 record keyed on container name.
	s := openTestStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	legacyKey := NotificationKey{ContainerID: "sonarr", RegistryDigest: "sha256:x"}
	if err := s.MarkNotified(legacyKey, NotificationRecord{Level: types.RiskReview}, now); err != nil {
		t.Fatal(err)
	}

	// New code paths look up by Container.ID first (a 64-hex string),
	// then fall back to the name-keyed entry.
	newKey := NotificationKey{ContainerID: "abc123def456", RegistryDigest: "sha256:x"}
	ok, err := s.ShouldNotifyOrLegacy(newKey, legacyKey, types.RiskReview, now.Add(time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("expected legacy hit to silence the notification (within TTL)")
	}
}

func TestLookupDecisionOrLegacy_HitsLegacyKey(t *testing.T) {
	s := openTestStore(t)
	legacyKey := ApprovalKey{ContainerID: "sonarr", RegistryDigest: "sha256:x"}
	if err := s.RecordDecision(ApprovalRecord{
		ApprovalKey: legacyKey, Decision: DecisionApproved, ContainerName: "sonarr",
	}); err != nil {
		t.Fatal(err)
	}

	newKey := ApprovalKey{ContainerID: "abc123def456", RegistryDigest: "sha256:x"}
	got, err := s.LookupDecisionOrLegacy(newKey, legacyKey)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Decision != DecisionApproved {
		t.Errorf("legacy fallback missed: %+v", got)
	}
}

func TestShouldNotifyOrLegacy_PrefersNewKeyWhenBothExist(t *testing.T) {
	s := openTestStore(t)
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	legacyKey := NotificationKey{ContainerID: "sonarr", RegistryDigest: "sha256:x"}
	newKey := NotificationKey{ContainerID: "abc123", RegistryDigest: "sha256:x"}

	// Old record (legacy) was marked long ago — past TTL.
	_ = s.MarkNotified(legacyKey, NotificationRecord{Level: types.RiskReview}, now.Add(-48*time.Hour))
	// New record (canonical) marked just now — within TTL.
	_ = s.MarkNotified(newKey, NotificationRecord{Level: types.RiskReview}, now)

	// New key wins → silenced (within TTL of the new record's timestamp).
	ok, err := s.ShouldNotifyOrLegacy(newKey, legacyKey, types.RiskReview, now.Add(time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("expected silence (new key matched within TTL)")
	}
}

func TestShouldNotify_NilStoreAlwaysTrue(t *testing.T) {
	var s *Store
	ok, err := s.ShouldNotify(NotificationKey{}, types.RiskReview, time.Now(), time.Hour)
	if err != nil || !ok {
		t.Errorf("nil store ShouldNotify = (%v, %v), want (true, nil)", ok, err)
	}
}

// --- Scan history -----------------------------------------------------------

func TestRecordScan_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	rec := ScanRecord{
		StartedAt:  time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 5, 1, 9, 0, 5, 0, time.UTC),
		Host:       "test",
		Summary:    ScanSummary{Total: 3, Pending: 1, Review: 1},
		Results: []ScanResultRecord{{
			ContainerName: "sonarr", Image: "lscr.io/linuxserver/sonarr:4.0.10",
			UpdateAvailable: true, Level: types.RiskReview, Kind: types.ChangeMinor,
		}},
	}
	saved, err := s.RecordScan(rec)
	if err != nil {
		t.Fatalf("RecordScan: %v", err)
	}
	if saved.ID == "" {
		t.Fatal("RecordScan should populate ID")
	}
	got, err := s.GetScan(saved.ID)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if got.Summary.Total != 3 || got.Summary.Review != 1 {
		t.Errorf("summary mismatch: %+v", got.Summary)
	}
	if len(got.Results) != 1 || got.Results[0].ContainerName != "sonarr" {
		t.Errorf("results mismatch: %+v", got.Results)
	}
}

func TestListScans_ReturnsNewestFirst(t *testing.T) {
	s := openTestStore(t)
	// Insert three scans 1 second apart.
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		_, err := s.RecordScan(ScanRecord{StartedAt: ts, FinishedAt: ts.Add(time.Second)})
		if err != nil {
			t.Fatal(err)
		}
	}
	scans, err := s.ListScans(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 3 {
		t.Fatalf("len = %d, want 3", len(scans))
	}
	// Newest first.
	if !scans[0].StartedAt.After(scans[1].StartedAt) {
		t.Errorf("not newest-first: %v then %v", scans[0].StartedAt, scans[1].StartedAt)
	}
	// Listings strip per-result detail.
	if len(scans[0].Results) != 0 {
		t.Errorf("ListScans should not include Results, got %+v", scans[0].Results)
	}
}

func TestRecordScan_PrunesPastMaxHistory(t *testing.T) {
	s := openTestStore(t)
	s.MaxHistory = 3
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 7; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		_, err := s.RecordScan(ScanRecord{StartedAt: ts, FinishedAt: ts})
		if err != nil {
			t.Fatal(err)
		}
	}
	scans, _ := s.ListScans(0)
	if len(scans) != 3 {
		t.Errorf("retention failed: %d scans retained, want 3", len(scans))
	}
	files, _ := s.listHistoryFiles()
	if len(files) != 3 {
		t.Errorf("orphan files: %d on disk, want 3", len(files))
	}
}

func TestListScans_IDDerivedFromFilenameSurvivesDrift(t *testing.T) {
	// Simulate the case where an on-disk scan file's content has a
	// different "id" than the filename (hand-edited, partial migration,
	// etc.). ListScans must return an ID that GetScan can resolve.
	s := openTestStore(t)
	hist := filepath.Join(s.DataDir, "history", "scan-canonical-id.json")
	body := `{"version":1,"record":{"id":"different-from-filename","started_at":"2026-05-01T09:00:00Z","finished_at":"2026-05-01T09:00:01Z","summary":{"total":0}}}`
	if err := os.WriteFile(hist, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	scans, err := s.ListScans(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 {
		t.Fatalf("len = %d", len(scans))
	}
	if scans[0].ID != "canonical-id" {
		t.Errorf("ListScans returned id %q, want %q (filename-derived)", scans[0].ID, "canonical-id")
	}
	if _, err := s.GetScan(scans[0].ID); err != nil {
		t.Errorf("GetScan with the ListScans-returned ID failed: %v", err)
	}
}

func TestGetScan_NotFound(t *testing.T) {
	s := openTestStore(t)
	_, err := s.GetScan("nonexistent")
	if err == nil {
		t.Fatal("expected ErrNotFound")
	}
}

func TestGetScan_RejectsPathTraversal(t *testing.T) {
	s := openTestStore(t)
	cases := []string{
		"../etc/passwd",
		"../../etc/passwd",
		"foo/bar",
		"foo\\bar",
		"foo\x00",
		"a/../../b",
		"/etc/passwd",
		"   ",
		"a b",
	}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			_, err := s.GetScan(id)
			if !errors.Is(err, ErrInvalidScanID) {
				t.Errorf("GetScan(%q) returned %v, want ErrInvalidScanID", id, err)
			}
		})
	}
}

func TestGetScan_AcceptsLegitimateIDs(t *testing.T) {
	// IDs the store itself produces must round-trip cleanly. Same alphabet
	// as RecordScan's derived filename: digits, dots, dashes.
	s := openTestStore(t)
	rec, err := s.RecordScan(ScanRecord{StartedAt: time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetScan(rec.ID); err != nil {
		t.Errorf("legitimate id %q rejected: %v", rec.ID, err)
	}
}

func TestRecordScan_NilStoreIsNoop(t *testing.T) {
	var s *Store
	_, err := s.RecordScan(ScanRecord{StartedAt: time.Now()})
	if err != nil {
		t.Errorf("nil store RecordScan should not error: %v", err)
	}
}

// --- atomic write -----------------------------------------------------------

func TestWriteAtomic_NoTmpLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	if err := writeAtomic(path, []byte(`{"x":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Confirm the resulting file exists and the directory has nothing else.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected 1 file, got %d: %s", len(entries), strings.Join(names, ","))
	}
}
