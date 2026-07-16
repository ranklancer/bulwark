package configstore

import (
	"encoding/json"
	"testing"

	"github.com/ranklancer/bulwark/internal/config"
)

func TestStore_PatchSection_Schedule(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.PatchSection("schedule", []byte(`{"check":"0 */4 * * *"}`), json.Unmarshal)
	if err != nil {
		t.Fatalf("patch schedule: %v", err)
	}
	if out.Schedule == nil || out.Schedule.CheckCron == nil || *out.Schedule.CheckCron != "0 */4 * * *" {
		t.Fatalf("post-patch settings = %+v; expected schedule.check = 0 */4 * * *", out.Schedule)
	}

	// Reopen and confirm persistence.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := s2.Settings()
	if got.Schedule == nil || got.Schedule.CheckCron == nil || *got.Schedule.CheckCron != "0 */4 * * *" {
		t.Errorf("after reopen: settings = %+v; lost schedule override", got)
	}
}

func TestStore_PatchSection_Classification(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"default_risk":"breaking","policies":{"major":"safe","minor":"review"}}`)
	out, err := s.PatchSection("classification", body, json.Unmarshal)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	if out.Classification == nil {
		t.Fatal("classification override is nil after patch")
	}
	if out.Classification.DefaultRisk == nil || *out.Classification.DefaultRisk != "breaking" {
		t.Errorf("default_risk = %+v, want 'breaking'", out.Classification.DefaultRisk)
	}
	if out.Classification.Policies == nil ||
		out.Classification.Policies.Major == nil || *out.Classification.Policies.Major != "safe" {
		t.Errorf("policies.major missing; got %+v", out.Classification.Policies)
	}

	// A subsequent partial patch should preserve earlier fields.
	out2, err := s.PatchSection("classification", []byte(`{"policies":{"latest":"breaking"}}`), json.Unmarshal)
	if err != nil {
		t.Fatalf("patch 2: %v", err)
	}
	if out2.Classification.DefaultRisk == nil || *out2.Classification.DefaultRisk != "breaking" {
		t.Errorf("default_risk got clobbered by second patch")
	}
	if out2.Classification.Policies.Major == nil || *out2.Classification.Policies.Major != "safe" {
		t.Errorf("major got clobbered by second patch")
	}
	if out2.Classification.Policies.Latest == nil || *out2.Classification.Policies.Latest != "breaking" {
		t.Errorf("latest not applied; got %+v", out2.Classification.Policies)
	}
}

func TestStore_PatchSection_RejectsBadRisk(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.PatchSection("classification", []byte(`{"default_risk":"danger"}`), json.Unmarshal)
	if err == nil {
		t.Fatal("expected error for invalid risk level")
	}
}

func TestStore_PatchSection_Health(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	body := []byte(`{"timeout":"180s","threshold":5}`)
	out, err := s.PatchSection("health", body, json.Unmarshal)
	if err != nil {
		t.Fatal(err)
	}
	if out.Health == nil || out.Health.Timeout == nil || *out.Health.Timeout != "180s" {
		t.Errorf("health.timeout missing: %+v", out.Health)
	}
	if out.Health.Threshold == nil || *out.Health.Threshold != 5 {
		t.Errorf("health.threshold missing: %+v", out.Health.Threshold)
	}
}

func TestStore_PatchSection_Health_RejectsBadDuration(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	_, err := s.PatchSection("health", []byte(`{"timeout":"forever"}`), json.Unmarshal)
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
}

func TestStore_PatchSection_Logging(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	if _, err := s.PatchSection("logging", []byte(`{"level":"debug","format":"json"}`), json.Unmarshal); err != nil {
		t.Fatal(err)
	}
	got := s.Settings()
	if got.Logging == nil || got.Logging.Level == nil || *got.Logging.Level != "debug" {
		t.Errorf("logging.level not set: %+v", got.Logging)
	}
}

func TestStore_PatchSection_Logging_RejectsBadLevel(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	_, err := s.PatchSection("logging", []byte(`{"level":"shouty"}`), json.Unmarshal)
	if err == nil {
		t.Fatal("expected error for invalid log level")
	}
}

func TestStore_PatchSection_Snapshots_Proxmox(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	body := []byte(`{"backend":"proxmox","proxmox":{"url":"https://pve.local:8006","token":"u@pve!t=s","node":"pve01","vmid":100,"kind":"lxc","insecure_tls":true}}`)
	out, err := s.PatchSection("snapshots", body, json.Unmarshal)
	if err != nil {
		t.Fatal(err)
	}
	if out.Snapshots == nil || out.Snapshots.Backend == nil || *out.Snapshots.Backend != "proxmox" {
		t.Errorf("backend not set: %+v", out.Snapshots)
	}
	if out.Snapshots.Proxmox == nil || out.Snapshots.Proxmox.Token == nil || *out.Snapshots.Proxmox.Token != "u@pve!t=s" {
		t.Errorf("proxmox token not set: %+v", out.Snapshots.Proxmox)
	}

	// Partial patch: only change vmid; token should persist.
	if _, err := s.PatchSection("snapshots", []byte(`{"proxmox":{"vmid":200}}`), json.Unmarshal); err != nil {
		t.Fatal(err)
	}
	got := s.Settings()
	if got.Snapshots.Proxmox.Token == nil || *got.Snapshots.Proxmox.Token != "u@pve!t=s" {
		t.Error("token was cleared by partial patch")
	}
	if got.Snapshots.Proxmox.VMID == nil || *got.Snapshots.Proxmox.VMID != 200 {
		t.Errorf("vmid not updated: %+v", got.Snapshots.Proxmox.VMID)
	}
}

func TestStore_PatchSection_Snapshots_RejectsBadKind(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	_, err := s.PatchSection("snapshots", []byte(`{"proxmox":{"kind":"bsd"}}`), json.Unmarshal)
	if err == nil {
		t.Fatal("expected error for invalid proxmox kind")
	}
}

func TestStore_PatchSection_UnknownSection(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	_, err := s.PatchSection("registries", []byte(`{}`), json.Unmarshal)
	if err == nil {
		t.Fatal("expected error for unknown section")
	}
}

func TestSettingsOverride_ToUISettingsApplies(t *testing.T) {
	const newCron = "30 2 * * *" // distinct from Defaults()'s "0 */6 * * *"
	cron := newCron
	risk := "breaking"
	pmajor := "safe"
	override := SettingsOverride{
		Schedule: &ScheduleOverride{CheckCron: &cron},
		Classification: &ClassificationOverride{
			DefaultRisk: &risk,
			Policies:    &PolicyOverride{Major: &pmajor},
		},
	}
	loaded := config.Defaults()
	originalCheck := loaded.Schedule.Check
	merged := loaded.WithUISettings(override.ToUISettings())
	if merged.Schedule.Check != newCron {
		t.Errorf("schedule.check = %q, want %q", merged.Schedule.Check, newCron)
	}
	if merged.Classification.DefaultRisk != "breaking" {
		t.Errorf("default_risk = %q, want breaking", merged.Classification.DefaultRisk)
	}
	if merged.Classification.Policies.Major != "safe" {
		t.Errorf("policies.major = %q, want safe", merged.Classification.Policies.Major)
	}
	if merged.Classification.Policies.Minor != "review" {
		t.Errorf("policies.minor changed unexpectedly to %q", merged.Classification.Policies.Minor)
	}
	// Original is not mutated.
	if loaded.Schedule.Check != originalCheck {
		t.Errorf("WithUISettings mutated original (was %q, now %q)", originalCheck, loaded.Schedule.Check)
	}
}
