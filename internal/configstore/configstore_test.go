package configstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadOrGenerateKey_GeneratesFreshFile(t *testing.T) {
	dir := t.TempDir()
	key, err := LoadOrGenerateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != KeyLen {
		t.Fatalf("key length = %d, want %d", len(key), KeyLen)
	}
	st, err := os.Stat(filepath.Join(dir, KeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v, want 0600", st.Mode().Perm())
	}
}

func TestLoadOrGenerateKey_ReturnsExistingKey(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadOrGenerateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrGenerateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("LoadOrGenerateKey returned a different key on second call")
	}
}

func TestLoadOrGenerateKey_RejectsWrongSize(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, KeyFileName), []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrGenerateKey(dir); err == nil {
		t.Fatal("expected error for malformed key file")
	}
}

func TestStore_OpenEmpty(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Notifiers(); len(got) != 0 {
		t.Errorf("fresh store has %d notifiers, want 0", len(got))
	}
}

func TestStore_MutateAndReload(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	entry := NotifierEntry{
		ID:       mustID(t),
		Name:     "ops-channel",
		Kind:     KindSlack,
		MinLevel: "review",
		Enabled:  true,
		Slack:    &SlackSettings{WebhookURL: "https://hooks.slack.com/T0/B0/abc"},
	}
	if err := entry.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	if _, err := s.Mutate(func(d *Data) error {
		d.Notifiers = append(d.Notifiers, entry)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Reopen — should decrypt + see the persisted entry.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := s2.Notifiers()
	if len(got) != 1 {
		t.Fatalf("after reload: got %d notifiers, want 1", len(got))
	}
	if got[0].Slack == nil || got[0].Slack.WebhookURL != entry.Slack.WebhookURL {
		t.Errorf("notifier slack settings did not round-trip; got=%+v", got[0])
	}
}

func TestStore_MutateRollbackOnError(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("validation fails")
	if _, err := s.Mutate(func(d *Data) error {
		d.Notifiers = append(d.Notifiers, NotifierEntry{ID: "x"})
		return want
	}); !errors.Is(err, want) {
		t.Fatalf("Mutate err = %v, want %v", err, want)
	}
	if got := s.Notifiers(); len(got) != 0 {
		t.Errorf("rollback failed: %d notifiers in store, want 0", len(got))
	}
	// No file should have been written either.
	if _, err := os.Stat(filepath.Join(dir, FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected no .enc file after failed mutate; stat err = %v", err)
	}
}

func TestStore_RefusesWrongKey(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Mutate(func(d *Data) error {
		d.Notifiers = append(d.Notifiers, NotifierEntry{
			ID: mustID(t), Name: "n", Kind: KindSlack, Enabled: true,
			Slack: &SlackSettings{WebhookURL: "https://example.com/hook"},
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Overwrite the key file with fresh bytes; reopening should fail.
	bogus := make([]byte, KeyLen)
	for i := range bogus {
		bogus[i] = byte(i + 1)
	}
	if err := os.WriteFile(filepath.Join(dir, KeyFileName), bogus, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("Open with mismatched key should error")
	}
}

func TestNotifierEntry_Validate(t *testing.T) {
	type tc struct {
		name    string
		mutate  func(*NotifierEntry)
		wantErr string
	}
	base := func() NotifierEntry {
		return NotifierEntry{
			ID:       mustID(t),
			Name:     "channel",
			Kind:     KindSlack,
			MinLevel: "review",
			Enabled:  true,
			Slack:    &SlackSettings{WebhookURL: "https://hooks.slack.com/services/T0/B0/x"},
		}
	}
	cases := []tc{
		{"missing id", func(e *NotifierEntry) { e.ID = "" }, "id is required"},
		{"missing name", func(e *NotifierEntry) { e.Name = "  " }, "name is required"},
		{"bad min_level", func(e *NotifierEntry) { e.MinLevel = "danger" }, "is not a valid risk level"},
		{"kind unknown", func(e *NotifierEntry) { e.Kind = "carrierpigeon"; e.Slack = nil }, "unknown notifier kind"},
		{"slack missing url", func(e *NotifierEntry) { e.Slack = &SlackSettings{} }, "slack.webhook_url is required"},
		{"slack bad scheme", func(e *NotifierEntry) { e.Slack = &SlackSettings{WebhookURL: "ftp://x/y"} }, "must be an http or https URL"},
		{"slack with cross-kind block", func(e *NotifierEntry) {
			e.Discord = &DiscordSettings{WebhookURL: "https://discord.com/x"}
		}, "non-slack settings present"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := base()
			c.mutate(&e)
			err := e.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantErr)
			}
			if c.wantErr != "" && !contains(err.Error(), c.wantErr) {
				t.Errorf("err = %q, want substring %q", err.Error(), c.wantErr)
			}
		})
	}
}

func TestNotifierEntry_Validate_NtfyRejectsBadInputs(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*NotifierEntry)
		wantErr string
	}{
		{"missing settings", func(e *NotifierEntry) { e.Ntfy = nil }, "ntfy settings are required"},
		{"missing server", func(e *NotifierEntry) { e.Ntfy.ServerURL = "" }, "must be an http or https URL"},
		{"bad scheme", func(e *NotifierEntry) { e.Ntfy.ServerURL = "ftp://ntfy.sh" }, "must be an http or https URL"},
		{"missing topic", func(e *NotifierEntry) { e.Ntfy.Topic = "" }, "ntfy.topic is required"},
		{"topic with slash", func(e *NotifierEntry) { e.Ntfy.Topic = "bad/topic" }, "must not contain slashes"},
		{"cross-kind block", func(e *NotifierEntry) {
			e.Slack = &SlackSettings{WebhookURL: "https://hooks.slack.com/x"}
		}, "non-ntfy settings"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := NotifierEntry{
				ID:      mustID(t),
				Name:    "ntfy-test",
				Kind:    KindNtfy,
				Enabled: true,
				Ntfy:    &NtfySettings{ServerURL: "https://ntfy.example.com", Topic: "alerts"},
			}
			c.mutate(&e)
			err := e.Validate()
			if err == nil {
				t.Fatalf("expected error %q", c.wantErr)
			}
			if !contains(err.Error(), c.wantErr) {
				t.Errorf("err = %q, want substring %q", err.Error(), c.wantErr)
			}
		})
	}
}

func TestNotifierEntry_Validate_OtherKinds(t *testing.T) {
	cases := []NotifierEntry{
		{ID: mustID(t), Name: "discord-ops", Kind: KindDiscord, Enabled: true,
			Discord: &DiscordSettings{WebhookURL: "https://discord.com/api/webhooks/1/abc"}},
		{ID: mustID(t), Name: "teams-ops", Kind: KindTeams, Enabled: true,
			Teams: &TeamsSettings{WebhookURL: "https://outlook.office.com/webhook/x"}},
		{ID: mustID(t), Name: "ha-mobile", Kind: KindHomeAssistant, Enabled: true,
			HomeAssistant: &HomeAssistantSettings{URL: "https://ha.local:8123", Token: "tok"}},
		{ID: mustID(t), Name: "smtp-relay", Kind: KindSMTP, Enabled: true,
			SMTP: &SMTPSettings{Host: "smtp.example.com", Port: 587, From: "bw@example.com", To: []string{"ops@example.com"}}},
		{ID: mustID(t), Name: "ntfy-prod", Kind: KindNtfy, Enabled: true,
			Ntfy: &NtfySettings{ServerURL: "https://ntfy.example.com", Topic: "bulwark", Token: "tk_abc"}},
	}
	for _, e := range cases {
		if err := e.Validate(); err != nil {
			t.Errorf("kind=%s validate failed: %v", e.Kind, err)
		}
	}
}

func mustID(t *testing.T) string {
	t.Helper()
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func contains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}
