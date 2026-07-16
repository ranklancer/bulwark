package notifier

import (
	"errors"
	"testing"
	"time"

	"github.com/ranklancer/bulwark/internal/configstore"
	"github.com/ranklancer/bulwark/pkg/types"
)

func TestRegistry_YamlAndUIBothSurface(t *testing.T) {
	yamlSlack, err := NewSlack("https://hooks.slack.com/yaml/x", "", types.RiskReview, "yaml-only")
	if err != nil {
		t.Fatal(err)
	}
	cs := mustStore(t)
	if _, err := cs.Mutate(func(d *configstore.Data) error {
		d.Notifiers = append(d.Notifiers, configstore.NotifierEntry{
			ID:        mustID(t),
			Name:      "ui-side",
			Kind:      configstore.KindSlack,
			Enabled:   true,
			Slack:     &configstore.SlackSettings{WebhookURL: "https://hooks.slack.com/ui/y"},
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistry([]Notifier{yamlSlack}, cs, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	entries := reg.Entries()
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	var sawYaml, sawUI bool
	for _, e := range entries {
		if e.Source == SourceYAML && e.Notifier.Name() == "yaml-only" {
			sawYaml = true
		}
		if e.Source == SourceUI && e.Notifier.Name() == "ui-side" {
			sawUI = true
		}
	}
	if !sawYaml || !sawUI {
		t.Errorf("entries = %+v, want one yaml + one ui", entries)
	}
	if reg.Dispatcher() == nil {
		t.Error("Dispatcher() returned nil")
	}
}

func TestRegistry_ReloadPicksUpNewEntries(t *testing.T) {
	cs := mustStore(t)
	reg, err := NewRegistry(nil, cs, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(reg.Entries()); got != 0 {
		t.Fatalf("fresh registry has %d entries, want 0", got)
	}

	if err := reg.AddUI(configstore.NotifierEntry{
		ID:        mustID(t),
		Name:      "x",
		Kind:      configstore.KindSlack,
		Enabled:   true,
		Slack:     &configstore.SlackSettings{WebhookURL: "https://hooks.slack.com/x/y"},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if got := len(reg.Entries()); got != 1 {
		t.Errorf("after AddUI: %d entries, want 1", got)
	}
}

func TestRegistry_DeleteUIRemovesEntry(t *testing.T) {
	cs := mustStore(t)
	reg, err := NewRegistry(nil, cs, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	id := mustID(t)
	if err := reg.AddUI(configstore.NotifierEntry{
		ID:        id,
		Name:      "to-delete",
		Kind:      configstore.KindSlack,
		Enabled:   true,
		Slack:     &configstore.SlackSettings{WebhookURL: "https://hooks.slack.com/x/y"},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := reg.DeleteUI(id); err != nil {
		t.Fatalf("DeleteUI: %v", err)
	}
	if got := len(reg.Entries()); got != 0 {
		t.Errorf("after delete: %d entries, want 0", got)
	}
	// Second delete should error — id no longer exists.
	if err := reg.DeleteUI(id); err == nil {
		t.Error("second DeleteUI should error; got nil")
	}
}

func TestRegistry_AddUIWithoutStoreReturnsErr(t *testing.T) {
	reg, err := NewRegistry(nil, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = reg.AddUI(configstore.NotifierEntry{
		ID: mustID(t), Name: "x", Kind: configstore.KindSlack, Enabled: true,
		Slack: &configstore.SlackSettings{WebhookURL: "https://hooks.slack.com/x/y"},
	})
	if !errors.Is(err, ErrUIWritesDisabled) {
		t.Errorf("AddUI without store: err = %v, want ErrUIWritesDisabled", err)
	}
}

func TestRegistry_FindUIEntry(t *testing.T) {
	cs := mustStore(t)
	reg, err := NewRegistry(nil, cs, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	id := mustID(t)
	if err := reg.AddUI(configstore.NotifierEntry{
		ID:        id,
		Name:      "findme",
		Kind:      configstore.KindSlack,
		Enabled:   true,
		Slack:     &configstore.SlackSettings{WebhookURL: "https://hooks.slack.com/x/y"},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	got, ok := reg.FindUIEntry(id)
	if !ok {
		t.Fatalf("FindUIEntry(%s) returned ok=false", id)
	}
	if got.Source != SourceUI {
		t.Errorf("found entry source = %v, want ui", got.Source)
	}
	if _, ok := reg.FindUIEntry("not-an-id"); ok {
		t.Error("FindUIEntry for unknown id should return ok=false")
	}
}

// mustStore is a test helper duplicated here (rather than imported from
// configstore's _test files) because configstore's test helpers aren't
// exported.
func mustStore(t *testing.T) *configstore.Store {
	t.Helper()
	cs, err := configstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func mustID(t *testing.T) string {
	t.Helper()
	id, err := configstore.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
