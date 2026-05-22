package notifier

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/configstore"
)

// Source identifies where a Notifier was configured. The dashboard uses
// this to render UI-managed entries with edit/delete controls and yaml-
// defined ones as read-only "managed by YAML" cards.
type Source string

const (
	SourceYAML Source = "yaml"
	SourceUI   Source = "ui"
)

// Entry attaches the configuration source + a stable identifier to a
// constructed Notifier. ID is the configstore UUID for UI entries, or a
// synthetic "yaml:<channel>" handle for yaml ones (mutable from yaml only,
// but the dashboard still needs *some* identifier to render).
type Entry struct {
	ID       string
	Source   Source
	Notifier Notifier
}

// Registry is the runtime-mutable notifier set. Yaml entries are
// constructed once at startup and immutable thereafter; UI entries live
// in the encrypted configstore and can be added/edited/removed at
// runtime. Reload() rebuilds the UI half from the store, then swaps in a
// fresh Dispatcher under a single atomic store so in-flight Dispatch
// calls always see a consistent set.
type Registry struct {
	logger    *slog.Logger
	timeout   time.Duration
	yamlList  []Entry
	store     *configstore.Store

	mu          sync.RWMutex
	entries     []Entry
	dispatcher  atomic.Pointer[Dispatcher]
}

// NewRegistry constructs a Registry from a yaml-defined notifier list +
// an (optional) UI store. The yaml list is the one returned by FromConfig;
// callers should pass nil if there is no yaml notifier block. Reload() is
// called once internally to assemble the initial dispatcher.
func NewRegistry(yamlList []Notifier, store *configstore.Store, logger *slog.Logger, timeout time.Duration) (*Registry, error) {
	yamlEntries := make([]Entry, 0, len(yamlList))
	for _, n := range yamlList {
		yamlEntries = append(yamlEntries, Entry{
			ID:       "yaml:" + n.Name(),
			Source:   SourceYAML,
			Notifier: n,
		})
	}
	r := &Registry{
		logger:   logger,
		timeout:  timeout,
		yamlList: yamlEntries,
		store:    store,
	}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload re-reads UI entries from the configstore (if one is wired),
// rebuilds the underlying Notifier objects, and atomically swaps in a
// fresh Dispatcher. Yaml entries are not re-read — they only change on
// daemon restart.
//
// Per-entry construction errors are logged + skipped: a single bad row
// in the store never disables every notifier. The Dispatcher is replaced
// even when some entries failed so the operator can correct the bad row
// and re-trigger reload.
func (r *Registry) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	combined := make([]Entry, 0, len(r.yamlList))
	combined = append(combined, r.yamlList...)

	if r.store != nil {
		for _, entry := range r.store.Notifiers() {
			if !entry.Enabled {
				continue
			}
			n, err := BuildFromEntry(entry)
			if err != nil {
				if r.logger != nil {
					r.logger.Warn("notifier: skipping bad ui entry", "id", entry.ID, "name", entry.Name, "err", err)
				}
				continue
			}
			combined = append(combined, Entry{ID: entry.ID, Source: SourceUI, Notifier: n})
		}
	}

	r.entries = combined
	notifiers := make([]Notifier, len(combined))
	for i, e := range combined {
		notifiers[i] = e.Notifier
	}
	r.dispatcher.Store(NewDispatcher(notifiers, r.logger, r.timeout))
	return nil
}

// Dispatcher returns the current Dispatcher. Safe to call from any
// goroutine; the pointer always references a complete, consistent set.
func (r *Registry) Dispatcher() *Dispatcher {
	return r.dispatcher.Load()
}

// Entries returns a snapshot of the current entries, yaml first then UI,
// in registration order. The returned slice is safe to retain — the
// caller never mutates the live set.
func (r *Registry) Entries() []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Entry, len(r.entries))
	copy(out, r.entries)
	return out
}

// FindStoreEntry returns the underlying configstore.NotifierEntry for a
// UI-managed notifier. Used by the dashboard's edit-form pre-fill: it
// needs the raw entry shape (including type-specific settings), not the
// runtime Notifier interface FindUIEntry returns.
func (r *Registry) FindStoreEntry(id string) (configstore.NotifierEntry, bool) {
	if r.store == nil {
		return configstore.NotifierEntry{}, false
	}
	return r.store.FindNotifier(id)
}

// FindUIEntry looks up a UI-managed entry by ID. Returns false when the
// ID names a yaml entry (yaml entries are immutable from this API) or
// when no entry matches.
func (r *Registry) FindUIEntry(id string) (Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.entries {
		if e.ID == id && e.Source == SourceUI {
			return e, true
		}
	}
	return Entry{}, false
}

// BuildFromEntry constructs a runtime Notifier from a configstore entry.
// Validation is repeated here (in addition to the store's pre-write
// Validate()) so a corrupted file never escapes the registry as a panic.
// Exported so the HTTP layer can build an ephemeral notifier for the
// "test before save" flow without re-implementing the kind-switch.
func BuildFromEntry(e configstore.NotifierEntry) (Notifier, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	min := parseMin(e.MinLevel)
	switch e.Kind {
	case configstore.KindSlack:
		return NewSlack(e.Slack.WebhookURL, e.Slack.Channel, min, e.Name)
	case configstore.KindDiscord:
		return NewDiscord(e.Discord.WebhookURL, min, e.Name)
	case configstore.KindTeams:
		return NewTeams(e.Teams.WebhookURL, min, e.Name)
	case configstore.KindSMTP:
		return NewSMTP(config.SMTPConfig{
			Enabled:  true,
			Host:     e.SMTP.Host,
			Port:     e.SMTP.Port,
			Username: e.SMTP.Username,
			Password: e.SMTP.Password,
			From:     e.SMTP.From,
			To:       e.SMTP.To,
			TLS:      e.SMTP.TLS,
		}, min, e.Name)
	case configstore.KindHomeAssistant:
		return NewHomeAssistant(config.HAConfig{
			Enabled:  true,
			URL:      e.HomeAssistant.URL,
			Token:    e.HomeAssistant.Token,
			Safe:     toYAMLHALevel(e.HomeAssistant.Safe),
			Review:   toYAMLHALevel(e.HomeAssistant.Review),
			Breaking: toYAMLHALevel(e.HomeAssistant.Breaking),
			Rollback: toYAMLHALevel(e.HomeAssistant.Rollback),
		}, e.Name)
	case configstore.KindNtfy:
		return NewNtfy(e.Ntfy.ServerURL, e.Ntfy.Topic, e.Ntfy.Token, min, e.Name)
	}
	return nil, fmt.Errorf("notifier: unknown kind %q", e.Kind)
}

// toYAMLHALevel adapts a configstore HALevelDispatch into the matching
// shape config.HANotifyLevel consumed by NewHomeAssistant. The two
// types are deliberately not aliased — the store schema versions
// independently of the yaml schema.
func toYAMLHALevel(in configstore.HALevelDispatch) config.HANotifyLevel {
	return config.HANotifyLevel{
		Persistent: in.Persistent,
		Push:       in.Push,
		Critical:   in.Critical,
	}
}

// ErrUIWritesDisabled is returned by registry mutation helpers when the
// caller asks to create/edit/delete via the UI but no configstore is
// configured. Kept exported so callers can render a clear "this deployment
// is yaml-only" error without resorting to string matching.
var ErrUIWritesDisabled = errors.New("notifier: UI writes are disabled (no configstore configured)")

// AddUI persists a new UI-managed notifier and triggers a reload. The
// caller is responsible for filling ID + timestamps (use configstore.NewID
// + time.Now); Validate is run before the store write.
func (r *Registry) AddUI(entry configstore.NotifierEntry) error {
	if r.store == nil {
		return ErrUIWritesDisabled
	}
	if err := entry.Validate(); err != nil {
		return err
	}
	_, err := r.store.Mutate(func(d *configstore.Data) error {
		for _, existing := range d.Notifiers {
			if existing.ID == entry.ID {
				return fmt.Errorf("notifier: id %q already exists", entry.ID)
			}
		}
		d.Notifiers = append(d.Notifiers, entry)
		return nil
	})
	if err != nil {
		return err
	}
	return r.Reload()
}

// UpdateUI replaces an existing UI-managed notifier in-place. The ID and
// CreatedAt timestamps are preserved from the existing entry; everything
// else comes from the incoming entry (including a refreshed UpdatedAt).
// Returns an error when the ID does not match an existing UI entry or
// when validation fails.
func (r *Registry) UpdateUI(entry configstore.NotifierEntry) error {
	if r.store == nil {
		return ErrUIWritesDisabled
	}
	if err := entry.Validate(); err != nil {
		return err
	}
	found := false
	_, err := r.store.Mutate(func(d *configstore.Data) error {
		for i, existing := range d.Notifiers {
			if existing.ID == entry.ID {
				entry.CreatedAt = existing.CreatedAt
				d.Notifiers[i] = entry
				found = true
				return nil
			}
		}
		return fmt.Errorf("notifier: no UI entry with id %q", entry.ID)
	})
	if err != nil {
		return err
	}
	if !found {
		// Mutate should have returned an error already in this case;
		// this is a defensive sanity check.
		return fmt.Errorf("notifier: no UI entry with id %q", entry.ID)
	}
	return r.Reload()
}

// DeleteUI removes a UI-managed notifier by ID and reloads. Yaml entries
// cannot be deleted via this API (they live in the yaml file).
func (r *Registry) DeleteUI(id string) error {
	if r.store == nil {
		return ErrUIWritesDisabled
	}
	found := false
	_, err := r.store.Mutate(func(d *configstore.Data) error {
		filtered := d.Notifiers[:0]
		for _, e := range d.Notifiers {
			if e.ID == id {
				found = true
				continue
			}
			filtered = append(filtered, e)
		}
		d.Notifiers = filtered
		return nil
	})
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("notifier: no UI entry with id %q", id)
	}
	return r.Reload()
}

