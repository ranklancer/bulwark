package store

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/ranklancer/bulwark/pkg/types"
)

// NotificationKey identifies a unique (container, target image) pair.
// Container ID is preferred over name because Docker IDs are stable across
// rename operations; we fall back to name when ID is unknown.
type NotificationKey struct {
	ContainerID    string `json:"container_id"`
	RegistryDigest string `json:"registry_digest"`
}

// NotificationRecord is the persisted row for a single dedup entry.
type NotificationRecord struct {
	NotificationKey
	ContainerName string          `json:"container_name,omitempty"`
	Image         string          `json:"image,omitempty"`
	Level         types.RiskLevel `json:"level"`
	FirstNotified time.Time       `json:"first_notified"`
	LastNotified  time.Time       `json:"last_notified"`
	Count         int             `json:"count"`
}

// notificationsFile is the on-disk wire shape. Versioned so future schema
// changes can migrate without losing data.
type notificationsFile struct {
	Version int                  `json:"version"`
	Entries []NotificationRecord `json:"entries"`
}

const notificationsSchemaVersion = 1

// loadNotifications reads and decodes the dedup file. A missing file is
// treated as an empty store, not an error.
func (s *Store) loadNotifications() ([]NotificationRecord, error) {
	data, err := os.ReadFile(s.notificationsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: read notifications: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var f notificationsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("store: decode notifications: %w", err)
	}
	return f.Entries, nil
}

// saveNotifications atomically writes the dedup file.
func (s *Store) saveNotifications(entries []NotificationRecord) error {
	f := notificationsFile{Version: notificationsSchemaVersion, Entries: entries}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode notifications: %w", err)
	}
	return writeAtomic(s.notificationsPath(), data, 0o644)
}

// ShouldNotifyOrLegacy is the migration-aware variant of ShouldNotify.
// It first checks `key` (the new Container.ID-keyed form). If no record
// matches, it consults `legacyKey` (typically the same digest with
// ContainerID=Container.Name) to honour records written by older
// Bulwark versions. Either match counts as "already notified".
//
// New writes from MarkNotified always land under the primary key, so
// legacy entries become inert tombstones — they'll be cleared by
// `bulwark history clear` or naturally as users churn through digests.
func (s *Store) ShouldNotifyOrLegacy(key, legacyKey NotificationKey, level types.RiskLevel, now time.Time, ttl time.Duration) (bool, error) {
	if s == nil {
		return true, nil
	}
	ok, err := s.ShouldNotify(key, level, now, ttl)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	if legacyKey == key || legacyKey.ContainerID == "" {
		return true, nil
	}
	// Primary said "yes notify" because the new key isn't recorded.
	// Check the legacy key — if there's a record there, honour it.
	return s.ShouldNotify(legacyKey, level, now, ttl)
}

// ShouldNotify reports whether a notification for key should be sent now,
// given the dedup TTL. A nil receiver returns true (no store → always
// notify), so callers can pass a nil *Store unconditionally to opt out of
// dedup.
//
// "Should notify" semantics:
//   - Key has never been notified: yes.
//   - Last notification was more than ttl ago: yes (re-notify).
//   - Last notification was within ttl: no (silenced).
//   - The new risk level is higher than the previously-notified level: yes
//     (escalations always re-notify, regardless of TTL).
func (s *Store) ShouldNotify(key NotificationKey, level types.RiskLevel, now time.Time, ttl time.Duration) (bool, error) {
	if s == nil {
		return true, nil
	}
	entries, err := s.loadNotifications()
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.NotificationKey != key {
			continue
		}
		if level > e.Level {
			return true, nil
		}
		if ttl > 0 && now.Sub(e.LastNotified) >= ttl {
			return true, nil
		}
		return false, nil
	}
	return true, nil
}

// MarkNotified records that a notification was sent for key. If a record
// exists, LastNotified and Count are updated; the level is ratcheted upward
// (matching the rest of Bulwark's "never silently downgrade" invariant).
func (s *Store) MarkNotified(key NotificationKey, meta NotificationRecord, when time.Time) error {
	if s == nil {
		return nil
	}
	entries, err := s.loadNotifications()
	if err != nil {
		return err
	}
	found := false
	for i, e := range entries {
		if e.NotificationKey != key {
			continue
		}
		found = true
		if meta.Level > e.Level {
			entries[i].Level = meta.Level
		}
		if meta.ContainerName != "" {
			entries[i].ContainerName = meta.ContainerName
		}
		if meta.Image != "" {
			entries[i].Image = meta.Image
		}
		entries[i].LastNotified = when
		entries[i].Count++
		break
	}
	if !found {
		rec := meta
		rec.NotificationKey = key
		if rec.FirstNotified.IsZero() {
			rec.FirstNotified = when
		}
		rec.LastNotified = when
		rec.Count = 1
		entries = append(entries, rec)
	}
	// Stable order: by container name then digest, so diffs in version
	// control are clean and the file is human-readable.
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].ContainerName != entries[j].ContainerName {
			return entries[i].ContainerName < entries[j].ContainerName
		}
		return entries[i].RegistryDigest < entries[j].RegistryDigest
	})
	return s.saveNotifications(entries)
}

// ListNotifications returns the full dedup state, sorted by container name.
func (s *Store) ListNotifications() ([]NotificationRecord, error) {
	if s == nil {
		return nil, nil
	}
	return s.loadNotifications()
}

// ForgetNotification removes the record for key. Returns ErrNotFound if no
// matching record exists.
func (s *Store) ForgetNotification(key NotificationKey) error {
	if s == nil {
		return nil
	}
	entries, err := s.loadNotifications()
	if err != nil {
		return err
	}
	for i, e := range entries {
		if e.NotificationKey != key {
			continue
		}
		entries = append(entries[:i], entries[i+1:]...)
		return s.saveNotifications(entries)
	}
	return ErrNotFound
}

// ClearNotifications removes all dedup records.
func (s *Store) ClearNotifications() error {
	if s == nil {
		return nil
	}
	before, _ := s.loadNotifications()
	if err := s.saveNotifications(nil); err != nil {
		return err
	}
	s.Audit(AuditEvent{
		Action: ActionDedupCleared,
		Detail: fmt.Sprintf("removed %d", len(before)),
	})
	return nil
}
