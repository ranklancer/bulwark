package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bulwark-docker/bulwark/internal/docker"
	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

type recordingNotifier struct {
	name string
	min  types.RiskLevel
	got  []notifier.Event
	calls int32
}

func (r *recordingNotifier) Name() string                { return r.name }
func (r *recordingNotifier) MinLevel() types.RiskLevel   { return r.min }
func (r *recordingNotifier) Notify(_ context.Context, e []notifier.Event) error {
	atomic.AddInt32(&r.calls, 1)
	r.got = append(r.got, e...)
	return nil
}

func TestCmdScan_NotifyDispatchesPendingUpdates(t *testing.T) {
	fd := &fakeDocker{
		containers: []docker.Container{
			{ID: "c1", Name: "sonarr",
				Image: "lscr.io/linuxserver/sonarr:4.0.10-ls45", ImageID: "sha256:l1",
				Labels: map[string]string{}},
			{ID: "c2", Name: "radarr",
				Image: "lscr.io/linuxserver/radarr:5.0.0-ls12", ImageID: "sha256:l2",
				Labels: map[string]string{}},
		},
		images: map[string]*docker.ImageInspect{
			"sha256:l1": {RepoDigests: []string{"lscr.io/linuxserver/sonarr@sha256:old"}},
			"sha256:l2": {RepoDigests: []string{"lscr.io/linuxserver/radarr@sha256:current"}},
		},
	}
	fr := &fakeRegistry{digests: map[string]string{
		"lscr.io/linuxserver/sonarr:4.0.10-ls45": "sha256:new",
		"lscr.io/linuxserver/radarr:5.0.0-ls12":  "sha256:current",
	}}

	rec := &recordingNotifier{name: "test", min: types.RiskSafe}
	var stdout, stderr bytes.Buffer
	err := cmdScanWith(
		[]string{"--no-fetch-notes", "--no-color", "--notify"},
		&stdout, &stderr,
		scanDeps{Docker: fd, Registry: fr, Notifiers: []notifier.Notifier{rec}},
	)
	if err != nil {
		t.Fatalf("cmdScan: %v\nstderr: %s", err, stderr.String())
	}
	if atomic.LoadInt32(&rec.calls) != 1 {
		t.Fatalf("notifier calls = %d, want 1 (sonarr only — radarr has no update)", rec.calls)
	}
	if len(rec.got) != 1 || rec.got[0].Container != "sonarr" {
		t.Errorf("dispatched events = %+v, want one for sonarr", rec.got)
	}

	out := stdout.String()
	if !strings.Contains(out, "Notifications:") || !strings.Contains(out, "test:") {
		t.Errorf("expected dispatch summary in output:\n%s", out)
	}
}

func TestCmdScan_NotifyJSON_IncludesDispatchEnvelope(t *testing.T) {
	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "c1", Name: "app",
			Image: "ghcr.io/owner/app:1.0.0", ImageID: "sha256:l",
			Labels: map[string]string{},
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:l": {RepoDigests: []string{"ghcr.io/owner/app@sha256:old"}},
		},
	}
	fr := &fakeRegistry{digests: map[string]string{
		"ghcr.io/owner/app:1.0.0": "sha256:new",
	}}
	rec := &recordingNotifier{name: "rec", min: types.RiskSafe}

	var stdout, stderr bytes.Buffer
	err := cmdScanWith(
		[]string{"--no-fetch-notes", "--json", "--notify"},
		&stdout, &stderr,
		scanDeps{Docker: fd, Registry: fr, Notifiers: []notifier.Notifier{rec}},
	)
	if err != nil {
		t.Fatalf("cmdScan: %v\nstderr: %s", err, stderr.String())
	}
	var got struct {
		Results       []map[string]any `json:"results"`
		Notifications []map[string]any `json:"notifications"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout.String())
	}
	if len(got.Results) != 1 {
		t.Errorf("results count = %d, want 1", len(got.Results))
	}
	if len(got.Notifications) != 1 {
		t.Fatalf("notifications count = %d, want 1", len(got.Notifications))
	}
	if got.Notifications[0]["notifier"] != "rec" {
		t.Errorf("notifier name = %v", got.Notifications[0]["notifier"])
	}
	if int(got.Notifications[0]["sent"].(float64)) != 1 {
		t.Errorf("sent = %v, want 1", got.Notifications[0]["sent"])
	}
}

func TestCmdScan_NotifyWithoutChannelsLogsWarningButSucceeds(t *testing.T) {
	fd := &fakeDocker{containers: nil}
	fr := &fakeRegistry{}
	var stdout, stderr bytes.Buffer
	err := cmdScanWith(
		[]string{"--no-fetch-notes", "--no-color", "--notify"},
		&stdout, &stderr,
		scanDeps{Docker: fd, Registry: fr},
	)
	if err != nil {
		t.Fatalf("cmdScan: %v", err)
	}
	if !strings.Contains(stderr.String(), "no notification channels") {
		t.Errorf("expected stderr warning about missing channels, got %q", stderr.String())
	}
}
