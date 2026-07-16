package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/internal/docker"
	"github.com/ranklancer/bulwark/internal/registry"
	"github.com/ranklancer/bulwark/internal/releasenotes"
)

// fakeDocker / fakeRegistry / fakeNotes here mirror the scanner package's
// fakes — kept local so this test file is self-contained.

type fakeDocker struct {
	containers []docker.Container
	images     map[string]*docker.ImageInspect
}

func (f *fakeDocker) ListContainers(_ context.Context, _ bool) ([]docker.Container, error) {
	return f.containers, nil
}
func (f *fakeDocker) InspectImage(_ context.Context, id string) (*docker.ImageInspect, error) {
	return f.images[id], nil
}

type fakeRegistry struct{ digests map[string]string }

func (f *fakeRegistry) Resolve(_ context.Context, ref registry.Reference) (string, error) {
	if d, ok := f.digests[ref.String()]; ok {
		return d, nil
	}
	return "", errors.New("digest not stubbed: " + ref.String())
}

type fakeNotes struct{ result releasenotes.Result }

func (f *fakeNotes) Fetch(_ context.Context, _ registry.Reference) (releasenotes.Result, error) {
	return f.result, nil
}

func TestCmdScan_JSON_OneUpdate_OneNoChange_OneSkipped(t *testing.T) {
	fd := &fakeDocker{
		containers: []docker.Container{
			{
				ID: "c1", Name: "sonarr",
				Image: "lscr.io/linuxserver/sonarr:4.0.10-ls45", ImageID: "sha256:olda",
				Labels: map[string]string{"com.docker.compose.project": "media"},
			},
			{
				ID: "c2", Name: "radarr",
				Image: "lscr.io/linuxserver/radarr:5.0.0-ls12", ImageID: "sha256:samea",
				Labels: map[string]string{},
			},
			{
				ID: "c3", Name: "secret",
				Image:  "ghcr.io/owner/private:1.0",
				Labels: map[string]string{"bulwark.enable": "false"},
			},
		},
		images: map[string]*docker.ImageInspect{
			"sha256:olda":  {RepoDigests: []string{"lscr.io/linuxserver/sonarr@sha256:older"}},
			"sha256:samea": {RepoDigests: []string{"lscr.io/linuxserver/radarr@sha256:current"}},
		},
	}
	fr := &fakeRegistry{digests: map[string]string{
		"lscr.io/linuxserver/sonarr:4.0.10-ls45": "sha256:newer",
		"lscr.io/linuxserver/radarr:5.0.0-ls12":  "sha256:current",
	}}

	var stdout, stderr bytes.Buffer
	err := cmdScanWith([]string{"--json", "--no-fetch-notes"}, &stdout, &stderr,
		scanDeps{Docker: fd, Registry: fr})
	if err != nil {
		t.Fatalf("cmdScan: %v\nstderr: %s", err, stderr.String())
	}

	var got []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode JSON: %v\noutput: %s", err, stdout.String())
	}
	if len(got) != 3 {
		t.Fatalf("got %d results, want 3", len(got))
	}

	byName := map[string]map[string]any{}
	for _, r := range got {
		byName[r["container"].(string)] = r
	}

	sonarr := byName["sonarr"]
	if sonarr["update_available"] != true {
		t.Errorf("sonarr update_available = %v, want true", sonarr["update_available"])
	}
	if sonarr["level"] != "safe" {
		t.Errorf("sonarr level = %v, want safe (LSIO rebuild)", sonarr["level"])
	}
	if sonarr["compose_project"] != "media" {
		t.Errorf("sonarr compose_project = %v", sonarr["compose_project"])
	}

	radarr := byName["radarr"]
	if radarr["update_available"] != false {
		t.Errorf("radarr update_available = %v, want false", radarr["update_available"])
	}

	secret := byName["secret"]
	if secret["skipped"] != true {
		t.Errorf("secret skipped = %v, want true", secret["skipped"])
	}
	if !strings.Contains(secret["skip_reason"].(string), "bulwark.enable") {
		t.Errorf("secret skip_reason = %v", secret["skip_reason"])
	}
}

func TestCmdScan_TextOutput_ContainsActionableSummary(t *testing.T) {
	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "c1", Name: "app",
			Image: "ghcr.io/owner/app:1.0.0", ImageID: "sha256:old",
			Labels: map[string]string{},
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:old": {RepoDigests: []string{"ghcr.io/owner/app@sha256:olddigest"}},
		},
	}
	fr := &fakeRegistry{digests: map[string]string{
		"ghcr.io/owner/app:1.0.0": "sha256:newdigest",
	}}

	var stdout, stderr bytes.Buffer
	err := cmdScanWith([]string{"--no-fetch-notes", "--no-color"}, &stdout, &stderr,
		scanDeps{Docker: fd, Registry: fr})
	if err != nil {
		t.Fatalf("cmdScan: %v\nstderr: %s", err, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{"app", "ghcr.io/owner/app:1.0.0", "SAFE", "1 update(s) pending"} {
		if !strings.Contains(output, want) {
			t.Errorf("expected output to contain %q\n--- output ---\n%s", want, output)
		}
	}
}

func TestCmdScan_RejectsPositionalArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := cmdScan([]string{"unexpected"}, &stdout, &stderr); err == nil {
		t.Error("expected error for unexpected positional arg")
	}
}
