package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/internal/registry"
	"github.com/ranklancer/bulwark/internal/releasenotes"
)

func TestCmdCheck_EndToEnd_Patch_WithReleaseNotes(t *testing.T) {
	regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/manifests/4.0.9-ls45"):
			w.Header().Set("Docker-Content-Digest", "sha256:c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0")
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/manifests/4.0.10-ls46"):
			w.Header().Set("Docker-Content-Digest", "sha256:7070707070707070707070707070707070707070707070707070707070707070")
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected registry path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer regSrv.Close()

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the stripped upstream tag has a release.
		if r.URL.Path == "/repos/linuxserver/docker-sonarr/releases/tags/4.0.10" {
			fmt.Fprintln(w, `{"tag_name":"4.0.10","html_url":"https://github.com/linuxserver/docker-sonarr/releases/tag/4.0.10","body":"Patch release: small bug fixes."}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ghSrv.Close()

	regClient := registry.New()
	regClient.BaseURL = regSrv.URL
	ghClient := releasenotes.NewGitHubClient()
	ghClient.BaseURL = ghSrv.URL

	var stdout, stderr bytes.Buffer
	err := cmdCheckWith(
		[]string{"lscr.io/linuxserver/sonarr:4.0.9-ls45", "4.0.10-ls46"},
		&stdout, &stderr,
		checkDeps{Registry: regClient, GitHub: ghClient},
	)
	if err != nil {
		t.Fatalf("cmdCheck: %v\nstderr: %s", err, stderr.String())
	}

	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode stdout JSON: %v\nstdout: %s", err, stdout.String())
	}
	if got["level"] != "safe" {
		t.Errorf("level = %v, want safe", got["level"])
	}
	if got["kind"] != "patch" {
		t.Errorf("kind = %v, want patch", got["kind"])
	}
	if got["current_digest"] != "sha256:c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0" {
		t.Errorf("current_digest = %v", got["current_digest"])
	}
	if got["target_digest"] != "sha256:7070707070707070707070707070707070707070707070707070707070707070" {
		t.Errorf("target_digest = %v", got["target_digest"])
	}
	if !strings.Contains(got["notes_source"].(string), "linuxserver/docker-sonarr") {
		t.Errorf("notes_source = %v", got["notes_source"])
	}
}

func TestCmdCheck_KeywordEscalatesToBreaking(t *testing.T) {
	regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Content-Digest", pathDigest(r.URL.Path))
		w.WriteHeader(http.StatusOK)
	}))
	defer regSrv.Close()

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"tag_name":"1.3.0","body":"This release contains a breaking change to the API."}`)
	}))
	defer ghSrv.Close()

	regClient := registry.New()
	regClient.BaseURL = regSrv.URL
	ghClient := releasenotes.NewGitHubClient()
	ghClient.BaseURL = ghSrv.URL

	var stdout, stderr bytes.Buffer
	err := cmdCheckWith(
		[]string{"ghcr.io/owner/app:1.2.3", "1.3.0"},
		&stdout, &stderr,
		checkDeps{Registry: regClient, GitHub: ghClient},
	)
	if err != nil {
		t.Fatalf("cmdCheck: %v\nstderr: %s", err, stderr.String())
	}
	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["level"] != "breaking" {
		t.Errorf("expected breaking after keyword match, got level=%v rationale=%v", got["level"], got["rationale"])
	}
}

func TestCmdCheck_UnknownImage_NoNotesButStillClassifies(t *testing.T) {
	regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Content-Digest", pathDigest(r.URL.Path))
		w.WriteHeader(http.StatusOK)
	}))
	defer regSrv.Close()

	regClient := registry.New()
	regClient.BaseURL = regSrv.URL
	// No GH stub — the mapper will yield no source for a private registry,
	// so the GitHub client should never be reached.

	var stdout, stderr bytes.Buffer
	err := cmdCheckWith(
		[]string{"registry.example.com/team/app:1.0.0", "2.0.0"},
		&stdout, &stderr,
		checkDeps{Registry: regClient},
	)
	if err != nil {
		t.Fatalf("cmdCheck: %v\nstderr: %s", err, stderr.String())
	}
	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["level"] != "breaking" {
		t.Errorf("major bump without notes should be breaking by default, got %v", got["level"])
	}
	if _, ok := got["notes_source"]; ok {
		t.Errorf("notes_source should be absent when no source is found, got %v", got["notes_source"])
	}
}

func TestCmdCheck_RequiresTwoArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := cmdCheck([]string{"only-one"}, &stdout, &stderr); err == nil {
		t.Fatal("expected error for missing positional args")
	}
}

func pathDigest(p string) string {
	sum := sha256.Sum256([]byte(p))
	return "sha256:" + hex.EncodeToString(sum[:])
}
