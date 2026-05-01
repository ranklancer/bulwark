package releasenotes

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/bulwark-docker/bulwark/internal/registry"
)

func TestFetcher_LSIO_FallsBackToUpstreamTag(t *testing.T) {
	gh, _ := newGitHubStub(t, func(w http.ResponseWriter, r *http.Request) {
		// Only the stripped upstream tag exists; the LSIO tags 404.
		if strings.HasSuffix(r.URL.Path, "/releases/tags/4.0.10") {
			fmt.Fprintln(w, `{"tag_name":"4.0.10","body":"upstream","html_url":"https://example.com/r"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	f := &Fetcher{Mapper: NewMapper(), GitHub: gh}
	ref := registry.Reference{Registry: "lscr.io", Repository: "linuxserver/sonarr", Tag: "4.0.10-ls45"}
	res, err := f.Fetch(context.Background(), ref)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.Found() {
		t.Fatalf("expected to find notes, got %+v", res)
	}
	if res.Source.Owner != "linuxserver" || res.Source.Repo != "docker-sonarr" {
		t.Errorf("source = %+v", res.Source)
	}
	if res.Notes.Tag != "4.0.10" {
		t.Errorf("notes tag = %q", res.Notes.Tag)
	}
}

func TestFetcher_NoMappingReturnsEmptyResult(t *testing.T) {
	f := NewFetcher()
	res, err := f.Fetch(context.Background(), registry.Reference{
		Registry: "registry.example.com", Repository: "team/app", Tag: "1.0.0",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Found() {
		t.Errorf("expected no notes for unmapped image, got %+v", res)
	}
}

func TestFetcher_NoCandidatesForLatestTag(t *testing.T) {
	gh, _ := newGitHubStub(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("GitHub should not be called when there are no tag candidates")
	})
	f := &Fetcher{Mapper: NewMapper(), GitHub: gh}
	res, err := f.Fetch(context.Background(), registry.Reference{
		Registry: "ghcr.io", Repository: "owner/app", Tag: "latest",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Found() {
		t.Errorf("expected no notes for :latest, got %+v", res)
	}
	if res.Source.Owner != "owner" {
		t.Errorf("source should still be set: %+v", res.Source)
	}
}
