package main

import (
	"testing"

	"github.com/bulwark-docker/bulwark/pkg/types"
)

func TestParseRef(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want types.ImageInfo
	}{
		{
			name: "repo-tag",
			in:   "lscr.io/linuxserver/sonarr:4.0.10-ls45",
			want: types.ImageInfo{Repository: "lscr.io/linuxserver/sonarr", Tag: "4.0.10-ls45"},
		},
		{
			name: "repo-tag-digest",
			in:   "lscr.io/linuxserver/sonarr:4.0.10-ls45@sha256:abc",
			want: types.ImageInfo{Repository: "lscr.io/linuxserver/sonarr", Tag: "4.0.10-ls45", Digest: "sha256:abc"},
		},
		{
			name: "registry-with-port",
			in:   "registry.example.com:5000/app:1.2.3",
			want: types.ImageInfo{Repository: "registry.example.com:5000/app", Tag: "1.2.3"},
		},
		{
			name: "no-tag",
			in:   "registry.example.com/app",
			want: types.ImageInfo{Repository: "registry.example.com/app"},
		},
		{
			name: "digest-only",
			in:   "registry.example.com/app@sha256:abc",
			want: types.ImageInfo{Repository: "registry.example.com/app", Digest: "sha256:abc"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRef(tc.in)
			if err != nil {
				t.Fatalf("parseRef error: %v", err)
			}
			if got != tc.want {
				t.Errorf("parseRef(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseRef_Empty(t *testing.T) {
	if _, err := parseRef(""); err == nil {
		t.Fatal("expected error for empty reference")
	}
}
