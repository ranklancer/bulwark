package releasenotes

import (
	"reflect"
	"testing"

	"github.com/ranklancer/bulwark/internal/registry"
)

func TestMapper_Defaults(t *testing.T) {
	m := NewMapper()

	cases := []struct {
		name string
		ref  registry.Reference
		want Source
		ok   bool
	}{
		{
			name: "lscr-linuxserver",
			ref:  registry.Reference{Registry: "lscr.io", Repository: "linuxserver/sonarr"},
			want: Source{Provider: ProviderGitHub, Owner: "linuxserver", Repo: "docker-sonarr"},
			ok:   true,
		},
		{
			name: "ghcr-linuxserver",
			ref:  registry.Reference{Registry: "ghcr.io", Repository: "linuxserver/radarr"},
			want: Source{Provider: ProviderGitHub, Owner: "linuxserver", Repo: "docker-radarr"},
			ok:   true,
		},
		{
			name: "ghcr-generic",
			ref:  registry.Reference{Registry: "ghcr.io", Repository: "owner/app"},
			want: Source{Provider: ProviderGitHub, Owner: "owner", Repo: "app"},
			ok:   true,
		},
		{
			name: "dockerhub-no-default-mapping",
			ref:  registry.Reference{Registry: "registry-1.docker.io", Repository: "library/nginx"},
			ok:   false,
		},
		{
			name: "private-registry-no-mapping",
			ref:  registry.Reference{Registry: "registry.example.com", Repository: "team/app"},
			ok:   false,
		},
		{
			name: "ghcr-too-deep-no-mapping",
			ref:  registry.Reference{Registry: "ghcr.io", Repository: "owner/team/app"},
			ok:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := m.Map(tc.ref)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (got=%+v)", ok, tc.ok, got)
			}
			if !ok {
				return
			}
			if got != tc.want {
				t.Errorf("source = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestMapper_Override_LongestPrefixWins(t *testing.T) {
	m := NewMapper()
	// Less specific override
	m.Add("registry.example.com/", Source{Provider: ProviderGitHub, Owner: "team", Repo: "default"})
	// More specific override
	m.Add("registry.example.com/team/special", Source{Provider: ProviderGitHub, Owner: "team", Repo: "special"})

	got, ok := m.Map(registry.Reference{Registry: "registry.example.com", Repository: "team/special"})
	if !ok {
		t.Fatal("expected mapping to be found")
	}
	if got.Repo != "special" {
		t.Errorf("longest-prefix mismatch: got %+v", got)
	}

	got, ok = m.Map(registry.Reference{Registry: "registry.example.com", Repository: "team/other"})
	if !ok {
		t.Fatal("expected mapping to be found")
	}
	if got.Repo != "default" {
		t.Errorf("default-prefix mismatch: got %+v", got)
	}
}

func TestCandidateTags(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"latest", nil},
		{"1.2.3", []string{"1.2.3", "v1.2.3"}},
		{"v1.2.3", []string{"v1.2.3", "1.2.3"}},
		{"4.0.10-ls45", []string{"4.0.10-ls45", "v4.0.10-ls45", "4.0.10", "v4.0.10"}},
		{"v4.0.10-ls45", []string{"v4.0.10-ls45", "4.0.10-ls45", "v4.0.10", "4.0.10"}},
		{"v4.0.10-rc1-ls45", []string{"v4.0.10-rc1-ls45", "4.0.10-rc1-ls45", "v4.0.10-rc1", "4.0.10-rc1"}},
		{"sha-abc123", []string{"sha-abc123"}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := CandidateTags(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("CandidateTags(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestSource_String(t *testing.T) {
	s := Source{Provider: ProviderGitHub, Owner: "linuxserver", Repo: "docker-sonarr"}
	if got := s.String(); got != "github.com/linuxserver/docker-sonarr" {
		t.Errorf("String() = %q", got)
	}
}
