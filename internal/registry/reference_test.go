package registry

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in        string
		registry  string
		repo      string
		tag       string
		digest    string
		expectErr bool
	}{
		{"nginx", "registry-1.docker.io", "library/nginx", "latest", "", false},
		{"nginx:1.25", "registry-1.docker.io", "library/nginx", "1.25", "", false},
		{"myorg/myrepo", "registry-1.docker.io", "myorg/myrepo", "latest", "", false},
		{"myorg/myrepo:v1", "registry-1.docker.io", "myorg/myrepo", "v1", "", false},
		{"docker.io/library/redis:7", "registry-1.docker.io", "library/redis", "7", "", false},
		{"index.docker.io/library/redis:7", "registry-1.docker.io", "library/redis", "7", "", false},
		{"lscr.io/linuxserver/sonarr", "lscr.io", "linuxserver/sonarr", "latest", "", false},
		{"lscr.io/linuxserver/sonarr:4.0.10-ls45", "lscr.io", "linuxserver/sonarr", "4.0.10-ls45", "", false},
		{"ghcr.io/owner/app:1.2.3", "ghcr.io", "owner/app", "1.2.3", "", false},
		{"registry.example.com:5000/app", "registry.example.com:5000", "app", "latest", "", false},
		{"registry.example.com:5000/app:v1", "registry.example.com:5000", "app", "v1", "", false},
		{"registry.example.com:5000/team/app:v1", "registry.example.com:5000", "team/app", "v1", "", false},
		{"localhost/myapp:v1", "localhost", "myapp", "v1", "", false},
		{"nginx@sha256:abc", "registry-1.docker.io", "library/nginx", "", "sha256:abc", false},
		{"nginx:1.25@sha256:abc", "registry-1.docker.io", "library/nginx", "1.25", "sha256:abc", false},
		{"lscr.io/linuxserver/sonarr@sha256:def", "lscr.io", "linuxserver/sonarr", "", "sha256:def", false},
		{"", "", "", "", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := Parse(tc.in)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("Parse(%q) expected error, got %+v", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.in, err)
			}
			if got.Registry != tc.registry {
				t.Errorf("Parse(%q).Registry = %q, want %q", tc.in, got.Registry, tc.registry)
			}
			if got.Repository != tc.repo {
				t.Errorf("Parse(%q).Repository = %q, want %q", tc.in, got.Repository, tc.repo)
			}
			if got.Tag != tc.tag {
				t.Errorf("Parse(%q).Tag = %q, want %q", tc.in, got.Tag, tc.tag)
			}
			if got.Digest != tc.digest {
				t.Errorf("Parse(%q).Digest = %q, want %q", tc.in, got.Digest, tc.digest)
			}
		})
	}
}

func TestReference_FullName_RoundTrip(t *testing.T) {
	cases := []string{
		"lscr.io/linuxserver/sonarr:4.0.10-ls45",
		"ghcr.io/owner/app:1.2.3@sha256:abc",
		"registry.example.com:5000/team/app:v1",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			r, err := Parse(in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", in, err)
			}
			if r.String() != in {
				t.Errorf("round-trip mismatch:\n  in:  %s\n  out: %s", in, r.String())
			}
		})
	}
}

func TestReference_ToImageInfo(t *testing.T) {
	r, err := Parse("lscr.io/linuxserver/sonarr:4.0.10-ls45")
	if err != nil {
		t.Fatal(err)
	}
	info := r.ToImageInfo()
	if info.Repository != "lscr.io/linuxserver/sonarr" {
		t.Errorf("Repository = %q", info.Repository)
	}
	if info.Tag != "4.0.10-ls45" {
		t.Errorf("Tag = %q", info.Tag)
	}
}
