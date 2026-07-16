package classifier

import (
	"testing"

	"github.com/ranklancer/bulwark/pkg/types"
)

func TestParseTag(t *testing.T) {
	cases := []struct {
		name string
		tag  string
		want version
		ok   bool
	}{
		{"plain", "1.2.3", version{Major: 1, Minor: 2, Patch: 3, Raw: "1.2.3"}, true},
		{"v-prefix", "v1.2.3", version{Major: 1, Minor: 2, Patch: 3, Raw: "v1.2.3"}, true},
		{"V-prefix", "V1.2.3", version{Major: 1, Minor: 2, Patch: 3, Raw: "V1.2.3"}, true},
		{"prerelease", "1.2.3-rc.1", version{Major: 1, Minor: 2, Patch: 3, Prerelease: "rc.1", Raw: "1.2.3-rc.1"}, true},
		{"build-meta", "1.2.3+build.5", version{Major: 1, Minor: 2, Patch: 3, Build: "build.5", Raw: "1.2.3+build.5"}, true},
		{"prerelease-and-build", "1.2.3-beta.2+sha.abc", version{Major: 1, Minor: 2, Patch: 3, Prerelease: "beta.2", Build: "sha.abc", Raw: "1.2.3-beta.2+sha.abc"}, true},
		{"lsio", "1.2.3-ls45", version{Major: 1, Minor: 2, Patch: 3, LSIO: 45, HasLSIO: true, Raw: "1.2.3-ls45"}, true},
		{"lsio-v-prefix", "v1.2.3-ls45", version{Major: 1, Minor: 2, Patch: 3, LSIO: 45, HasLSIO: true, Raw: "v1.2.3-ls45"}, true},
		{"version-prefix", "version-1.2.3-ls45", version{Major: 1, Minor: 2, Patch: 3, LSIO: 45, HasLSIO: true, Raw: "version-1.2.3-ls45"}, true},
		{"prerelease-and-lsio", "1.2.3-rc1-ls45", version{Major: 1, Minor: 2, Patch: 3, Prerelease: "rc1", LSIO: 45, HasLSIO: true, Raw: "1.2.3-rc1-ls45"}, true},
		{"empty", "", version{}, false},
		{"latest-literal", "latest", version{}, false},
		{"non-numeric", "stable", version{}, false},
		{"two-component", "1.2", version{}, false},
		{"leading-zero-rejected", "01.2.3", version{}, false},
		{"sha-tag", "sha-abc123", version{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseTag(tc.tag)
			if ok != tc.ok {
				t.Fatalf("parseTag(%q) ok = %v, want %v", tc.tag, ok, tc.ok)
			}
			if !ok {
				return
			}
			if got.Major != tc.want.Major || got.Minor != tc.want.Minor || got.Patch != tc.want.Patch ||
				got.Prerelease != tc.want.Prerelease || got.Build != tc.want.Build ||
				got.LSIO != tc.want.LSIO || got.HasLSIO != tc.want.HasLSIO {
				t.Errorf("parseTag(%q) = %+v, want %+v", tc.tag, got, tc.want)
			}
		})
	}
}

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want int
	}{
		{"equal", "1.2.3", "1.2.3", 0},
		{"major-lt", "1.2.3", "2.0.0", -1},
		{"major-gt", "2.0.0", "1.2.3", 1},
		{"minor", "1.2.3", "1.3.0", -1},
		{"patch", "1.2.3", "1.2.4", -1},
		{"v-prefix-equal", "v1.2.3", "1.2.3", 0},
		{"prerelease-vs-release", "1.2.3-rc.1", "1.2.3", -1},
		{"prerelease-numeric", "1.2.3-rc.1", "1.2.3-rc.2", -1},
		{"prerelease-lex", "1.2.3-alpha", "1.2.3-beta", -1},
		{"prerelease-numeric-vs-alpha", "1.2.3-1", "1.2.3-alpha", -1},
		{"lsio-rebuild-newer", "1.2.3-ls45", "1.2.3-ls46", -1},
		{"lsio-rebuild-equal", "1.2.3-ls45", "1.2.3-ls45", 0},
		{"upstream-bump-with-lsio", "1.2.3-ls99", "1.2.4-ls1", -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, okA := parseTag(tc.a)
			b, okB := parseTag(tc.b)
			if !okA || !okB {
				t.Fatalf("parse failed: a=%v b=%v", okA, okB)
			}
			got := a.compare(b)
			if got != tc.want {
				t.Errorf("compare(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestClassifyChange(t *testing.T) {
	repo := "registry.example.com/app"
	img := func(tag, digest string) types.ImageInfo {
		return types.ImageInfo{Repository: repo, Tag: tag, Digest: digest}
	}

	cases := []struct {
		name      string
		current   types.ImageInfo
		available types.ImageInfo
		want      types.ChangeKind
	}{
		{"none-identical", img("1.2.3", "sha256:aaa"), img("1.2.3", "sha256:aaa"), types.ChangeNone},
		{"digest-rebuild", img("1.2.3", "sha256:aaa"), img("1.2.3", "sha256:bbb"), types.ChangeDigest},
		{"patch", img("1.2.3", "sha256:aaa"), img("1.2.4", "sha256:bbb"), types.ChangePatch},
		{"minor", img("1.2.3", ""), img("1.3.0", ""), types.ChangeMinor},
		{"major", img("1.2.3", ""), img("2.0.0", ""), types.ChangeMajor},
		{"downgrade-treated-as-none", img("2.0.0", ""), img("1.9.9", ""), types.ChangeNone},
		{"prerelease-bump", img("1.2.3-rc.1", ""), img("1.2.3-rc.2", ""), types.ChangePrerelease},
		{"prerelease-graduating-to-release", img("1.2.3-rc.1", ""), img("1.2.3", ""), types.ChangePrerelease},
		{"lsio-rebuild", img("1.2.3-ls45", ""), img("1.2.3-ls46", ""), types.ChangeLSIORebuild},
		{"lsio-upstream-patch", img("1.2.3-ls45", ""), img("1.2.4-ls1", ""), types.ChangePatch},
		{"latest-tag-digest-changed", img("latest", "sha256:aaa"), img("latest", "sha256:bbb"), types.ChangeLatest},
		{"latest-tag-no-change", img("latest", "sha256:aaa"), img("latest", "sha256:aaa"), types.ChangeNone},
		{"unparseable-same-tag-different-digest", img("stable", "sha256:aaa"), img("stable", "sha256:bbb"), types.ChangeDigest},
		{"unparseable-different-tag", img("stable", "sha256:aaa"), img("edge", "sha256:bbb"), types.ChangeUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyChange(tc.current, tc.available)
			if got != tc.want {
				t.Errorf("classifyChange = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestShortDigest(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"sha256:abcdef0123456789", "sha256:abcdef012345"},
		{"short", "short"},
		{"verylongstringnotahash", "verylongstri"},
	}
	for _, tc := range cases {
		if got := shortDigest(tc.in); got != tc.want {
			t.Errorf("shortDigest(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
