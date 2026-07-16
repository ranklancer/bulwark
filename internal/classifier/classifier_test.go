package classifier

import (
	"context"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/pkg/types"
)

func TestClassify_NoNotes_PolicyMapping(t *testing.T) {
	c := New(DefaultConfig())
	ctx := context.Background()

	cases := []struct {
		name      string
		current   types.ImageInfo
		available types.ImageInfo
		wantLevel types.RiskLevel
		wantKind  types.ChangeKind
	}{
		{
			name:      "patch-is-safe",
			current:   types.ImageInfo{Repository: "registry.example.com/app", Tag: "1.2.3"},
			available: types.ImageInfo{Repository: "registry.example.com/app", Tag: "1.2.4"},
			wantLevel: types.RiskSafe,
			wantKind:  types.ChangePatch,
		},
		{
			name:      "minor-is-review",
			current:   types.ImageInfo{Repository: "registry.example.com/app", Tag: "1.2.3"},
			available: types.ImageInfo{Repository: "registry.example.com/app", Tag: "1.3.0"},
			wantLevel: types.RiskReview,
			wantKind:  types.ChangeMinor,
		},
		{
			name:      "major-is-breaking",
			current:   types.ImageInfo{Repository: "registry.example.com/app", Tag: "1.2.3"},
			available: types.ImageInfo{Repository: "registry.example.com/app", Tag: "2.0.0"},
			wantLevel: types.RiskBreaking,
			wantKind:  types.ChangeMajor,
		},
		{
			name:      "lsio-rebuild-is-safe",
			current:   types.ImageInfo{Repository: "lscr.io/linuxserver/sonarr", Tag: "4.0.10-ls45"},
			available: types.ImageInfo{Repository: "lscr.io/linuxserver/sonarr", Tag: "4.0.10-ls46"},
			wantLevel: types.RiskSafe,
			wantKind:  types.ChangeLSIORebuild,
		},
		{
			name:      "latest-tag-is-review",
			current:   types.ImageInfo{Repository: "registry.example.com/app", Tag: "latest", Digest: "sha256:aaa"},
			available: types.ImageInfo{Repository: "registry.example.com/app", Tag: "latest", Digest: "sha256:bbb"},
			wantLevel: types.RiskReview,
			wantKind:  types.ChangeLatest,
		},
		{
			name:      "no-change",
			current:   types.ImageInfo{Repository: "registry.example.com/app", Tag: "1.2.3", Digest: "sha256:aaa"},
			available: types.ImageInfo{Repository: "registry.example.com/app", Tag: "1.2.3", Digest: "sha256:aaa"},
			wantLevel: types.RiskSafe,
			wantKind:  types.ChangeNone,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.Classify(ctx, tc.current, tc.available, nil)
			if err != nil {
				t.Fatalf("Classify error: %v", err)
			}
			if got.Level != tc.wantLevel {
				t.Errorf("Level = %v, want %v (rationale: %s)", got.Level, tc.wantLevel, got.Rationale)
			}
			if got.Delta.Kind != tc.wantKind {
				t.Errorf("Delta.Kind = %v, want %v", got.Delta.Kind, tc.wantKind)
			}
		})
	}
}

func TestClassify_KeywordsRatchetUpward(t *testing.T) {
	c := New(DefaultConfig())
	ctx := context.Background()

	current := types.ImageInfo{Repository: "registry.example.com/app", Tag: "1.2.3"}
	available := types.ImageInfo{Repository: "registry.example.com/app", Tag: "1.2.4"} // would be SAFE without keywords

	t.Run("breaking-keyword-escalates-patch-to-breaking", func(t *testing.T) {
		notes := &ReleaseNotes{Body: "This release contains a breaking change to the auth flow.", URL: "https://releases.example.com/1.2.4"}
		got, err := c.Classify(ctx, current, available, notes)
		if err != nil {
			t.Fatalf("Classify error: %v", err)
		}
		if got.Level != types.RiskBreaking {
			t.Errorf("Level = %v, want RiskBreaking (rationale: %s)", got.Level, got.Rationale)
		}
		if got.Confidence != types.ConfidenceHigh {
			t.Errorf("Confidence = %v, want High", got.Confidence)
		}
		if !contains(got.MatchedTokens, "breaking change") {
			t.Errorf("expected matched token 'breaking change', got %v", got.MatchedTokens)
		}
		if got.ReleaseURL != notes.URL {
			t.Errorf("ReleaseURL = %q, want %q", got.ReleaseURL, notes.URL)
		}
	})

	t.Run("migration-keyword-escalates-patch-to-review", func(t *testing.T) {
		notes := &ReleaseNotes{Body: "Database migration required before starting."}
		got, err := c.Classify(ctx, current, available, notes)
		if err != nil {
			t.Fatalf("Classify error: %v", err)
		}
		if got.Level != types.RiskReview {
			t.Errorf("Level = %v, want RiskReview (rationale: %s)", got.Level, got.Rationale)
		}
	})

	t.Run("security-keyword-does-not-change-level", func(t *testing.T) {
		notes := &ReleaseNotes{Body: "Includes fix for CVE-2025-12345."}
		got, err := c.Classify(ctx, current, available, notes)
		if err != nil {
			t.Fatalf("Classify error: %v", err)
		}
		// Patch with no breaking/migration keywords stays SAFE per default policy.
		if got.Level != types.RiskSafe {
			t.Errorf("Level = %v, want RiskSafe", got.Level)
		}
		if !strings.Contains(got.Rationale, "Security keywords") {
			t.Errorf("expected rationale to mention security keywords, got: %s", got.Rationale)
		}
	})

	t.Run("breaking-keyword-on-major-stays-breaking", func(t *testing.T) {
		major := types.ImageInfo{Repository: current.Repository, Tag: "2.0.0"}
		notes := &ReleaseNotes{Body: "Breaking change: removed support for v1 config."}
		got, err := c.Classify(ctx, current, major, notes)
		if err != nil {
			t.Fatalf("Classify error: %v", err)
		}
		if got.Level != types.RiskBreaking {
			t.Errorf("Level = %v, want RiskBreaking", got.Level)
		}
	})

	t.Run("security-keyword-does-not-downgrade-major", func(t *testing.T) {
		major := types.ImageInfo{Repository: current.Repository, Tag: "2.0.0"}
		notes := &ReleaseNotes{Body: "This major release fixes CVE-2025-12345."}
		got, err := c.Classify(ctx, current, major, notes)
		if err != nil {
			t.Fatalf("Classify error: %v", err)
		}
		if got.Level != types.RiskBreaking {
			t.Errorf("major+security stayed at %v, want RiskBreaking (security must not downgrade)", got.Level)
		}
	})
}

func TestClassify_RepositoryMismatchIsError(t *testing.T) {
	c := New(DefaultConfig())
	_, err := c.Classify(context.Background(),
		types.ImageInfo{Repository: "registry.example.com/a", Tag: "1.0.0"},
		types.ImageInfo{Repository: "registry.example.com/b", Tag: "1.0.1"},
		nil,
	)
	if err == nil {
		t.Fatal("expected error for repository mismatch, got nil")
	}
}

func TestClassify_TrustedRebuilderUpgradesDigestToLSIORebuild(t *testing.T) {
	c := New(DefaultConfig())
	got, err := c.Classify(context.Background(),
		types.ImageInfo{Repository: "lscr.io/linuxserver/sonarr", Tag: "stable", Digest: "sha256:aaa"},
		types.ImageInfo{Repository: "lscr.io/linuxserver/sonarr", Tag: "stable", Digest: "sha256:bbb"},
		nil,
	)
	if err != nil {
		t.Fatalf("Classify error: %v", err)
	}
	if got.Delta.Kind != types.ChangeLSIORebuild {
		t.Errorf("Kind = %v, want LSIORebuild (LSIO trusted-rebuilder digest change)", got.Delta.Kind)
	}
	if got.Level != types.RiskSafe {
		t.Errorf("Level = %v, want RiskSafe", got.Level)
	}
}

func TestClassify_NoChangeReturnsHighConfidence(t *testing.T) {
	c := New(DefaultConfig())
	img := types.ImageInfo{Repository: "registry.example.com/app", Tag: "1.2.3", Digest: "sha256:aaa"}
	got, err := c.Classify(context.Background(), img, img, nil)
	if err != nil {
		t.Fatalf("Classify error: %v", err)
	}
	if got.Confidence != types.ConfidenceHigh {
		t.Errorf("Confidence = %v, want High for unchanged image", got.Confidence)
	}
}

func TestPolicy_DefaultMappings(t *testing.T) {
	p := DefaultPolicy()
	cases := map[types.ChangeKind]types.RiskLevel{
		types.ChangePatch:       types.RiskSafe,
		types.ChangeMinor:       types.RiskReview,
		types.ChangeMajor:       types.RiskBreaking,
		types.ChangeDigest:      types.RiskSafe,
		types.ChangeLatest:      types.RiskReview,
		types.ChangeLSIORebuild: types.RiskSafe,
		types.ChangePrerelease:  types.RiskReview,
		types.ChangeNone:        types.RiskSafe,
		types.ChangeKind(99):    types.RiskReview, // fallback to Default
	}
	for kind, want := range cases {
		if got := p.levelFor(kind); got != want {
			t.Errorf("policy for %v = %v, want %v", kind, got, want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 100); got != "hello" {
		t.Errorf("under-budget got %q", got)
	}
	if got := truncate("hello world", 5); got != "hello…" {
		t.Errorf("over-budget got %q", got)
	}
	if got := truncate("hello", 0); got != "hello" {
		t.Errorf("zero budget should not truncate, got %q", got)
	}
}

func contains(s []string, want string) bool {
	for _, x := range s {
		if x == want {
			return true
		}
	}
	return false
}
