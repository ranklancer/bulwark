package classifier

import "testing"

func TestKeywordScan_Defaults(t *testing.T) {
	ks := NewKeywordSet(nil, nil, nil)

	cases := []struct {
		name      string
		text      string
		wantClass map[KeywordClass]bool
	}{
		{
			name:      "empty",
			text:      "",
			wantClass: map[KeywordClass]bool{},
		},
		{
			name:      "no-signal",
			text:      "Bumped Go version. Improved logging.",
			wantClass: map[KeywordClass]bool{},
		},
		{
			name:      "breaking-phrase",
			text:      "This release contains a breaking change to the API.",
			wantClass: map[KeywordClass]bool{KeywordBreaking: true},
		},
		{
			name:      "migration-phrase",
			text:      "Database migration required before starting the new version.",
			wantClass: map[KeywordClass]bool{KeywordMigration: true},
		},
		{
			name:      "security-phrase",
			text:      "Includes fix for CVE-2025-12345.",
			wantClass: map[KeywordClass]bool{KeywordSecurity: true},
		},
		{
			name:      "case-insensitive",
			text:      "BREAKING CHANGE: removed support for v1 API.",
			wantClass: map[KeywordClass]bool{KeywordBreaking: true},
		},
		{
			name: "multiple-classes",
			text: "Schema migration required. Includes security patch for CVE-2025-99999. " +
				"Backwards incompatible with v1.",
			wantClass: map[KeywordClass]bool{
				KeywordBreaking:  true,
				KeywordMigration: true,
				KeywordSecurity:  true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := ks.Scan(tc.text)
			got := make(map[KeywordClass]bool)
			for _, m := range matches {
				got[m.Class] = true
			}
			for c := range tc.wantClass {
				if !got[c] {
					t.Errorf("expected class %v in matches, got %v (matches=%+v)", c, got, matches)
				}
			}
			for c := range got {
				if !tc.wantClass[c] {
					t.Errorf("unexpected class %v in matches: %+v", c, matches)
				}
			}
		})
	}
}

func TestKeywordScan_WordBoundaries(t *testing.T) {
	ks := NewKeywordSet([]string{"removed"}, nil, nil)
	if got := ks.Scan("Fixed an issue where the file was not being removed."); len(got) != 1 {
		t.Errorf("expected 1 match for 'removed', got %d (%+v)", len(got), got)
	}
	if got := ks.Scan("New flag --remove-orphans."); len(got) != 0 {
		t.Errorf("expected no match for substring 'remove' inside other word, got %+v", got)
	}
}

func TestKeywordScan_NilReceiverSafe(t *testing.T) {
	var ks *KeywordSet
	if got := ks.Scan("breaking change"); got != nil {
		t.Errorf("nil receiver should return nil, got %+v", got)
	}
}

func TestKeywordScan_RegexCharsInUserKeywords(t *testing.T) {
	// User keywords with regex metacharacters must be treated as literals.
	ks := NewKeywordSet([]string{"v1.0+"}, nil, nil)
	matches := ks.Scan("This release removes v1.0+ support.")
	if len(matches) != 1 {
		t.Errorf("expected literal match for 'v1.0+', got %+v", matches)
	}
}
