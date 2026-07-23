package cve

import (
	"encoding/json"
	"strings"
	"testing"
)

// a hardening tier: kills the real (non-equivalent) mutation survivors in internal/cve found
// by the 2026-07-23 Gremlins re-baseline (86.42% efficacy, 11 LIVED).
//
// KILLED here (8): assess.go:55 & :56 (closed-list severity ordering, NEGATION),
// assess.go:68 (HighestSeverity string, NEGATION), registry_advisory.go:113
// (numeric CVSS score band, NEGATION), scansource.go:99 (docker-scout/registry
// server-mode rejection, NEGATION), trivy.go:137 & :144 (@-prefix boundary).
//
// DELIBERATELY NOT killed — EQUIVALENT mutants (no behavioral difference, so no
// test can distinguish them; documented as not-live-gaps, per the a hardening tier precedent):
//   - assess.go:49  `if v.Severity > highest`  (>→>=): max-tracking; a tie
//     reassigns the same value, so behavior is identical.
//   - assess.go:56  BOUNDARY (>→>=): guarded by `if si != sj`, so on every
//     reachable state si != sj and `>` ≡ `>=`.
//   - dockerscout.go:88 and registry_advisory.go:75 `if sev > out[i].Severity`
//     (>→>=): dedup keep-max; a tie reassigns the same severity.
// Confirmed post-state: see re-baseline note at end of file.

func TestAssessUpgrade_ClosedListOrdering_KillsSortMutants(t *testing.T) {
	// Severity-descending, then ID-ascending. IDs are chosen so severity order
	// and pure ID order DISAGREE: the Critical has the alphabetically-last ID.
	cur := []Vuln{
		{ID: "AAA-high", Severity: SeverityHigh},
		{ID: "ZZZ-crit", Severity: SeverityCritical},
		{ID: "MMM-high", Severity: SeverityHigh},
	}
	sa := AssessUpgrade(cur, nil, SeverityLow)
	if sa.ClosedCount != 3 {
		t.Fatalf("ClosedCount = %d, want 3", sa.ClosedCount)
	}
	// Critical must sort FIRST despite having the last ID — kills the `si != sj`
	// negation (which collapses to pure ID-asc -> AAA first) and the `si > sj`
	// negation (which reverses to severity-asc -> AAA/high first).
	if got := sa.Closed[0].ID; got != "ZZZ-crit" {
		t.Fatalf("Closed[0].ID = %q, want ZZZ-crit (severity-desc must win over ID)", got)
	}
	if sa.Closed[0].Severity != "critical" {
		t.Fatalf("Closed[0].Severity = %q, want critical", sa.Closed[0].Severity)
	}
	// Equal-severity entries fall back to ID-ascending.
	if sa.Closed[1].ID != "AAA-high" || sa.Closed[2].ID != "MMM-high" {
		t.Fatalf("high tier order = [%s %s], want [AAA-high MMM-high]", sa.Closed[1].ID, sa.Closed[2].ID)
	}
}

func TestAssessUpgrade_HighestSeverityString_KillsNegation(t *testing.T) {
	// Non-empty closed set -> HighestSeverity is the max severity string.
	sa := AssessUpgrade([]Vuln{{ID: "X", Severity: SeverityCritical}}, nil, SeverityLow)
	if sa.HighestSeverity != "critical" {
		t.Fatalf("HighestSeverity = %q, want critical (kills the != -> == negation)", sa.HighestSeverity)
	}
	// Empty closed set -> highest is Unknown -> string stays empty (not "unknown").
	none := AssessUpgrade(nil, nil, SeverityLow)
	if none.HighestSeverity != "" {
		t.Fatalf("HighestSeverity(empty) = %q, want \"\"", none.HighestSeverity)
	}
}

func TestOSVSeverity_NumericScoreBand_KillsNegation(t *testing.T) {
	// No textual DB severity; only a numeric CVSS score -> banded via score.
	var v osvVuln
	if err := json.Unmarshal([]byte(`{"id":"GHSA-x","database_specific":{"severity":""},"severity":[{"type":"CVSS_V3","score":"9.8"}]}`), &v); err != nil {
		t.Fatal(err)
	}
	if got := osvSeverity(v); got != SeverityCritical {
		t.Fatalf("osvSeverity(score 9.8) = %v, want Critical (kills the band != Unknown negation)", got)
	}
}

func TestNewScanSource_ServerModeRejected_KillsNegation(t *testing.T) {
	// docker-scout WITH a server URL must be rejected as server-mode, even though
	// a report_dir is also present. Kills the `ServerURL != "" -> == ""` negation.
	_, err := NewScanSource(ScanSourceSpec{Provider: "docker-scout", ServerURL: "http://scanner:1", ReportDir: "/reports"})
	if err == nil || !strings.Contains(err.Error(), "server mode") {
		t.Fatalf("err = %v, want a 'server mode is not implemented' rejection", err)
	}
}

func TestTrimDigestDigestOf_AtBoundary_KillsBoundary(t *testing.T) {
	// "@" at index 0 is the boundary that separates i>=0 (correct) from i>0.
	if got := trimDigest("@sha256:abc"); got != "" {
		t.Fatalf("trimDigest(@-prefixed) = %q, want \"\" (kills i>=0 -> i>0 boundary)", got)
	}
	if got := digestOf("@sha256:abc"); got != "sha256:abc" {
		t.Fatalf("digestOf(@-prefixed) = %q, want sha256:abc", got)
	}
	// Regression guards for the normal cases.
	if trimDigest("repo@dig") != "repo" || digestOf("repo@dig") != "dig" {
		t.Fatalf("normal split wrong: %q / %q", trimDigest("repo@dig"), digestOf("repo@dig"))
	}
	if trimDigest("repo") != "repo" || digestOf("repo") != "" {
		t.Fatalf("no-digest case wrong: %q / %q", trimDigest("repo"), digestOf("repo"))
	}
}

// Re-baseline (2026-07-23, with this change): efficacy 86.42% -> 93.98%
// (killed 70 -> 78, lived 11 -> 5, not-covered 18 -> 16). The 5 residual LIVED
// are all provably-equivalent boundary mutants and cannot be killed:
// assess.go:49 (max-track, >=), assess.go:56 (guarded by si!=sj), assess.go:58
// (deduped distinct IDs, < == <=), dockerscout.go:88 and registry_advisory.go:75
// (dedup keep-max, >=).
