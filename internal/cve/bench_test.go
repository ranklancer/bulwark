package cve

import "testing"

// a hardening tier benchstat baseline: closed-CVE / urgency assessment hot path.
func BenchmarkAssessUpgrade(b *testing.B) {
	cur := []Vuln{
		{ID: "C1", Severity: SeverityCritical},
		{ID: "H1", Severity: SeverityHigh},
		{ID: "H2", Severity: SeverityHigh},
		{ID: "M1", Severity: SeverityMedium},
		{ID: "L1", Severity: SeverityLow},
	}
	cand := []Vuln{{ID: "H1", Severity: SeverityHigh}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AssessUpgrade(cur, cand, SeverityHigh)
	}
}
