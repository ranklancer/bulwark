package verify

import (
	"context"
	"testing"

	"github.com/ranklancer/bulwark/internal/cve"
)

// a hardening tier benchstat baseline: deploy-time trust gate hot path.
// Reuses the fakes defined in gate_test.go (same package).

func BenchmarkGateEvaluate_Disabled(b *testing.B) {
	g := Gate{Policy: Policy{Enabled: false}, Signature: untrustedVerifier()}
	in := Input{PinnedRef: "repo@sha256:abc"}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.Evaluate(ctx, in)
	}
}

func BenchmarkGateEvaluate_SignedClean(b *testing.B) {
	g := Gate{
		Policy: Policy{
			Enabled:   true,
			Signature: sigBlockPolicy(),
			Vuln:      VulnPolicy{Mode: ModeBlock, BlockThreshold: cve.SeverityCritical},
		},
		Signature: trustedVerifier(),
		Vulns:     fakeSource{vulns: []cve.Vuln{{ID: "CVE-2020-1", Severity: cve.SeverityMedium}}},
	}
	in := Input{PinnedRef: "repo@sha256:abc"}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.Evaluate(ctx, in)
	}
}
