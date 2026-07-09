package verify

import (
	"errors"
	"testing"

	"github.com/bulwark-docker/bulwark/internal/cve"
)

func TestVerdictRemediation(t *testing.T) {
	errBoom := errors.New("boom")
	cases := []struct {
		name string
		v    Verdict
		want RemediationCode
	}{
		{"clean allow", Verdict{Decision: DecisionAllow}, RemediationNone},
		{"signature untrusted", Verdict{Signature: SignatureResult{Evaluated: true, Verified: false}}, RemediationSignatureUntrusted},
		{"signature verifier error", Verdict{Signature: SignatureResult{Evaluated: true, Err: errBoom}}, RemediationVerifierUnavailable},
		{"signature ok but vuln blocking", Verdict{Signature: SignatureResult{Evaluated: true, Verified: true}, Vuln: VulnResult{Evaluated: true, Blocking: []cve.Vuln{{}}}}, RemediationVulnerable},
		{"vuln source error", Verdict{Vuln: VulnResult{Evaluated: true, Err: errBoom}}, RemediationVerifierUnavailable},
	}
	for _, tc := range cases {
		if got := tc.v.Remediation(); got != tc.want {
			t.Errorf("%s: Remediation() = %q, want %q", tc.name, got, tc.want)
		}
	}
}
