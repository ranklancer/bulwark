package revoke

import (
	"errors"
	"strings"
	"testing"
)

// defectExitCodeOnly mirrors the estate delivery-path defect recorded in
// p849 §8 finding #5 (source p842): the old shell pattern
//
//	curl --connect-timeout 3 --max-time 6 -sS -K "$REVOKE_CFG" \
//	    -X DELETE "${API_BASE}/installation/token" -o /dev/null 2>/dev/null \
//	    && revoked="true" || true
//
// recorded revoked=true whenever the revoke command exited 0 — and curl exits
// 0 on HTTP 401/404/500 (the server answered; only transport failure is
// non-zero), so a revoke that did not revoke was recorded as revoked. Keeping
// the defect's decision rule in this test (not production) pins what the bug
// WAS so the regression tests can demonstrate that the corrected check rejects
// the exact observations the defect mis-recorded.
func defectExitCodeOnly(curlExitCode int) bool { return curlExitCode == 0 }

// TestRevoke_DefectRecordsTrue_OnHTTP404_CheckMustFailClosed pins the finding's
// headline case: the defect recorded revoked=true when the server answered 404
// (no such installation token). The corrected check must fail closed on the
// same observation.
func TestRevoke_DefectRecordsTrue_OnHTTP404_CheckMustFailClosed(t *testing.T) {
	if !defectExitCodeOnly(0) {
		t.Fatal("precondition: the exit-code-only defect records revoked=true when curl exits 0")
	}
	revoked, detail := Revoked(Result{DeleteHTTPStatus: 404})
	if revoked {
		t.Fatalf("a DELETE that returned HTTP 404 did not revoke; must not be recorded revoked: %s", detail)
	}
	if !strings.Contains(detail, "404") {
		t.Fatalf("detail should name the offending status, got %q", detail)
	}
}

// TestRevoke_DefectRecordsTrue_OnHTTP401_CheckMustFailClosed pins the 401 case
// (token invalid / expired — still not a revocation performed by us).
func TestRevoke_DefectRecordsTrue_OnHTTP401_CheckMustFailClosed(t *testing.T) {
	if !defectExitCodeOnly(0) {
		t.Fatal("precondition: the exit-code-only defect records revoked=true when curl exits 0")
	}
	if revoked, _ := Revoked(Result{DeleteHTTPStatus: 401}); revoked {
		t.Fatal("a DELETE that returned HTTP 401 must not be recorded as revoked")
	}
}

// TestRevoke_DefectRecordsTrue_OnHTTP500_CheckMustFailClosed pins the 500 case
// (server error — the API did not revoke anything).
func TestRevoke_DefectRecordsTrue_OnHTTP500_CheckMustFailClosed(t *testing.T) {
	if !defectExitCodeOnly(0) {
		t.Fatal("precondition: the exit-code-only defect records revoked=true when curl exits 0")
	}
	if revoked, _ := Revoked(Result{DeleteHTTPStatus: 500}); revoked {
		t.Fatal("a DELETE that returned HTTP 500 must not be recorded as revoked")
	}
}

// TestRevoke_NoHTTPResponse_FailsClosed pins the transport-failure case: status
// 000 means no HTTP response at all, so there is nothing to assert and the
// revoke cannot be verified.
func TestRevoke_NoHTTPResponse_FailsClosed(t *testing.T) {
	if revoked, _ := Revoked(Result{DeleteHTTPStatus: 0}); revoked {
		t.Fatal("no HTTP response must not be recorded as revoked")
	}
}

// TestRevoke_204_ButProbeRejectedNotConfirmed_FailsClosed pins the card's
// read-back requirement: even a 204 is not trusted until the revocation state
// is read back. A zero-value ProbeRejected (probe never ran, or still
// authenticates) must fail closed — callers cannot skip the read-back.
func TestRevoke_204_ButProbeRejectedNotConfirmed_FailsClosed(t *testing.T) {
	revoked, detail := Revoked(Result{DeleteHTTPStatus: 204})
	if revoked {
		t.Fatal("a 204 without a read-back probe confirming rejection is not a verified revocation")
	}
	if !strings.Contains(detail, "read-back") {
		t.Fatalf("detail should name the missing read-back confirmation, got %q", detail)
	}
}

// TestRevoke_204_ButProbeFailed_FailsClosed pins the unreadable-state case: a
// read-back probe that could not run cannot confirm the revocation.
func TestRevoke_204_ButProbeFailed_FailsClosed(t *testing.T) {
	if revoked, _ := Revoked(Result{DeleteHTTPStatus: 204, ProbeErr: errors.New("probe timeout")}); revoked {
		t.Fatal("an unreadable revocation state must not be recorded as revoked")
	}
}

// TestRevoke_204_AndProbeRejected_Verified pins the only observation set that
// may record revoked=true: the DELETE returned 204 AND the read-back probe
// confirmed the credential is rejected.
func TestRevoke_204_AndProbeRejected_Verified(t *testing.T) {
	revoked, detail := Revoked(Result{DeleteHTTPStatus: 204, ProbeRejected: true})
	if !revoked {
		t.Fatalf("204 + read-back probe rejecting the credential is a verified revocation, got %q", detail)
	}
	if !strings.Contains(detail, "204") {
		t.Fatalf("verified detail should cite the 204, got %q", detail)
	}
}

// TestRevoke_RecordingContract pins the recording contract as a table: the
// bool Revoked returns IS the value a caller must record as `revoked=` — never
// a transport exit code. Any exit-code-only reimplementation of the check
// fails this table, so the p842 defect is caught here, not at deploy time.
func TestRevoke_RecordingContract(t *testing.T) {
	cases := []struct {
		name string
		in   Result
		want bool
	}{
		{"204+probe-rejected", Result{DeleteHTTPStatus: 204, ProbeRejected: true}, true},
		{"404", Result{DeleteHTTPStatus: 404}, false},
		{"401", Result{DeleteHTTPStatus: 401}, false},
		{"500", Result{DeleteHTTPStatus: 500}, false},
		{"000-no-http", Result{DeleteHTTPStatus: 0}, false},
		{"204-alone", Result{DeleteHTTPStatus: 204}, false},
		{"204+probe-err", Result{DeleteHTTPStatus: 204, ProbeErr: errors.New("boom")}, false},
		{"zero-value", Result{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := Revoked(tc.in); got != tc.want {
				t.Fatalf("Revoked(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
