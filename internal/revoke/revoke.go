// Package revoke verifies that a revocation actually took effect.
//
// p849 §8 finding #5 (source p842) records that the estate delivery-path
// revoke check was exit-code-only: `curl ... -X DELETE .../installation/token
// ... && revoked="true" || true` recorded revoked=true whenever the revoke
// command exited 0 — and curl exits 0 on HTTP 401/404/500, so a revoke that
// did not revoke was recorded as revoked. The corrected contract (p842) is:
// assert the revocation explicitly (HTTP 204 on DELETE .../installation/token)
// AND read the revocation state back before recording success.
//
// This package implements that contract as a fail-closed, pure function over
// the observable signals a revocation attempt leaves behind. It is the
// executable specification the estate delivery path must satisfy; the bool it
// returns is the only value a caller may record as `revoked=`.
package revoke

import "fmt"

// Result carries the observable signals a revocation attempt leaves behind.
//
// DeleteHTTPStatus is the HTTP status code of the DELETE .../installation/token
// call; 204 is GitHub's documented success code. ProbeRejected reports whether
// a read-back probe made AFTER the DELETE confirmed that the credential is
// rejected (true = the credential no longer authenticates). ProbeErr records a
// failure to run the read-back probe itself.
//
// A zero-value Result never verifies: every signal must be positively
// observed, so a caller that skips the read-back cannot accidentally record a
// revocation.
type Result struct {
	DeleteHTTPStatus int
	ProbeRejected    bool
	ProbeErr         error
}

// Revoked decides whether the revocation is verified to have taken effect.
// It fails closed on every ambiguity:
//
//   - a DELETE status other than 204 means the API did not revoke — 401, 404
//     and 500 included, the exact cases the exit-code-only check mis-recorded;
//   - a read-back probe that could not run cannot confirm the revocation;
//   - a read-back probe that did not confirm rejection (still authenticates,
//     or was never run) proves the revoke did not take effect, even after a
//     204.
//
// It returns the verdict and a human-readable reason. Callers record
// `revoked=<verdict>` — never the exit code of the revoke command.
func Revoked(r Result) (bool, string) {
	if r.DeleteHTTPStatus != 204 {
		return false, fmt.Sprintf(
			"DELETE returned HTTP %d, want 204 — token not revoked (the revoke command's exit code is not evidence)",
			r.DeleteHTTPStatus)
	}
	if r.ProbeErr != nil {
		return false, fmt.Sprintf(
			"read-back probe failed: %v — cannot confirm the revocation", r.ProbeErr)
	}
	if !r.ProbeRejected {
		return false,
			"read-back probe did not confirm the credential is rejected — the revoke did not take effect"
	}
	return true,
		"revocation verified: DELETE returned HTTP 204 and the read-back probe rejects the credential"
}
