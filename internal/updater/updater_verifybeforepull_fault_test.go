package updater

// a hardening tier: verify-before-pull fault injection (bulwark pre-public hardening
// backlog an internal audit).
//
// These tests prove that Updater.ApplyWithOptions' verify-before-pull gate
// (updater.go, the verify-before-pull design, ~lines 210-247) fails CLOSED -- no pull, no container
// mutation -- when the things it depends on go wrong mid-flow, not just when
// they are absent:
//
//   - the configured Verifier's underlying dependency (e.g. a registry/cosign
//     lookup) returns an error, distinct from the already-pinned nil-Verify
//     "feature disabled" case;
//   - a Verifier is wired (u.Verify != nil) but ITS OWN internal signature
//     sub-verifier is nil/unconfigured, exercised end-to-end through
//     ApplyWithOptions rather than in isolation against verify.Gate.Evaluate;
//   - the target reference fails the digest-pinning precondition in various
//     malformed ways (empty/short/non-hex/missing-prefix digest) -- the closest
//     analogue this codebase has to a "resolver returned no usable digest",
//     since verify-before-pull refuses to attest a mutable/unpinned target.
//
// Each assertion below would fail if the corresponding gate were made
// fail-OPEN: a pull recorded, a container created, or a nil error returned.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/internal/docker"
	"github.com/ranklancer/bulwark/internal/verify"
)

// countingVerifier records how many times Evaluate was invoked and returns a
// fixed decision. Used to prove a fail-closed-before-verify precondition
// (e.g. an unpinned/malformed digest) never even reaches the trust gate.
type countingVerifier struct {
	calls    int
	decision verify.Decision
}

func (c *countingVerifier) Evaluate(_ context.Context, _ verify.Input) verify.Verdict {
	c.calls++
	return verify.Verdict{Decision: c.decision}
}

// noMutationOps asserts the fake Docker client observed nothing but the
// initial InspectContainer call -- i.e. no stop/rename/create/start/remove
// side effect occurred. Verify-before-pull sits after inspect (the updater
// needs OldImage for the pre-update hook context) but before every
// side-effecting step, so a correctly fail-closed gate must leave ops at
// exactly one entry.
func noMutationOps(t *testing.T, ops []string, wantInspectID string) {
	t.Helper()
	if len(ops) != 1 || ops[0] != "inspect:"+wantInspectID {
		t.Fatalf("verify-before-pull block must produce NO side effects beyond the initial inspect; ops=%v", ops)
	}
}

// --- resolver/dependency error inside the verify gate -----------------------

// TestVerifyBeforePull_SignatureDependencyError_FailsClosedNoPull wires a real
// verify.Gate (not the canned fakeVerifier used elsewhere in this package) whose
// signature axis fails not because the image is untrusted, but because the
// underlying dependency the signature verifier relies on (a registry/transparency
// -log fetch, in production) errored out. This is the fault this codebase can
// inject that is closest to "the resolver/registry step between verify and pull
// fails": the axis is Evaluated but unable to answer, exactly the "unknown"
// state gate.go's own fail-closed contract documents.
//
// A mutant that treated an unknown/errored axis as a pass (fail-open) would
// let this pull the image; this test would then fail on the pull-count and
// ops assertions.
func TestVerifyBeforePull_SignatureDependencyError_FailsClosedNoPull(t *testing.T) {
	fd := &fakeDocker{containers: map[string]*docker.ContainerInspect{
		"old-id": sampleInspect("old-id", "sonarr", "lscr.io/linuxserver/sonarr:4.0.10-ls45"),
	}}
	sig := &verify.FakeSignatureVerifier{
		Result: verify.SignatureResult{
			Err: errors.New("registry: fetch manifest: connection refused"),
		},
	}
	gate := verify.Gate{
		Policy: verify.Policy{
			Enabled:   true,
			Signature: verify.SignaturePolicy{Mode: verify.ModeBlock},
		},
		Signature: sig,
	}
	u := &Updater{Docker: fd, Verify: gate}

	res := u.ApplyWithOptions(context.Background(), "old-id", pinnedTarget, ApplyOptions{})

	if !res.VerifyBlocked || res.Err == nil {
		t.Fatalf("a signature dependency error must block the update fail-closed: VerifyBlocked=%v err=%v", res.VerifyBlocked, res.Err)
	}
	if res.VerifyDecision != verify.DecisionBlock {
		t.Fatalf("VerifyDecision=%q, want block", res.VerifyDecision)
	}
	if len(fd.pulls) != 0 {
		t.Fatalf("a blocked verify-before-pull gate must never pull; pulls=%v", fd.pulls)
	}
	if len(fd.created) != 0 {
		t.Fatalf("a blocked verify-before-pull gate must never create a replacement container; created=%v", fd.created)
	}
	if len(sig.Calls) != 1 {
		t.Fatalf("the signature verifier should have been consulted exactly once; calls=%v", sig.Calls)
	}
	noMutationOps(t, fd.ops, "old-id")
}

// TestVerifyBeforePull_NilSignatureSubVerifier_FailsClosedEndToEnd mirrors
// verify.TestEvaluate_NilVerifier_FailsClosed, but exercises it through the
// FULL Updater.ApplyWithOptions path rather than calling Gate.Evaluate in
// isolation. u.Verify is non-nil (the operator DID configure verification --
// this is not the "feature disabled" path); it is the Gate's own internal
// Signature dependency that is unconfigured. This is a distinct, genuine
// defense-in-depth property from "nil Verifier disables verify-before-pull
// entirely": here the gate is active and must still refuse to pull when it
// cannot complete a block-mode axis.
func TestVerifyBeforePull_NilSignatureSubVerifier_FailsClosedEndToEnd(t *testing.T) {
	fd := &fakeDocker{containers: map[string]*docker.ContainerInspect{
		"old-id": sampleInspect("old-id", "sonarr", "lscr.io/linuxserver/sonarr:4.0.10-ls45"),
	}}
	gate := verify.Gate{
		Policy: verify.Policy{
			Enabled:   true,
			Signature: verify.SignaturePolicy{Mode: verify.ModeBlock},
		},
		Signature: nil, // unconfigured sub-dependency, NOT a nil Updater.Verify
	}
	u := &Updater{Docker: fd, Verify: gate}

	res := u.ApplyWithOptions(context.Background(), "old-id", pinnedTarget, ApplyOptions{})

	if !res.VerifyBlocked || res.Err == nil {
		t.Fatalf("an unconfigured signature sub-verifier in block mode must fail closed end-to-end: VerifyBlocked=%v err=%v", res.VerifyBlocked, res.Err)
	}
	if res.VerifyDecision != verify.DecisionBlock {
		t.Fatalf("VerifyDecision=%q, want block", res.VerifyDecision)
	}
	if len(fd.pulls) != 0 {
		t.Fatalf("fail-closed on an unconfigured axis must never pull; pulls=%v", fd.pulls)
	}
	if len(fd.created) != 0 {
		t.Fatalf("fail-closed on an unconfigured axis must never create a replacement container; created=%v", fd.created)
	}
	noMutationOps(t, fd.ops, "old-id")
}

// --- missing/malformed digest: fail closed before the gate is even asked ----

// TestVerifyBeforePull_MalformedDigest_FailsClosedBeforeVerify covers targets
// that carry an "@" separator (so they are not plainly "an unpinned tag") but
// whose digest payload is empty, truncated, non-hex, or missing its algorithm
// prefix. verify-before-pull can only attest a canonical digest-bound
// reference; every one of these must be refused BEFORE the configured
// Verifier is ever consulted (a resolver/registry step that "succeeded" with
// no usable digest must not be allowed to reach pull), and certainly before
// any pull happens.
func TestVerifyBeforePull_MalformedDigest_FailsClosedBeforeVerify(t *testing.T) {
	cases := []struct {
		name string
		ref  string
	}{
		{"empty_digest_after_at", "lscr.io/linuxserver/sonarr@"},
		{"truncated_hex_63_chars", "lscr.io/linuxserver/sonarr@sha256:" + strings.Repeat("a", 63)},
		{"non_hex_characters", "lscr.io/linuxserver/sonarr@sha256:" + strings.Repeat("z", 64)},
		{"missing_sha256_prefix", "lscr.io/linuxserver/sonarr@" + strings.Repeat("a", 64)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fd := &fakeDocker{containers: map[string]*docker.ContainerInspect{
				"old-id": sampleInspect("old-id", "sonarr", "lscr.io/linuxserver/sonarr:4.0.10-ls45"),
			}}
			cv := &countingVerifier{decision: verify.DecisionAllow}
			u := &Updater{Docker: fd, Verify: cv}

			res := u.ApplyWithOptions(context.Background(), "old-id", tc.ref, ApplyOptions{})

			if !res.VerifyBlocked || res.Err == nil {
				t.Fatalf("%s: a malformed/missing digest must fail closed: VerifyBlocked=%v err=%v", tc.name, res.VerifyBlocked, res.Err)
			}
			if !strings.Contains(res.Err.Error(), "not digest-pinned") {
				t.Fatalf("%s: expected a not-digest-pinned error, got %v", tc.name, res.Err)
			}
			if cv.calls != 0 {
				t.Fatalf("%s: the trust gate must never be consulted for an unpinned/malformed target; calls=%d", tc.name, cv.calls)
			}
			if len(fd.pulls) != 0 {
				t.Fatalf("%s: a fail-closed digest precondition must never pull; pulls=%v", tc.name, fd.pulls)
			}
			if len(fd.created) != 0 {
				t.Fatalf("%s: a fail-closed digest precondition must never create a replacement container; created=%v", tc.name, fd.created)
			}
			noMutationOps(t, fd.ops, "old-id")
		})
	}
}
