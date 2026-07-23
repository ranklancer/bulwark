# Perf baselines — bulwark hot paths (a hardening tier)

Captured with `make bench` (`go test -bench=. -benchmem`). Snapshots are dated.

## How to read these numbers (scope)

- `BenchmarkGateEvaluate_*` (`internal/verify`) measure **gate-orchestration
  overhead** using the fake verifiers from `gate_test.go` — **not** real
  cosign/crypto signature verification, which is I/O- and crypto-bound and
  orders of magnitude larger. `_Disabled` is the short-circuit floor; do not
  read these as a signature-verification SLA.
- `BenchmarkParse` (`internal/registry`) — reference/digest string parse.
- `BenchmarkAssessUpgrade` (`internal/cve`) — closed-CVE urgency diff.

Re-capture with `make bench` when a hot path changes.

Fast-follow (not yet done): wire a `benchstat`-diff regression check into a
gate so these baselines cannot silently rot. Tracked against a hardening tier follow-up.
