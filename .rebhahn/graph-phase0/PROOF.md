# Graph Engineering Phase-0 — build/push idempotency proof marker

This file is the trivial artifact produced by the `build` node of the
Phase-0 dev-loop graph (internal engineering notes). Its git object hash is the
`artifact_hash` recorded in the DevLoopUnit state record. The `push`
node publishes it to origin and records `remote_sha`.

unit: bulwark#P0-proof
lane: mechanical(T0)
classification: internal, shape-only, PII-free
