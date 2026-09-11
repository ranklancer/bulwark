# Commit-identity check — defect record and fix

## What the check is for

`sanitization.yml`'s commit-identity step fails a push or pull request unless
every author and committer email is a GitHub noreply address. The intent is
that no commit in a public-bound repo is attributable to an unregistered or
personal identity.

## The class-H defect (fixed)

The original pattern was:

```
^noreply@github\.com$|@users\.noreply\.github\.com$
```

Two defects made it accept well-shaped but unprovisioned addresses:

1. **The second alternative was unanchored on the left.** `@users\.noreply\.github\.com$`
   matches any email that merely *ends* in the GitHub noreply domain, so
   `caradon-agent@users.noreply.github.com` and `attacker@users.noreply.github.com`
   both passed. Neither resolves to an account.
2. **It checked email only, never name.** GitHub's modern noreply form is
   `<numeric-id>+<username>@users.noreply.github.com`. The check did not require
   the numeric-id prefix or validate the username side, so a bare
   `<anything>@users.noreply.github.com` was accepted.

Live specimen (2026-09-06): `caradon-agent@users.noreply.github.com` (bad —
unprovisioned, no numeric-id prefix) versus
`325855022+caradon-harness@users.noreply.github.com` (good — provisioned
GitHub account). Nine of ten local commits once carried the bad address.

## The fix

`scripts/commit-identity-check.sh` now holds the check (the workflow calls it,
so the tested artifact is the shipped artifact):

```
^(noreply@github\.com|[0-9]+\+[A-Za-z0-9]([A-Za-z0-9]|-[A-Za-z0-9])*@users\.noreply\.github\.com)$
```

- Both alternatives are anchored.
- The modern alternative requires a numeric-id prefix (`[0-9]+\+`).
- The username side is validated: alphanumeric start and end, hyphens allowed
  inside but never doubled.
- The legacy generic `noreply@github.com` remains accepted (GitHub's own
  web-flow merge commits use it; main's history contains `GitHub
  <noreply@github.com>` committers).

## Negative test

`scripts/test-commit-identity.sh` (wired into `make gate` via the
`check-commit-identity` target, so it runs in `make gate-full`) asserts that:

- the provisioned fixtures are accepted
  (`325855022+caradon-harness@users.noreply.github.com`,
  `43620530+ranklancer@users.noreply.github.com`, `noreply@github.com`);
- the class-H specimen `caradon-agent@users.noreply.github.com` is **rejected**,
  along with `attacker@users.noreply.github.com`,
  `attacker+caradon-harness@users.noreply.github.com`, and
  `325855022+@users.noreply.github.com`.

If the defect is reintroduced (the old unanchored pattern restored), the
reject-expectations fail and `make gate-full` goes red.

## Companion change

`scripts/check-pii.sh` (blocking `pii-scan` job in `ci.yml`) now allows
`@users.noreply.github.com` addresses alongside its existing `noreply@`
allowance. This is required because the negative-test fixtures are literal
`@users.noreply.github.com` addresses; GitHub noreply addresses are
pseudonymous by design, not personal PII, so the scanner's purpose (keep
personal emails out of a public repo) is unaffected.
