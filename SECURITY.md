# Security Policy

Bulwark is a supply-chain security tool for container updates, so the security
of Bulwark itself is treated as a first-class concern.

## Supported versions

Bulwark is pre-1.0 and ships from `main`. Security fixes are applied to `main`
and the latest tagged release. Operators should track the latest release and
pin to an immutable image digest in production.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public
issue, pull request, or discussion for a security report.

Use GitHub's private vulnerability reporting for this repository:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability** (Private vulnerability reporting).
3. Provide the details below.

This channel is private to the maintainers and keeps the report out of public
view until a fix is available.

Please include, where possible:

- affected component, version, or commit;
- a description of the issue and its security impact;
- reproduction steps or a proof of concept;
- any known mitigations or workarounds.

## Response targets

These are good-faith targets, not contractual guarantees:

| Stage | Target |
|---|---|
| Acknowledge receipt | within 3 business days |
| Initial assessment / triage | within 7 business days |
| Fix or mitigation plan for a confirmed issue | within 30 days, severity-dependent |

Critical, actively-exploited issues are handled with priority over these
windows. We will keep you informed of progress and coordinate disclosure
timing with you.

## Coordinated disclosure & safe harbor

We follow coordinated disclosure: please give us a reasonable opportunity to
release a fix before any public disclosure. We will credit reporters who wish
to be acknowledged.

Good-faith security research conducted in accordance with this policy is
welcome. We will not pursue or support action against researchers who:

- make a good-faith effort to avoid privacy violations, data destruction, and
  service interruption;
- only interact with systems and data they own or are authorized to test;
- report promptly and give us reasonable time to remediate before disclosure;
- do not exfiltrate more data than necessary to demonstrate the issue.

Activity that violates other laws, or that harms users or third-party systems,
is outside the scope of this safe harbor.

## Scope

In scope: the Bulwark source in this repository and the images published from
it. Out of scope: third-party dependencies (report those upstream), and issues
requiring privileged local access that Bulwark does not itself grant.
