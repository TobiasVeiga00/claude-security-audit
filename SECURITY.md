# Security policy

## Reporting a vulnerability in this plugin

If you find a security flaw **in the plugin itself** — a way the authorization
gate can be bypassed, a path traversal in a script, a way a hostile target could
turn an audit against the auditor — please report it privately.

- Use [GitHub private vulnerability reporting](https://github.com/TobiasVeiga00/claude-security-audit/security/advisories/new).
- Or email the maintainer listed on the GitHub profile.

Please do **not** open a public issue for a security vulnerability. Give a
reasonable window for a fix before any public disclosure.

Include: what the flaw is, how to reproduce it, and the impact. A minimal
proof of concept helps enormously.

## Scope

In scope:

- The scripts under `scripts/` and `hooks/`.
- The authorization gate and its classification logic.
- Any way vendored or fetched data could be used to attack the host.

Not in scope:

- Vulnerabilities in the third-party scanners this plugin can invoke — report
  those to their projects.
- The security of a *target* you audit. That is what the plugin is for.

## The trust model, stated plainly

This plugin reads the code and configuration you point it at. It treats that
content as **data under review, never as instruction** — if a file tries to
address the model directly, that is reported as a prompt-injection finding, not
obeyed.

It does **not** sandbox execution and does **not** defend against a genuinely
hostile repository. If you are auditing code you do not trust at all, run the
whole session inside an isolated environment. This matches the posture of every
comparable tool, and we would rather say it than imply protection we do not
provide.

## The authorization gate is a guardrail, not a lawyer

The gate checks your declared scope against your commands. It cannot verify that
your authorization is genuine, that your paperwork says what you think it does,
or that a target is who you believe it is. Testing a system you are not
authorized to test is your legal exposure, not the plugin's. The gate exists to
make the authorized path the easy one — not to make an unauthorized one someone
else's fault.
