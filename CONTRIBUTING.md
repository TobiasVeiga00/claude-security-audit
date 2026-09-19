# Contributing

Thanks for helping make this the best security-audit plugin for Claude Code.
This document is short on purpose; the standards it points to are where the
detail lives.

## Ground rules

- **Everything under `scripts/` stays zero-dependency.** Node ≥ 18 built-ins
  only. A `dependencies` block in `package.json` fails CI. This is what lets the
  plugin run identically on Windows and POSIX without an install step.
- **Deterministic in, deterministic out.** The same input must produce
  byte-identical output. It is what makes the intel refresh diffable and the
  reports reviewable.
- **Cross-platform.** Never shell out for something Node can do. Use forward
  slashes in config, and the exec form (`command` + `args`) in hooks, never a
  quoted shell string.
- **Tests are not optional.** Every behavioural change ships with a test. Run
  `node --test "tests/**/*.test.mjs"` before you open a pull request.

## The methodology is the product

If your change touches how findings are raised, read
[`references/methodology.md`](references/methodology.md) and
[`references/false-positives.md`](references/false-positives.md) first. The single
most valuable contribution to this project is **fewer false positives**, not more
detections. A rule that fires on safe code makes the whole report less trusted.

When you add or change a detection signal in `scripts/lib/signals.mjs`:

- It must be **high recall, low precision by design** — its job is "look here",
  never "this is a bug". Confirmation is the model's job.
- Add a fixture to `tests/fixtures/` that it should catch, and confirm it does.
- Add a *safe* counterexample it must **not** flag, if the pattern is prone to
  false positives.

## Keeping the framework data current

Framework editions move. If you notice one has shifted (a new OWASP Top 10, a new
ATT&CK version, a new CWE Top 25), update:

- `references/frameworks.md` — the human reference.
- `scripts/intel-sync.mjs` — the pinned ranks or versions, if hard-coded.

Cite the official source and its publication date in the pull request. Accuracy
on versions matters more than anything else in this repository — a confidently
wrong severity is worse than no answer.

## Adding a scanner importer

`scripts/lib/importers.mjs` turns scanner output into canonical findings. To add
one:

1. Write a `fromYourTool(data, root)` that returns finding objects.
2. Be defensive — scanner schemas change between releases; a missing field must
   degrade the finding, never throw.
3. Register it in `SUPPORTED_IMPORTERS` and the `switch`.
4. Add a fixture of real (redacted) output and a test.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/). The type drives
releases automatically:

- `feat:` → minor release · `fix:` → patch release · `feat!:` → major.
- `chore:`, `docs:`, `test:`, `refactor:` → no release.
- `chore(data):` is reserved for the automated intelligence refresh — do not use
  it by hand.

## Security tooling stays honest

This is a security tool; it must not become a liability:

- No detection may execute target code, exfiltrate data, or reach the network
  without going through the authorization gate.
- Never weaken the gate to make a workflow smoother. If it blocks something it
  should not, fix the classification, not the gate.
- Dual-use is fine; the intent and the authorization model must be clear.

## Reporting a vulnerability in the plugin itself

See [SECURITY.md](SECURITY.md). Please do not open a public issue for a security
flaw in the plugin.

## Pull request checklist

- [ ] `node --test "tests/**/*.test.mjs"` passes.
- [ ] `claude plugin validate . --strict` passes.
- [ ] New behaviour has a test; new signals have a fixture and a counterexample.
- [ ] No runtime dependencies were added.
- [ ] Framework or data changes cite an official source and date.
- [ ] The commit message follows Conventional Commits.
