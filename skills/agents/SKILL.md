---
name: agents
description: Agent supply-chain security — audit the MCP servers, plugins, skills, hooks and instruction files a coding agent loads and trusts. Detects tool poisoning, prompt injection in tool/skill descriptions, unpinned or remote MCP servers, secrets in agent config, download-and-execute hooks, and excessive tool permissions. Use for "audit my MCP servers", "is this skill safe to install", "check my agent config", "MCP security", "tool poisoning", "agent supply chain".
argument-hint: "[path]"
allowed-tools: Read, Glob, Grep, Write, Bash(node:*), Bash(git:*)
---

# Agent supply-chain security

The fastest-growing attack surface in 2026 is not the application — it is the
**agent itself**. An MCP server, a plugin, a skill, a hook or an instruction file
runs with the agent's full authority: it can read your code, run commands, and
reach the network. A poisoned tool description, an unpinned server, or a hook
that pipes a remote script into a shell compromises the developer, not the app.

Anchored to the **OWASP Agentic Top 10** and **MITRE ATLAS**. This audits the
*agent's own supply chain* — complementary to `/security-audit:llm`, which audits
the agentic risk of the *application under review*.

## Surface

!`node "${CLAUDE_PLUGIN_ROOT}/scripts/agentscan.mjs" $ARGUMENTS --summary`

The scan discovers every agent-config file under the target — `.mcp.json`,
`.claude/settings.json`, `.claude-plugin/*`, `hooks/hooks.json`, `SKILL.md`,
agent prompts, `CLAUDE.md`/`AGENTS.md`/`.cursorrules` — and flags the risks
below with a line and an excerpt. Start from those; each is a *candidate*, not a
finding, until you read the config and confirm it.

---

## What to hunt

**Tool poisoning and prompt injection (LLM01, ATLAS AML.T0051).** Instructions
hidden in a tool description, a skill body, an agent prompt or `CLAUDE.md` that
hijack the agent — an override of its earlier guidance, a request to surface its
own hidden configuration, a directive to act while keeping the operator in the
dark, or zero-width / bidirectional characters concealing text. `agentscan` flags
these; read the surrounding context and judge whether it changes the agent's
behaviour.

**MCP trust boundary.** A **remote** MCP server (`url:` over http/ws) sends your
prompts and tool results to a third party — a data-egress boundary that needs a
reason. Confirm who operates the endpoint and what it receives.

**Mutable supply chain.** An MCP server launched with `npx`/`uvx`/`bunx` and an
**unpinned** package (or `@latest`) runs whatever the registry serves today —
the classic rug-pull vector. Pin to a version, or vendor it.

**Arbitrary execution.** A server whose `command` is a shell (`bash -c`), or that
fetches code from a URL, or a **hook** that runs `curl … | sh` on a tool event,
is remote code execution with the agent's rights. These are high severity by
default; the only question is whether the source is trusted.

**Secrets in config.** A long-lived credential sitting as a literal in an MCP
`env` or `headers` block leaks with the config. It belongs in an environment
reference (`${VAR}`), not the file. **Redact to first-four/last-two when you
record it** — never echo the value.

**Excessive agency / least privilege.** A skill, agent or hook granting
unrestricted tools (bare `Bash`, `Bash(*)`, `*`) can do far more than its stated
job. Note the gap between the permission and the purpose.

## Confirming a candidate

For each flagged risk, the bar is the same as everywhere in this plugin: name the
actor, the input, the missing control, the crossing and the concrete result. A
remote MCP server is not automatically a finding — a first-party one you operate
is fine. A pinned `npx` package is not unpinned. Read the config, not just the
excerpt.

## Recording

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/finding.mjs" add --file candidates.json
```

Set `domain: "agents"`, put the config file in `location.file` and the server or
skill name in `location.symbol`, tag `owasp` with the **Agentic Top 10** code,
and give a remediation that names the exact change — pin this version, move this
secret to `${VAR}`, remove this instruction, restrict this tool grant. Never
print a live credential; redact it.
