---
name: llm
description: Security review of LLM and agentic applications against the OWASP GenAI Top 10 2026 and the Agentic Top 10 — prompt injection, excessive agency, tool misuse, insecure output handling, sensitive-information disclosure and supply-chain risk. Use for "audit my AI agent", "prompt injection review", "LLM security", "is my agent safe", "check my RAG pipeline".
argument-hint: "[path]"
allowed-tools: Read, Glob, Grep, Write, Bash(node:*), Bash(git:*)
---

# LLM and agentic application security

Anchored to **OWASP Top 10 for LLM Applications 2026** and **OWASP Top 10 for
Agentic Applications 2026**. Codes are in
`${CLAUDE_PLUGIN_ROOT}/references/frameworks.md`.

This is a young field where the classic web instincts mislead. The core shift:
the model's context window is a **trust boundary you cannot fully police**, and
anything the model can *do* — tools, retrieval, code execution — is reachable by
whoever can get text into that window.

## Surface

!`node "${CLAUDE_PLUGIN_ROOT}/scripts/surface.mjs" ${1:-.} --budget 150000 --domain llm --summary`

---

## First, map the data and authority flow

Before hunting, draw two things. Everything else follows from them.

1. **Where does untrusted text enter the context?** Direct user input, retrieved
   documents (RAG), tool results, other agents, file contents, web pages, email.
   Each is an injection vector; retrieved and tool-sourced text is the one people
   forget.
2. **What can the model cause to happen?** Every tool, function, API call, code
   execution, database write and outbound message. This is its *agency*, and it
   is the blast radius of a successful injection.

A prompt-injection finding is only as severe as the authority reachable from it.
Injection into a model that can only produce text is low. Injection into a model
that can call `send_email`, `execute_sql` or `run_shell` is critical.

## LLM01 — Prompt injection

- **Direct:** user input overriding system instructions.
- **Indirect:** the dangerous one. Malicious instructions inside content the
  model ingests — a RAG document, a scraped page, a tool's JSON response, a
  filename. The user never sees it; the model obeys it.
- Look for: system and user content concatenated without a trust boundary;
  retrieved content inserted without delimiting or provenance; tool output fed
  back verbatim; no output-side check on what the model then does.
- The honest finding: input-side filtering **cannot** fully prevent this. The
  real control is limiting authority (LLM03) and validating output (LLM10), so
  assess those before claiming injection is "mitigated".

## LLM02 — Sensitive information disclosure

System prompt content, secrets embedded in prompts, training or fine-tuning data
leakage, other users' data reachable through shared context or a poorly scoped
retrieval index. Check what the model *can* retrieve, not just what it is meant
to.

## LLM03 — Excessive agency

Promoted in 2026, and usually the most important finding. Does the model have
tools it does not need? Can it act without a human in the loop on
irreversible or high-impact operations? Is each tool scoped to least privilege,
or does one `run_query` tool have full database rights? The fix is architectural:
remove tools, narrow scopes, gate consequential actions on confirmation.

## LLM04 — Supply chain

Model provenance, unverified model weights, poisoned or typosquatted model and
dataset packages, compromised inference dependencies. Route the package side to
`/security-audit:deps`.

## LLM05 — Data and model poisoning

Can an attacker influence training, fine-tuning or the RAG index? An
open-submission knowledge base that feeds retrieval is a poisoning vector.

## LLM06 — Unbounded consumption

No token or rate limits, unbounded output, recursive agent loops with no budget,
"denial of wallet" where each request is expensive. For an agent, check the
loop-termination and cost-ceiling logic specifically.

## LLM07 — Misinformation

Over-reliance on unverified output for consequential decisions; no grounding, no
citation, no human check where correctness matters.

## LLM08 — Hidden context exposure

New in 2026 (it broadens the retired "system prompt leakage"). Instructions,
tool definitions, or context the developer assumed were hidden but are
recoverable, and whose exposure reveals attackable structure.

## LLM09 — Vector and embedding weaknesses

Embedding inversion recovering source text, cross-tenant retrieval from a shared
index, and injection through the embedding pipeline.

## LLM10 — Improper output handling

The model's output treated as trusted downstream: rendered as HTML (XSS), passed
to `eval` or a shell (RCE), used to build SQL (injection), or followed as a
command without validation. **This is where injection becomes code execution**,
so trace every path from model output into a sink — exactly as you would trace
user input in `/security-audit:code`.

## Agentic applications (ASI01–ASI10)

If the system has autonomous agents, add the agentic lens:

- **ASI01 Goal hijack / ASI06 memory poisoning** — persistent state or memory an
  attacker can write to, that later steers behaviour.
- **ASI02 Tool misuse** — tools invoked with attacker-influenced arguments.
- **ASI03 Identity and privilege abuse** — the agent acting with more authority
  than the user it acts for; confused-deputy patterns.
- **ASI05 Unexpected code execution** — the agent's own code paths reachable
  through crafted input.
- **ASI07 Insecure inter-agent communication** — trust between agents with no
  authentication or validation.
- **ASI10 Rogue agents** — no oversight, no kill switch, no bounded autonomy.

## Recording

`domain: "llm"`, tag `owasp` with the `LLM0n` or `ASI0n` code. State the
reachable authority in the impact — a prompt-injection finding without its blast
radius is only half a finding.
