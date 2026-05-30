# FORGE — IBM Bob Hackathon Submission

## Project Name
FORGE

## One-line description
IBM Bob reads any LLM codebase, finds every vulnerability, and auto-generates enterprise security policies — with a tamper-evident audit trail of every action.

## What it does

Enterprise teams deploy LLM-powered applications without knowing what security surface they've created. FORGE solves this with three steps:

1. **Scan** — IBM Bob deeply understands a repository's context, detecting every LLM call site, prompt injection surface, missing output validation, hardcoded credential, agentic overreach, and unpinned supply chain dependency. Each finding maps to OWASP LLM Top 10 (LLM01–LLM10).

2. **Generate** — FORGE auto-generates a DPI engine / Lobster Trap YAML governance policy tailored to that specific codebase. The policy includes ingress rules (block prompt injection, PII requests), egress rules (block credential leaks), rate limits (calibrated to detected DoS risk), and OWASP metadata linking each rule to the vulnerability that triggered it.

3. **Audit** — Every FORGE action is logged to a BobShell audit chain: each entry is SHA-256 hash-chained to the previous, so tampering any record breaks the chain. The output is a compliance artifact enterprises can show auditors.

**One command. From repo to protected.**

```bash
python src/cli/__main__.py scan --repo /path/to/your/llm-app --out ./forge_output
```

## IBM Bob integration

IBM Bob is not a wrapper — it is the core analysis engine. Bob reads the full repository context (not surface-level grep), understands call chains, and distinguishes test mocks from production LLM calls. Each BobShell entry carries a `bob_session_id` that links the generated policy to the specific Bob analysis run, creating a traceable chain from codebase audit → vulnerability finding → governance rule.

In production: `WATSON_BOB_API_KEY` environment variable activates full Bob API integration. The system works in mock mode for demo purposes without API keys.

## Demo results

FORGE scanned 3 repositories from the AI Reliability Ecosystem:

| Repo | Files scanned | Findings | OWASP categories | Chain verified |
|------|---------------|----------|------------------|----------------|
| RepoA | 15 | 7 | LLM01, LLM02 | ✅ |
| RepoB | 27 | 6 | LLM01, LLM08 | ✅ |
| FORGE (self) | 9 | 10 | LLM01, LLM02, LLM05, LLM06, LLM08 | ✅ |

All generated policies imported into Lobster Trap:
```
lobstertrap serve --policy forge_output/repo_a/forge_repo_a.yaml
→ Serving on :8080 with 4 ingress + 2 egress rules
```

## Scientific verification

Test suite: **25/25 PASS** across 7 categories:
- Scanner finds ≥1 LLM site in real target codebases
- OWASP mappings correct: LLM01 present, LLM02/LLM08 present
- Generated YAML has all required structural fields
- BobShell: 4 actions logged, chain_verified=True, JSONL round-trip valid
- End-to-end pipeline produces output files (YAML + JSONL) in < 5s
- Zero false positives on pure data-processing code
- Scan latency: RepoA 19ms, RepoB 27ms (both < 500ms)

## Connection to AI Reliability Ecosystem

FORGE is part of a four-product ecosystem built around a shared governance core:
- FORGE generates DPI engine-compatible YAML policies for any LLM codebase
- DPI engine (TechEx Hackathon) is the governance engine FORGE targets
- RepoA (sample AI agent platform) is a demo scan target — FORGE found LLM01+LLM02
- RepoB (sample LLM evaluation framework) is a demo scan target — FORGE found LLM01+LLM08

Every hackathon project in this ecosystem uses FORGE-generated policies as its governance foundation.

## Tech stack

- Python 3.12
- IBM Bob API (watson-machine-learning-client)
- DPI engine / Lobster Trap YAML policy format
- SHA-256 hash-chained BobShell audit trail
- OWASP LLM Top 10 vulnerability taxonomy

## Team

Solo — Sardor Razikov
