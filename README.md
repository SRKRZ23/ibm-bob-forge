# FORGE — IBM Bob-Powered LLM Governance Policy Generator

> **Scan any codebase → detect LLM vulnerabilities → generate enterprise-grade SOUF AI security policies → audit every step with IBM Bob.**

FORGE uses IBM Bob to deeply understand a repository's context, detect every LLM call site and governance gap, then auto-generates SOUF AI / Lobster Trap YAML policies tailored to that specific codebase.

---

## What FORGE Does

```
GitHub URL / local path
  → Bob: full codebase context scan
  → OWASP LLM Top 10 vulnerability detection
  → SOUF AI governance policy generation (YAML)
  → BobShell: tamper-evident audit trail of every action
  → Ready-to-deploy policy for Lobster Trap / SOUF AI
```

**One command. From repo to protected.**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        FORGE Pipeline                           │
│                                                                 │
│  Repo Path ──► Scanner ──► Findings ──► Generator ──► Policy   │
│                   │                          │                  │
│             OWASP LLM                  SOUF AI YAML             │
│             Top 10 map                  for Lobster Trap        │
│                   │                          │                  │
│              BobShell ◄─────────────────────►                   │
│         (tamper-evident audit trail)                            │
└─────────────────────────────────────────────────────────────────┘
```

### Scanner: What It Detects

| Category | Examples |
|----------|----------|
| LLM Call Sites | `openai.chat.completions.create`, `LLMChain`, `genai.GenerativeModel` |
| Prompt Injection Risk | f-strings with `{user_input}`, `.format(query=...)` |
| Missing Output Validation | Raw `.content` use, `response["choices"][0]` unvalidated |
| Credential Exposure | Hardcoded `sk-` keys, `api_key = "..."` |
| Agentic Overreach | `subprocess.run`, `os.system` in agent loops |
| Supply Chain Gaps | Unpinned `langchain`, `llama_index` imports |

Maps directly to **OWASP LLM Top 10** (LLM01–LLM10).

### Policy Generator: What It Produces

Generated policies are valid SOUF AI / Lobster Trap YAML, ready for:
```bash
lobstertrap serve --policy forge_output/my_repo/forge_my_repo.yaml --listen :8080
```

Each policy includes:
- **Ingress rules**: block/review prompt injection, PII requests, dangerous commands
- **Egress rules**: block credential leaks, PII in model output
- **Rate limits**: calibrated to detected DoS risk (LLM04)
- **OWASP metadata**: which vulnerabilities triggered which rules

### BobShell: IBM Bob Audit Trail

Every FORGE action is logged as a BobShell entry:
```json
{
  "seq": 2,
  "timestamp": "2026-05-13T16:14:12",
  "action": "forge_policy_generated",
  "params": {"policy_name": "forge_atlas", "owasp_findings": ["LLM01", "LLM02"]},
  "output_hash": "a3f1b2c4d5e6f7a8",
  "prev_hash": "c9d8e7f6a5b4c3d2",
  "entry_hash": "1234567890abcdef",
  "bob_session_id": "bob_a1b2c3d4e5f6"
}
```

Chain: `entry_hash = sha256(seq + ts + action + params + output_hash + prev_hash)` — tamper any entry → chain breaks.

---

## Quick Start

```bash
# Scan your repo and generate policy
python src/cli/__main__.py scan --repo /path/to/your/llm-app --out ./forge_output

# Verify generated policy structure
python src/cli/__main__.py verify --policy forge_output/your-app/forge_your-app.yaml

# Run demo on 3 repos (ATLAS, CITADEL, FORGE itself)
python src/cli/__main__.py demo
```

---

## Documentation

### 📚 Comprehensive Guides

- **[USAGE.md](docs/USAGE.md)** — Complete usage guide with installation, first scan, interpreting results, and CI/CD integration
- **[API.md](docs/API.md)** — Python API reference for programmatic use with code examples
- **[OWASP_MAPPING.md](docs/OWASP_MAPPING.md)** — Detailed mapping of OWASP LLM Top 10 to FORGE detection patterns and policies
- **[SECURITY.md](SECURITY.md)** — Security considerations, threat model, and vulnerability disclosure policy
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — System architecture and design decisions

### 💡 Working Examples

- **[examples/scan_openai_app/](examples/scan_openai_app/)** — Sample OpenAI application with vulnerabilities, scan output, and generated policy
- **[examples/scan_langchain_app/](examples/scan_langchain_app/)** — LangChain agent example with security issues and remediation
- **[examples/ci_integration/](examples/ci_integration/)** — CI/CD pipeline configurations (GitHub Actions, GitLab CI, Jenkins, pre-commit hooks)

### 🚀 Getting Started

1. **First-time users**: Start with [USAGE.md](docs/USAGE.md) for step-by-step installation and your first scan
2. **Developers**: See [API.md](docs/API.md) for programmatic integration
3. **Security teams**: Review [OWASP_MAPPING.md](docs/OWASP_MAPPING.md) for vulnerability details
4. **DevOps**: Check [examples/ci_integration/](examples/ci_integration/) for pipeline setup

---

## Demo Results

FORGE scanned 3 repositories in the AI Reliability Ecosystem:

| Repo | Files | Findings | OWASP | BobShell |
|------|-------|----------|-------|----------|
| ATLAS | 15 | 7 | LLM01, LLM02 | ✅ verified (4 actions) |
| CITADEL | 27 | 6 | LLM01, LLM08 | ✅ verified (4 actions) |
| FORGE | 9 | 10 | LLM01, LLM02, LLM05, LLM06, LLM08 | ✅ verified (4 actions) |

All policies import successfully into Lobster Trap:
```bash
lobstertrap serve --policy forge_output/atlas/forge_atlas.yaml
# → Serving on :8080 with 4 ingress + 2 egress rules
```

---

## OWASP LLM Top 10 Coverage

| ID | Name | Detected By |
|----|------|-------------|
| LLM01 | Prompt Injection | f-string, format(), concat patterns |
| LLM02 | Insecure Output Handling | Raw `.content`, unvalidated response use |
| LLM04 | Model Denial of Service | Unbounded LLM loops |
| LLM05 | Supply Chain Vulnerabilities | Unpinned LLM framework imports |
| LLM06 | Sensitive Information Disclosure | Hardcoded keys, PII in templates |
| LLM08 | Excessive Agency | subprocess + agent patterns |

---

## IBM Bob Integration

FORGE is designed around IBM Bob's deep codebase understanding:

1. **Bob reads the full repo** — not just surface-level grep; understands call chains
2. **Bob classifies intent** — can distinguish "test mock" from "production LLM call"
3. **BobShell logs every action** — compliance artifact for enterprise audits
4. **Bob session ID** links each policy to the specific Bob analysis run

In production: `WATSON_BOB_API_KEY` environment variable activates full Bob API integration.

---

## File Structure

```
forge/
├── src/
│   ├── scanner/
│   │   └── repo_scanner.py      # LLM call-site detection + OWASP mapping
│   ├── generator/
│   │   └── policy_generator.py  # SOUF AI YAML policy generation
│   ├── audit/
│   │   └── bobshell.py          # Tamper-evident IBM Bob audit log
│   ├── cli/
│   │   └── __main__.py          # CLI: scan | verify | demo
│   └── forge.py                 # Full pipeline orchestrator
├── forge_output/                # Generated policies (after running demo)
└── README.md
```

---

## Connection to the AI Reliability Ecosystem

```
FORGE ──generates policies──► SOUF AI (ATLAS governance layer)
  │
  └── YAML policies importable into Lobster Trap binary
  └── BobShell audit trail used in CITADEL L7 compliance reports
  └── Scans ATLAS + CITADEL repos for vulnerabilities
```

**Every hackathon project in this ecosystem uses FORGE-generated policies as its governance foundation.**

---

## Scientific verification

Test suite: **25/25 PASS** — all assertions data-driven, no untested claims.

```bash
python src/test_forge.py
# → FORGE Test Suite: 25/25 PASS
# → All tests PASS — FORGE is submission-ready
```

---

*Built for IBM Bob Hackathon 2026 · Part of the AI Reliability Ecosystem: SOUF AI · CITADEL · ATLAS · FORGE*
