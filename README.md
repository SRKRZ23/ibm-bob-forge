# FORGE — IBM Bob-Powered LLM Governance Policy Generator

> **Scan any codebase → detect LLM vulnerabilities → generate enterprise-grade SOUF AI security policies → audit every step with IBM Bob.**

FORGE uses IBM Bob to deeply understand a repository's context, detect every LLM call site and governance gap, then auto-generates SOUF AI / Lobster Trap YAML policies tailored to that specific codebase.

---

## 🚀 Submission (IBM Bob Hackathon, May 2026)

| Resource | Link |
|----------|------|
| 🎯 lablab.ai project page | [lablab.ai/.../forge-ai-security-policy-generator-for-llms](https://lablab.ai/ai-hackathons/ibm-bob-hackathon/forge/forge-ai-security-policy-generator-for-llms) |
| 🎥 Demo video (3:53, unlisted) | [youtu.be/_9PXGN_nxn8](https://youtu.be/_9PXGN_nxn8) |
| 💼 LinkedIn announcement | [linkedin.com/feed/update/...](https://www.linkedin.com/feed/update/urn:li:activity:7461775548038459392/) |
| 🐦 X announcement | [@SardorRazi99093](https://x.com/SardorRazi99093) (search `#ibm-bob-hackathon`) |
| 📺 YouTube channel | [@FORGE-LLM_SECURITY_SCANNER](https://www.youtube.com/@FORGE-LLM_SECURITY_SCANNER) |

**Submitted:** 17 May 2026 18:46 UZT (1h 14m before deadline) · **Status:** Accepted, judging in progress

**📣 Featured in build-in-public posts (4-of-5 hackathon week, $242K+ prize-eligibility):**
[LinkedIn long-form](https://www.linkedin.com/posts/sardor-razikov-569a5327b_atlas-enterprise-multi-agent-system-ai-activity-7462457002317975552-ADGR) · [X 5-tweet thread](https://x.com/SardorRazi99093/status/2056690128613970060) · [Facebook](https://www.facebook.com/share/p/1Nr4M2WhUG/) — full ecosystem story (FORGE + CITADEL + SOUF AI + ATLAS)

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

# Verify the BobShell tamper-evident SHA-256 audit chain
python3 verify_bobshell.py demo/output/forge_sample_vulnerable_repo_bobshell.jsonl
# → BobShell chain verified: 4 entries, SHA-256 tamper-evident
```

---

## Documentation

### 📚 Comprehensive Guides

- **[USAGE.md](docs/USAGE.md)** — Complete usage guide with installation, first scan, interpreting results, and CI/CD integration
- **[API.md](docs/API.md)** — Python API reference for programmatic use with code examples
- **[OWASP_MAPPING.md](docs/OWASP_MAPPING.md)** — Detailed mapping of OWASP LLM Top 10 to FORGE detection patterns and policies
- **[SECURITY.md](SECURITY.md)** — Security considerations, threat model, and vulnerability disclosure policy
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — System architecture and design decisions
- **[ROADMAP.md](ROADMAP.md)** — v1.1 / v2 / v3 plan with multi-action confidence scoring + Plan/Task DAG architecture
- **[CHANGELOG.md](CHANGELOG.md)** — Full release history including post-submission improvements

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
| FORGE | 9 | 15 | LLM01, LLM02, LLM05, LLM06, LLM07, LLM08 | ✅ verified (4 actions) |

All policies import successfully into Lobster Trap:
```bash
lobstertrap serve --policy forge_output/atlas/forge_atlas.yaml
# → Serving on :8080 with 4 ingress + 2 egress rules
```

---

## OWASP LLM Top 10 Coverage (2025 v2)

| ID | Name | Detected By |
|----|------|-------------|
| LLM01 | Prompt Injection | f-string, format(), concat patterns |
| LLM02 | Insecure Output Handling | Raw `.content`, unvalidated response use |
| LLM04 | Model Denial of Service | Unbounded LLM loops |
| LLM05 | Supply Chain Vulnerabilities | Unpinned LLM framework imports |
| LLM06 | Sensitive Information Disclosure | Hardcoded keys, PII in templates |
| LLM07 | System Prompt Leakage | Hardcoded system prompts, prompt logging, user concatenation, f-string templates |
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
│   │   └── repo_scanner.py      # LLM call-site detection + OWASP mapping (LLM01-LLM10)
│   ├── generator/
│   │   └── policy_generator.py  # SOUF AI YAML policy generation
│   ├── audit/
│   │   └── bobshell.py          # Tamper-evident IBM Bob audit log
│   ├── cli/
│   │   └── __main__.py          # CLI: scan | verify | demo
│   └── forge.py                 # Full pipeline orchestrator
├── tests/                       # 95 tests (pytest)
├── bob_sessions/                # IBM Bob IDE markdown exports + screenshots (mandatory)
├── docs/                        # USAGE.md, API.md, OWASP_MAPPING.md
├── examples/                    # Sample apps + CI integrations
├── demo/                        # sample_vulnerable_repo + benchmarks
├── forge_output/                # Generated policies (after running demo)
├── ONBOARDING.md                # Contributor guide (Bob IDE Task 2 output)
├── RISK_REGISTER.md             # Security self-audit (Bob IDE Task 3 output)
├── ARCHITECTURE.md
├── SECURITY.md
├── CHANGELOG.md
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

Test suite: **95/95 PASS** — all assertions data-driven, no untested claims.

```bash
pytest tests/ -v
# → 95 passed in 1.2s
# → Coverage: 41% overall, 100% policy_generator, 84% repo_scanner
```

---

## IBM Bob — Mandatory Submission Artifacts

Three productive Bob IDE tasks were executed against the FORGE codebase. Each task includes the exported markdown transcript **and** a screenshot of the Bob IDE task session consumption summary panel, per the official IBM Bob Hackathon Guide (May 2026, pages 18–19).

| # | Task | Markdown export | Screenshot(s) |
|---|------|-----------------|--------------|
| 1 | Add OWASP LLM07 System Prompt Leakage detection | [`bob_sessions/task1_llm07.md`](bob_sessions/task1_llm07.md) | [`bob_sessions/task1_llm07_summary.png`](bob_sessions/task1_llm07_summary.png) |
| 2 | Generate `ONBOARDING.md` contributor guide (717 lines) | [`bob_sessions/task2_onboarding.md`](bob_sessions/task2_onboarding.md) | [`task2_onboarding_summary_1.png`](bob_sessions/task2_onboarding_summary_1.png), [`task2_onboarding_summary_2.png`](bob_sessions/task2_onboarding_summary_2.png) |
| 3 | Security self-audit → `RISK_REGISTER.md` (595 lines) | [`bob_sessions/task3_risk_register.md`](bob_sessions/task3_risk_register.md) | [`task3_risk_register_summary_1.png`](bob_sessions/task3_risk_register_summary_1.png), [`task3_risk_register_summary_2.png`](bob_sessions/task3_risk_register_summary_2.png) |

**Bobcoin usage:** ~27 / 40 (~68% of allocation). Account: `ibm-coding-challenge-uat` (enterprise plan).

Supplementary Bob Shell session JSON files (the optional CLI variant) are also preserved under `bob_sessions/` as a historical record of the earlier build sprint — see [`bob_sessions/README.md`](bob_sessions/README.md) for the full breakdown.

Bob-produced artifacts now living at project root:
- [`ONBOARDING.md`](ONBOARDING.md) — 5-minute setup, first scan walkthrough, "how to add a detection pattern" using the real LLM07 example
- [`RISK_REGISTER.md`](RISK_REGISTER.md) — 5+ identified risks with severity, repro PoC, mitigation, OWASP ASVS cross-references

---

## Author

**Sardor Razikov** — Independent ML Engineer · Founder · Researcher · Tashkent 🇺🇿

**Research & competitions**
- CVPR 2026 Gait Recognition Challenge: **#2 / 56 teams** (sub40 = 0.90271)
- Kaggle SPR 2026 Mammography: **#7 / 371 teams** (Top 1.9%) — Portuguese medical NLP / BI-RADS
- Kaggle S6E3 Customer Churn: #23 / 4,142 (Top 1%)
- Author: [Epistemic Curie Benchmark](https://doi.org/10.5281/zenodo.19791329) — Zenodo DOI, CC BY 4.0
- AIMO3 (XTX $2.2M olympiad math): 39 / 50 with custom SC-TIR inference pipeline on gpt-oss-120B

**Founder track record**
- UCAR (auto-services marketplace, 2023–present) — **U-Start Demo Day 2023 1st place** (85M UZS grant + Korea internship)
- **KUSE Seoul 2024** — 2nd overall, 1st international (KOICA × Soonchunhyang University)
- **UJC PMP-43** senior executive Project Management — youngest student ever admitted
- 5 languages (Uzbek / Russian / English / Turkish B1 / Chinese) · operations across UK, China, Korea, Uzbekistan

**FORGE: built solo across 5 Bob Shell sessions + 3 Bob IDE tasks (~27 / 40 Bobcoins).**

## Team

FORGE was built solo by Sardor Razikov, with informal strategic guidance from a
small network of senior mentors in Tashkent (technical, business, and operational
domains). Looking to formalize co-founders and hire engineering team post-funding.

**Inquiries from large strategic partners are welcome** — anyone interested in
hiring, acquiring, or partnering can reach out at the addresses below.

## Contact

| Channel | Where |
|---|---|
| Email (primary) | razikovsardor1@gmail.com |
| Email (alt) | razikovs777@gmail.com |
| LinkedIn | [linkedin.com/in/sardor-razikov-569a5327b](https://linkedin.com/in/sardor-razikov-569a5327b) |
| X | [@SardorRazi99093](https://x.com/SardorRazi99093) |
| GitHub | [SRKRZ23](https://github.com/SRKRZ23) |
| lablab | [lablab.ai/u/@Sardor_R](https://lablab.ai/u/@Sardor_R) |

---

Built for the [IBM Bob Hackathon 2026](https://lablab.ai/ai-hackathons/ibm-bob-hackathon) · Part of the AI Reliability Ecosystem: SOUF AI · CITADEL · ATLAS · FORGE
