# Security Notice — Demo Credentials Are Placeholders

## TL;DR

All credential-like strings in this repository are **intentional placeholders** for FORGE security scanner testing. No real secrets have ever been committed.

## Background

FORGE detects OWASP LLM06 (Sensitive Information Disclosure) by scanning for hardcoded credentials in LLM application code. To demonstrate this capability, the `demo/sample_vulnerable_repo/` folder contains intentionally vulnerable code with **fake credential strings**.

## Where placeholder credentials appear

| File | Purpose | What kind of placeholders |
|------|---------|---------------------------|
| `demo/sample_vulnerable_repo/config.py` | FORGE scanner test fixture | `ghp_FORGE_DEMO_PLACEHOLDER_NOT_A_REAL_GITHUB_PAT`, `sk-FORGE_DEMO_PLACEHOLDER_NOT_A_REAL_TOKEN`, AWS-documented sample keys |
| `demo/sample_vulnerable_repo/app.py` | Flask demo app with deliberate vulnerabilities | Same pattern |
| `demo/sample_vulnerable_repo/agent.py` | LangChain agent with deliberate vulnerabilities | Same pattern |
| `bob_sessions/*.json` | IBM Bob session transcripts (read those files during dev) | Same pattern, post-processed to `*_FORGE_DEMO_REDACTED` |
| `demo/output/scan.log` | FORGE scan output from running demo | Same pattern, redacted |

## How to verify (for security reviewers)

1. **Grep for the explicit placeholder marker:**
   ```bash
   grep -rE "FORGE_DEMO_(PLACEHOLDER|REDACTED|FAKE)" .
   ```
   All current credential-pattern strings in the repo contain one of these markers.

2. **AWS sample keys** are AWS-documentation standard examples:
   - `AKIAIOSFODNN7EXAMPLE` — used in AWS official documentation, intentionally non-functional
   - `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` — same

3. **Run FORGE on this repo itself:**
   ```bash
   python src/cli/__main__.py scan --repo . --out ./scan_self_output
   ```
   FORGE will detect the placeholders in `demo/sample_vulnerable_repo/` and generate a policy blocking them — exactly the demonstration intended.

## False-positive secret scanner alerts

If GitGuardian, Gitleaks, TruffleHog, or any other secret scanner flags this repository, please mark the alerts as **false positive — intentional demo fixtures**. All flagged strings will be in:
- `demo/sample_vulnerable_repo/` (deliberate test fixtures)
- `bob_sessions/*.json` (Bob session records of reading those fixtures)

There are no real credentials in this repository's git history.

## Contact

If you find an actual leaked secret (not one of the documented placeholders above), please open an issue at https://github.com/SRKRZ23/ibm-bob-forge/issues immediately and the maintainer will rotate credentials.
