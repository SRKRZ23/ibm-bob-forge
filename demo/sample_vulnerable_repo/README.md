# Sample Vulnerable Repository

This is an intentionally vulnerable LLM application used to demonstrate FORGE's detection capabilities.

## Vulnerabilities Included

### LLM01: Prompt Injection
- `app.py:25` - Unsanitized user input in prompts
- `agent.py:68` - No input sanitization in agent

### LLM02: Insecure Output Handling
- `app.py:36` - Direct HTML rendering of LLM output
- `app.py:120` - SQL injection via LLM output

### LLM04: Model Denial of Service
- `app.py:29` - No rate limiting, no timeout, no max_tokens
- `agent.py:62` - No max_iterations or max_execution_time

### LLM05: Supply Chain Vulnerabilities
- `requirements.txt` - All dependencies unpinned

### LLM06: Sensitive Information Disclosure
- `app.py:12` - Hardcoded OpenAI API key
- `app.py:56` - PII (SSN, credit card) in prompts
- `app.py:66` - PII in logs
- `agent.py:11` - Hardcoded API key
- `config.py` - Multiple hardcoded credentials and secrets

### LLM08: Excessive Agency
- `app.py:79` - Unrestricted command execution with shell=True
- `app.py:97` - Unrestricted network access
- `app.py:106` - Unrestricted file system access
- `agent.py:17-40` - Unrestricted agent tools

## Expected FORGE Findings

When scanned with FORGE, this repository should detect:
- **15+ HIGH severity** vulnerabilities
- **1+ MEDIUM severity** vulnerabilities
- **OWASP categories**: LLM01, LLM02, LLM04, LLM05, LLM06, LLM08

## Usage

```bash
# Scan this repository
python -m src.cli scan --repo demo/sample_vulnerable_repo --out demo/output

# Expected output:
# - 4 files scanned
# - 15+ findings
# - Generated policy: demo/output/forge_sample_vulnerable_repo.yaml
# - Audit log: demo/output/forge_sample_vulnerable_repo_bobshell.jsonl
```
