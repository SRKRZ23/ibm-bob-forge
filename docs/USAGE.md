# FORGE Usage Guide

Complete guide to using FORGE for LLM security policy generation.

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [First Scan](#first-scan)
4. [Interpreting Results](#interpreting-results)
5. [Policy Output](#policy-output)
6. [CI/CD Integration](#cicd-integration)
7. [Advanced Usage](#advanced-usage)
8. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Git (for cloning repositories)

### Install from Source

```bash
# Clone the repository
git clone https://github.com/your-org/forge.git
cd forge

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -m src.cli scan --help
```

### Install as Package (Future)

```bash
pip install forge-llm-security
forge scan --help
```

---

## Quick Start

### 1. Scan Your First Repository

```bash
python -m src.cli scan --repo /path/to/your/llm-app --out ./policies
```

**What happens:**
1. FORGE scans all Python/JS/TS files in the repository
2. Detects LLM SDK calls and vulnerability patterns
3. Generates a DPI policy YAML policy
4. Creates a tamper-evident BobShell audit log

### 2. Verify Generated Policy

```bash
python -m src.cli verify --policy ./policies/forge_your-app.yaml
```

### 3. Deploy to Lobster Trap

```bash
lobstertrap serve --policy ./policies/forge_your-app.yaml --listen :8080
```

---

## First Scan

### Example 1: Scanning an OpenAI Application

**Repository Structure:**
```
my-openai-app/
├── app.py
├── config.py
└── requirements.txt
```

**Command:**
```bash
python -m src.cli scan --repo ./my-openai-app --out ./scan-results
```

**Sample Output:**
```
🔍 FORGE scanning: /Users/you/my-openai-app
   Output dir:      /Users/you/scan-results
   Strict mode:     False

============================================================
FORGE Scan Complete — 3 files, 247 lines
  LLM call sites:   5
  Governance gaps:  2
  Total findings:   7

OWASP breakdown:
  LLM01 Prompt Injection                  3 findings
  LLM02 Insecure Output Handling          2 findings
  LLM06 Sensitive Information Disclosure  2 findings

Severity:
  HIGH   ████████ 5
  MEDIUM ██ 2
  LOW    0

Policy:    scan-results/forge_my-openai-app.yaml
BobShell:  scan-results/forge_my-openai-app_bobshell.jsonl
Scan time: 127ms

Top findings:
  [HIGH  ] LLM01 app.py:15
           prompt = f"Summarize: {user_input}"
           → Add DPI input sanitisation before LLM call
  [HIGH  ] LLM02 app.py:20
           return response.choices[0].message.content
           → Add output validation and content filtering post-LLM
  [HIGH  ] LLM06 config.py:5
           OPENAI_API_KEY = "sk-proj-abc123..."
           → Move credentials to env vars; add output PII filter

BobShell chain: ✅ verified (4 actions logged)
============================================================
```

### Example 2: Scanning with Strict Mode

Strict mode reduces rate limits and applies stricter rules:

```bash
python -m src.cli scan --repo ./my-app --out ./policies --strict
```

**Differences in Strict Mode:**
- Rate limits: 30 RPM (vs 60 RPM normal)
- More aggressive blocking rules
- Lower risk thresholds for human review

### Example 3: Scanning Multiple Repositories (Demo Mode)

```bash
python -m src.cli demo --repos ./app1 ./app2 ./app3
```

**Sample Output:**
```
🔷 FORGE Demo — scanning 3 repos
============================================================

  Repo: app1
    Files:     15 | Findings:   7
    OWASP:    LLM01, LLM02
    BobShell: ✅ (4 actions)
    Policy:   forge_output/app1/forge_app1.yaml

  Repo: app2
    Files:     27 | Findings:   6
    OWASP:    LLM01, LLM08
    BobShell: ✅ (4 actions)
    Policy:   forge_output/app2/forge_app2.yaml

  Repo: app3
    Files:      9 | Findings:  10
    OWASP:    LLM01, LLM02, LLM05, LLM06, LLM08
    BobShell: ✅ (4 actions)
    Policy:   forge_output/app3/forge_app3.yaml

✅ Demo complete. All policies written to forge_output/
```

---

## Interpreting Results

### Understanding Findings

Each finding includes:

1. **Severity**: HIGH, MEDIUM, or LOW
2. **OWASP Category**: LLM01-LLM10
3. **Location**: File path and line number
4. **Code Snippet**: The problematic code
5. **Suggested Action**: How to fix it

### OWASP Categories Quick Reference

| ID | Name | Risk |
|----|------|------|
| LLM01 | Prompt Injection | User input flows into LLM prompts |
| LLM02 | Insecure Output Handling | LLM output used without validation |
| LLM04 | Model Denial of Service | Unbounded LLM calls |
| LLM05 | Supply Chain Vulnerabilities | Unpinned LLM framework dependencies |
| LLM06 | Sensitive Information Disclosure | Hardcoded credentials, PII in prompts |
| LLM08 | Excessive Agency | Unsafe system commands in agents |

See [OWASP_MAPPING.md](./OWASP_MAPPING.md) for complete details.

### Severity Levels

**HIGH** (Immediate Action Required):
- Prompt injection vulnerabilities
- Hardcoded API keys
- Unsafe code execution
- Missing output validation

**MEDIUM** (Should Fix Soon):
- Unpinned dependencies
- Missing rate limiting
- Supply chain risks

**LOW** (Best Practice):
- Minor configuration issues
- Documentation gaps

---

## Policy Output

### Generated Files

After scanning, FORGE creates two files:

1. **`forge_<repo-name>.yaml`**: DPI policy for Lobster Trap
2. **`forge_<repo-name>_bobshell.jsonl`**: Tamper-evident audit log

### Policy Structure

```yaml
version: "1.0"
policy_name: "forge_my_app"
generated_by: "FORGE v1.0"
generated_at: "2026-05-17T05:00:00"
source_repo: "/path/to/my_app"
owasp_findings: ["LLM01", "LLM02", "LLM06"]

default_action: "ALLOW"

ingress_rules:
  - name: "forge_block_prompt_injection"
    priority: 100
    action: "DENY"
    deny_message: "[FORGE/SOUF-AI] Blocked: prompt injection detected"
    conditions:
      - field: "contains_injection_patterns"
        match_type: "boolean"
        value: true

egress_rules:
  - name: "forge_block_credential_leak"
    priority: 100
    action: "DENY"
    deny_message: "[FORGE/SOUF-AI] Output blocked: credentials detected"
    conditions:
      - field: "contains_credentials"
        match_type: "boolean"
        value: true

rate_limits:
  requests_per_minute: 60
  requests_per_hour: 1800
  burst_threshold: 15

network:
  egress_policy: "allowlist"
  allowed_domains: ["api.openai.com", "api.anthropic.com"]
  denied_domains: ["*.onion", "pastebin.com"]

filesystem:
  denied_paths: ["/etc/**", "/root/**", "**/.ssh/**"]
  allowed_read_paths: ["/tmp/agent_workspace/**"]
  allowed_write_paths: ["/tmp/agent_workspace/**"]
```

### BobShell Audit Log

```jsonl
{"version":"1.0","seq":0,"timestamp":"2026-05-17T05:00:00","action":"forge_scan_start","params":{"repo":"/path/to/app"},"output_hash":"abc123...","prev_hash":"000000...","entry_hash":"def456...","bob_session_id":"bob_xyz123"}
{"version":"1.0","seq":1,"timestamp":"2026-05-17T05:00:01","action":"forge_scan_complete","params":{"files":15,"findings":7},"output_hash":"ghi789...","prev_hash":"def456...","entry_hash":"jkl012...","bob_session_id":"bob_xyz123"}
```

**Verification:**
```bash
# Verify chain integrity
python -c "
from src.audit.bobshell import BobShell
import json

bob = BobShell()
with open('forge_output/my_app_bobshell.jsonl') as f:
    for line in f:
        entry = json.loads(line)
        # Load entries...
print('Chain verified:', bob.verify())
"
```

---

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/forge-scan.yml`:

```yaml
name: FORGE Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install FORGE
        run: |
          git clone https://github.com/your-org/forge.git /tmp/forge
          cd /tmp/forge
          pip install -r requirements.txt
      
      - name: Run FORGE Scan
        run: |
          python -m /tmp/forge/src/cli scan \
            --repo . \
            --out ./forge-policies \
            --strict
      
      - name: Upload Policy Artifacts
        uses: actions/upload-artifact@v3
        with:
          name: forge-policies
          path: forge-policies/
      
      - name: Check for HIGH Severity Findings
        run: |
          # Parse scan output and fail if HIGH severity found
          if grep -q "HIGH" forge-policies/*.yaml; then
            echo "❌ HIGH severity vulnerabilities found!"
            exit 1
          fi
```

### GitLab CI

Create `.gitlab-ci.yml`:

```yaml
stages:
  - security

forge-scan:
  stage: security
  image: python:3.10
  script:
    - git clone https://github.com/your-org/forge.git /tmp/forge
    - cd /tmp/forge && pip install -r requirements.txt
    - cd $CI_PROJECT_DIR
    - python -m /tmp/forge/src/cli scan --repo . --out ./policies
  artifacts:
    paths:
      - policies/
    expire_in: 30 days
  only:
    - main
    - merge_requests
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('FORGE Scan') {
            steps {
                sh '''
                    git clone https://github.com/your-org/forge.git /tmp/forge
                    cd /tmp/forge
                    pip install -r requirements.txt
                    cd ${WORKSPACE}
                    python -m /tmp/forge/src/cli scan --repo . --out ./policies
                '''
            }
        }
        
        stage('Archive Policies') {
            steps {
                archiveArtifacts artifacts: 'policies/**', fingerprint: true
            }
        }
    }
}
```

### Pre-Commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash

echo "Running FORGE security scan..."

python -m src/cli scan --repo . --out /tmp/forge-scan

if [ $? -ne 0 ]; then
    echo "❌ FORGE scan failed!"
    exit 1
fi

echo "✅ FORGE scan passed"
exit 0
```

---

## Advanced Usage

### Custom Output Directory

```bash
python -m src.cli scan \
  --repo ./my-app \
  --out /secure/policies/$(date +%Y%m%d)
```

### Scanning Specific File Types

By default, FORGE scans `.py`, `.js`, `.ts`, `.go` files. To customize:

```python
from src.scanner.repo_scanner import scan_repo

result = scan_repo(
    repo_path="/path/to/repo",
    extensions=(".py", ".js", ".ts", ".jsx", ".tsx")
)
```

### Programmatic Usage

See [API.md](./API.md) for Python API reference.

### Custom Policy Names

```bash
python -m src.cli scan \
  --repo ./my-app \
  --out ./policies \
  --policy-name production_v2
```

(Note: This requires modifying the CLI to accept `--policy-name` argument)

---

## Troubleshooting

### Common Issues

#### 1. "Path does not exist" Error

```
ERROR: Invalid repository path: Path does not exist: /path/to/repo
```

**Solution**: Verify the path exists and you have read permissions:
```bash
ls -la /path/to/repo
```

#### 2. "Scan timed out" Warning

```
WARNING: Scan stopped: exceeded max duration (60s)
```

**Solution**: Large repositories may hit the timeout. Increase limit:
```python
from src.scanner.repo_scanner import scan_repo

result = scan_repo(
    repo_path="/path/to/large/repo",
    max_duration=120  # 2 minutes
)
```

#### 3. "Exceeded max files limit" Warning

```
WARNING: Scan stopped: exceeded max files limit (10000)
```

**Solution**: Repository has too many files. Increase limit or scan subdirectories:
```python
result = scan_repo(
    repo_path="/path/to/repo",
    max_files=20000
)
```

#### 4. No Findings Detected

If FORGE finds no vulnerabilities:
- Verify repository contains LLM code (OpenAI, Anthropic, LangChain, etc.)
- Check file extensions are supported (`.py`, `.js`, `.ts`, `.go`)
- Review patterns in `src/scanner/repo_scanner.py`

#### 5. BobShell Chain Verification Failed

```
BobShell chain: ❌ INVALID (4 actions logged)
```

**Solution**: Audit log has been tampered with. Do not trust the scan results. Re-run scan.

### Debug Mode

Enable verbose logging:

```bash
export FORGE_DEBUG=1
python -m src.cli scan --repo ./my-app --out ./policies
```

### Getting Help

- **Documentation**: [docs/](../docs/)
- **Examples**: [examples/](../examples/)
- **Issues**: https://github.com/your-org/forge/issues
- **Security**: See [SECURITY.md](../SECURITY.md)

---

## Next Steps

- Read [API.md](./API.md) for programmatic usage
- Review [OWASP_MAPPING.md](./OWASP_MAPPING.md) for vulnerability details
- Check [examples/](../examples/) for working code samples
- See [SECURITY.md](../SECURITY.md) for security considerations

---

*Last updated: 2026-05-17*
