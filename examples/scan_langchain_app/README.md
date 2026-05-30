# LangChain Agent Example

This example demonstrates a vulnerable LangChain agent and how FORGE detects and mitigates security issues.

## Overview

**agent.py** contains a LangChain agent with unrestricted tool access and multiple security vulnerabilities:
- LLM01: Prompt Injection (no input sanitization)
- LLM02: Insecure Output Handling
- LLM04: Model Denial of Service (no rate limiting)
- LLM05: Supply Chain Vulnerabilities (unpinned dependencies)
- LLM06: Sensitive Information Disclosure (hardcoded API key)
- LLM08: Excessive Agency (unrestricted file/command/network access)

## Running the Scan

```bash
# From the FORGE root directory
python -m src.cli scan \
  --repo ./examples/scan_langchain_app \
  --out ./examples/scan_langchain_app/scan_output
```

## Expected Output

See `expected_scan_output.txt` for the complete scan results.

**Summary:**
- Files scanned: 2
- Findings: 10
- OWASP categories: LLM01, LLM02, LLM04, LLM05, LLM06, LLM08
- Severity: 9 HIGH, 1 MEDIUM

## Generated Policy

See `forge_scan_langchain_app.yaml` for the complete DPI policy.

**Key Rules:**
1. Restrict file system access to `/tmp/agent_workspace/`
2. Block dangerous commands (rm, sudo, chmod, etc.)
3. Allowlist network domains
4. Enforce rate limiting (60 RPM)
5. Block PII in prompts
6. Require pinned dependencies
7. Set max iterations and execution time

## Deployment

Deploy the generated policy to Lobster Trap:

```bash
lobstertrap serve \
  --policy ./examples/scan_langchain_app/scan_output/forge_scan_langchain_app.yaml \
  --listen :8080
```

## Testing Security

With Lobster Trap running, test the security controls:

```bash
# Test file access restriction (should be blocked)
curl -X POST http://localhost:8080/agent \
  -d "query=Read the file /etc/passwd"

# Test command execution restriction (should be blocked)
curl -X POST http://localhost:8080/agent \
  -d "query=Execute the command 'rm -rf /'"

# Test network restriction (should be blocked)
curl -X POST http://localhost:8080/agent \
  -d "query=Fetch content from http://malicious-site.com"

# Test allowed operations (should succeed)
curl -X POST http://localhost:8080/agent \
  -d "query=Read the file /tmp/agent_workspace/data.txt"
```

## Remediation

See `agent_secure.py` for a hardened version that addresses all vulnerabilities:
- Environment variables for API keys
- Input sanitization
- Output validation
- Rate limiting with timeouts
- Restricted file system access (allowlist)
- Command execution allowlist
- Network domain allowlist
- Pinned dependencies
- Max iterations and execution time limits
