# CI/CD Integration Examples

This directory contains example CI/CD pipeline configurations for integrating FORGE security scans into your development workflow.

## Overview

FORGE can be integrated into various CI/CD platforms to automatically scan your LLM applications for security vulnerabilities on every commit, pull request, or scheduled interval.

## Available Examples

### 1. GitHub Actions (`.github/workflows/forge-scan.yml`)

**Features:**
- Runs on push to main/develop branches
- Runs on pull requests
- Daily scheduled scans at 2 AM UTC
- Fails build if HIGH severity vulnerabilities found
- Posts scan results as PR comments
- Uploads policy artifacts
- Verifies BobShell audit log integrity

**Usage:**
```bash
# Copy to your repository
cp .github/workflows/forge-scan.yml /path/to/your/repo/.github/workflows/

# Commit and push
git add .github/workflows/forge-scan.yml
git commit -m "Add FORGE security scan"
git push
```

**Configuration:**
- Update `FORGE_REPO` URL to your FORGE installation
- Set `LOBSTERTRAP_API_KEY` secret in GitHub repository settings
- Adjust `--strict` flag based on your security requirements

### 2. GitLab CI (`.gitlab-ci.yml`)

**Features:**
- Multi-stage pipeline (security, deploy)
- Runs on main, develop, and merge requests
- Fails pipeline if HIGH severity found
- Verifies BobShell audit log
- Manual deployment to Lobster Trap
- 30-day artifact retention

**Usage:**
```bash
# Copy to your repository
cp .gitlab-ci.yml /path/to/your/repo/

# Commit and push
git add .gitlab-ci.yml
git commit -m "Add FORGE security scan"
git push
```

**Configuration:**
- Set `FORGE_REPO` variable in GitLab CI/CD settings
- Set `LOBSTERTRAP_API_KEY` secret variable
- Update Lobster Trap deployment URL

### 3. Jenkins Pipeline (`Jenkinsfile`)

**Features:**
- Declarative pipeline syntax
- Parallel execution support
- Email notifications on failure
- Archives policy artifacts
- Slack integration (optional)

**Usage:**
```bash
# Copy to your repository
cp Jenkinsfile /path/to/your/repo/

# Create Jenkins pipeline job pointing to your repository
```

**Configuration:**
- Update FORGE installation path
- Configure email recipients
- Set up Slack webhook (optional)

### 4. Pre-commit Hook (`pre-commit-hook.sh`)

**Features:**
- Runs locally before each commit
- Fast feedback loop
- Prevents committing vulnerable code
- Can be bypassed with `--no-verify` if needed

**Usage:**
```bash
# Copy to your repository
cp pre-commit-hook.sh /path/to/your/repo/.git/hooks/pre-commit
chmod +x /path/to/your/repo/.git/hooks/pre-commit
```

## Integration Best Practices

### 1. Fail Fast on HIGH Severity

Always fail the build/pipeline when HIGH severity vulnerabilities are detected:

```yaml
- name: Check for HIGH Severity
  run: |
    if grep -q "severity: HIGH" forge-policies/*.yaml; then
      echo "❌ HIGH severity vulnerabilities found!"
      exit 1
    fi
```

### 2. Use Strict Mode in Production

Enable strict mode for production branches:

```bash
python -m src/cli scan --repo . --out ./policies --strict
```

### 3. Verify Audit Logs

Always verify BobShell audit log integrity:

```python
import json

with open('audit.jsonl', 'r') as f:
    entries = [json.loads(line) for line in f]

for i in range(1, len(entries)):
    if entries[i]['prev_hash'] != entries[i-1]['entry_hash']:
        raise ValueError("Audit chain broken!")
```

### 4. Archive Artifacts

Keep scan results and policies for compliance:

```yaml
artifacts:
  paths:
    - forge-policies/
  retention-days: 90
```

### 5. Notify Security Team

Send alerts for security findings:

```yaml
- name: Notify Security
  if: steps.scan.outputs.high_count > 0
  run: |
    curl -X POST https://slack.com/api/chat.postMessage \
      -H "Authorization: Bearer $SLACK_TOKEN" \
      -d "channel=#security" \
      -d "text=FORGE detected $HIGH_COUNT HIGH severity vulnerabilities"
```

## Deployment Workflow

### Recommended Flow

1. **Development**: Run FORGE locally or in pre-commit hook
2. **Pull Request**: Run FORGE scan, post results as comment
3. **Main Branch**: Run FORGE scan, fail if HIGH severity
4. **Production**: Deploy generated policy to Lobster Trap

### Example Multi-Stage Pipeline

```yaml
stages:
  - scan
  - test
  - deploy

scan:
  stage: scan
  script:
    - forge scan --repo . --out ./policies
    - if [ HIGH_COUNT > 0 ]; then exit 1; fi

test:
  stage: test
  needs: [scan]
  script:
    - run tests

deploy:
  stage: deploy
  needs: [scan, test]
  script:
    - deploy policy to lobstertrap
  only:
    - main
```

## Troubleshooting

### Issue: Scan Times Out

**Solution**: Increase timeout or scan smaller directories:
```yaml
timeout-minutes: 10
```

### Issue: False Positives

**Solution**: Review and adjust patterns in `src/scanner/repo_scanner.py`

### Issue: Audit Log Verification Fails

**Solution**: Re-run scan, do not trust previous results

## Security Considerations

1. **Secrets Management**: Never commit API keys or tokens
2. **Artifact Security**: Restrict access to scan artifacts
3. **Audit Logs**: Verify integrity before trusting results
4. **Policy Deployment**: Use manual approval for production

## Next Steps

- Review [USAGE.md](../../docs/USAGE.md) for CLI usage
- See [API.md](../../docs/API.md) for programmatic integration
- Check [OWASP_MAPPING.md](../../docs/OWASP_MAPPING.md) for vulnerability details

---

*Last updated: 2026-05-17*
