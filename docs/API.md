# FORGE Python API Reference

Complete reference for using FORGE programmatically in your Python applications.

---

## Table of Contents

1. [Overview](#overview)
2. [Scanner API](#scanner-api)
3. [Generator API](#generator-api)
4. [BobShell Audit API](#bobshell-audit-api)
5. [Complete Examples](#complete-examples)
6. [Error Handling](#error-handling)
7. [Best Practices](#best-practices)

---

## Overview

FORGE provides three main APIs:

1. **Scanner API** (`src.scanner.repo_scanner`): Scan repositories for LLM vulnerabilities
2. **Generator API** (`src.generator.policy_generator`): Generate SOUF AI policies
3. **BobShell API** (`src.audit.bobshell`): Create tamper-evident audit logs

### Installation

```python
# Add FORGE to your project
import sys
sys.path.append('/path/to/forge')

from src.scanner.repo_scanner import scan_repo
from src.generator.policy_generator import generate_policy
from src.audit.bobshell import BobShell
```

---

## Scanner API

### `scan_repo()`

Scans a repository for LLM security vulnerabilities.

#### Function Signature

```python
def scan_repo(
    repo_path: str,
    extensions: tuple = (".py", ".js", ".ts", ".go"),
    max_file_size: int = 10 * 1024 * 1024,  # 10MB
    max_files: int = 10000,
    max_duration: int = 60  # seconds
) -> dict
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `repo_path` | `str` | Required | Absolute path to repository |
| `extensions` | `tuple` | `(".py", ".js", ".ts", ".go")` | File extensions to scan |
| `max_file_size` | `int` | `10485760` (10MB) | Max file size in bytes |
| `max_files` | `int` | `10000` | Max files to scan |
| `max_duration` | `int` | `60` | Max scan duration in seconds |

#### Returns

```python
{
    "repo_path": str,           # Absolute path to repository
    "files_scanned": int,       # Number of files scanned
    "lines_scanned": int,       # Total lines of code
    "llm_calls": int,           # LLM API call sites found
    "findings": [               # List of vulnerability findings
        {
            "severity": str,    # "HIGH", "MEDIUM", or "LOW"
            "owasp_id": str,    # "LLM01", "LLM02", etc.
            "category": str,    # Human-readable category
            "file": str,        # Relative file path
            "line": int,        # Line number
            "code": str,        # Code snippet
            "description": str, # Finding description
            "suggestion": str   # Remediation suggestion
        }
    ],
    "owasp_categories": list,   # Unique OWASP IDs found
    "scan_duration_ms": int,    # Scan duration in milliseconds
    "warnings": list            # Any warnings during scan
}
```

#### Example 1: Basic Scan

```python
from src.scanner.repo_scanner import scan_repo

# Scan a repository
result = scan_repo(repo_path="/path/to/my-llm-app")

# Print summary
print(f"Files scanned: {result['files_scanned']}")
print(f"Findings: {len(result['findings'])}")
print(f"OWASP categories: {', '.join(result['owasp_categories'])}")

# Iterate through findings
for finding in result['findings']:
    print(f"\n[{finding['severity']}] {finding['owasp_id']} - {finding['category']}")
    print(f"  File: {finding['file']}:{finding['line']}")
    print(f"  Code: {finding['code']}")
    print(f"  Fix: {finding['suggestion']}")
```

**Output:**
```
Files scanned: 15
Findings: 7
OWASP categories: LLM01, LLM02, LLM06

[HIGH] LLM01 - Prompt Injection
  File: app.py:15
  Code: prompt = f"Summarize: {user_input}"
  Fix: Add SOUF AI DPI input sanitisation before LLM call
```

#### Example 2: Custom File Extensions

```python
from src.scanner.repo_scanner import scan_repo

# Scan only Python and JavaScript files
result = scan_repo(
    repo_path="/path/to/repo",
    extensions=(".py", ".js")
)

print(f"Scanned {result['files_scanned']} Python/JS files")
```

#### Example 3: Large Repository with Custom Limits

```python
from src.scanner.repo_scanner import scan_repo

# Scan large repository with increased limits
result = scan_repo(
    repo_path="/path/to/large-repo",
    max_file_size=20 * 1024 * 1024,  # 20MB
    max_files=50000,                  # 50k files
    max_duration=300                  # 5 minutes
)

# Check for warnings
if result['warnings']:
    print("Warnings:")
    for warning in result['warnings']:
        print(f"  - {warning}")
```

#### Example 4: Filter High Severity Findings

```python
from src.scanner.repo_scanner import scan_repo

result = scan_repo(repo_path="/path/to/repo")

# Get only HIGH severity findings
high_severity = [
    f for f in result['findings'] 
    if f['severity'] == 'HIGH'
]

print(f"Critical vulnerabilities: {len(high_severity)}")

# Group by OWASP category
from collections import defaultdict
by_category = defaultdict(list)
for finding in high_severity:
    by_category[finding['owasp_id']].append(finding)

for owasp_id, findings in by_category.items():
    print(f"\n{owasp_id}: {len(findings)} findings")
```

---

## Generator API

### `generate_policy()`

Generates a SOUF AI YAML policy from scan results.

#### Function Signature

```python
def generate_policy(
    scan_result: dict,
    policy_name: str = None,
    strict_mode: bool = False
) -> str
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scan_result` | `dict` | Required | Output from `scan_repo()` |
| `policy_name` | `str` | Auto-generated | Custom policy name |
| `strict_mode` | `bool` | `False` | Enable stricter rules |

#### Returns

`str`: YAML policy content ready for Lobster Trap

#### Example 1: Generate Policy from Scan

```python
from src.scanner.repo_scanner import scan_repo
from src.generator.policy_generator import generate_policy

# Scan repository
scan_result = scan_repo(repo_path="/path/to/app")

# Generate policy
policy_yaml = generate_policy(scan_result)

# Save to file
with open("policy.yaml", "w") as f:
    f.write(policy_yaml)

print("Policy generated: policy.yaml")
```

#### Example 2: Strict Mode Policy

```python
from src.scanner.repo_scanner import scan_repo
from src.generator.policy_generator import generate_policy

scan_result = scan_repo(repo_path="/path/to/app")

# Generate strict policy (lower rate limits, stricter rules)
policy_yaml = generate_policy(
    scan_result=scan_result,
    strict_mode=True
)

print("Strict policy generated")
print(f"Rate limit: 30 RPM (vs 60 RPM normal)")
```

#### Example 3: Custom Policy Name

```python
from src.scanner.repo_scanner import scan_repo
from src.generator.policy_generator import generate_policy
import datetime

scan_result = scan_repo(repo_path="/path/to/app")

# Generate policy with timestamp
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
policy_yaml = generate_policy(
    scan_result=scan_result,
    policy_name=f"production_{timestamp}"
)

with open(f"policy_{timestamp}.yaml", "w") as f:
    f.write(policy_yaml)
```

#### Example 4: Parse Generated Policy

```python
from src.scanner.repo_scanner import scan_repo
from src.generator.policy_generator import generate_policy
import yaml

scan_result = scan_repo(repo_path="/path/to/app")
policy_yaml = generate_policy(scan_result)

# Parse YAML
policy = yaml.safe_load(policy_yaml)

# Inspect policy
print(f"Policy name: {policy['policy_name']}")
print(f"OWASP findings: {', '.join(policy['owasp_findings'])}")
print(f"Ingress rules: {len(policy['ingress_rules'])}")
print(f"Egress rules: {len(policy['egress_rules'])}")
print(f"Rate limit: {policy['rate_limits']['requests_per_minute']} RPM")

# Check for specific rules
for rule in policy['ingress_rules']:
    if 'injection' in rule['name']:
        print(f"\nPrompt injection rule: {rule['name']}")
        print(f"  Action: {rule['action']}")
        print(f"  Priority: {rule['priority']}")
```

---

## BobShell Audit API

### `BobShell` Class

Creates tamper-evident audit logs using SHA-256 chain hashing.

#### Class Signature

```python
class BobShell:
    def __init__(self, session_id: str = None)
    def log(self, action: str, params: dict = None, output_hash: str = None) -> dict
    def verify(self) -> bool
    def get_entries(self) -> list
    def save(self, filepath: str) -> None
    def load(self, filepath: str) -> None
```

#### Methods

##### `__init__(session_id=None)`

Initialize a new BobShell audit log.

**Parameters:**
- `session_id` (str, optional): Custom session ID. Auto-generated if not provided.

##### `log(action, params=None, output_hash=None)`

Log an action to the audit chain.

**Parameters:**
- `action` (str): Action name (e.g., "forge_scan_start")
- `params` (dict, optional): Action parameters
- `output_hash` (str, optional): Hash of action output

**Returns:** `dict` - The logged entry

##### `verify()`

Verify the integrity of the audit chain.

**Returns:** `bool` - True if chain is valid, False if tampered

##### `get_entries()`

Get all audit log entries.

**Returns:** `list` - List of all entries

##### `save(filepath)`

Save audit log to JSONL file.

**Parameters:**
- `filepath` (str): Path to save file

##### `load(filepath)`

Load audit log from JSONL file.

**Parameters:**
- `filepath` (str): Path to load file

#### Example 1: Basic Audit Logging

```python
from src.audit.bobshell import BobShell

# Create audit log
bob = BobShell()

# Log scan start
bob.log(
    action="forge_scan_start",
    params={"repo": "/path/to/app"}
)

# Log scan progress
bob.log(
    action="forge_files_scanned",
    params={"count": 15}
)

# Log scan complete
bob.log(
    action="forge_scan_complete",
    params={"findings": 7, "duration_ms": 127}
)

# Verify chain
is_valid = bob.verify()
print(f"Audit chain valid: {is_valid}")

# Save to file
bob.save("audit.jsonl")
```

#### Example 2: Verify Existing Audit Log

```python
from src.audit.bobshell import BobShell

# Load existing audit log
bob = BobShell()
bob.load("audit.jsonl")

# Verify integrity
if bob.verify():
    print("✅ Audit log is valid and untampered")
    
    # Print entries
    for entry in bob.get_entries():
        print(f"[{entry['seq']}] {entry['action']}")
        print(f"  Time: {entry['timestamp']}")
        print(f"  Params: {entry['params']}")
else:
    print("❌ Audit log has been tampered with!")
```

#### Example 3: Custom Session ID

```python
from src.audit.bobshell import BobShell
import uuid

# Create audit log with custom session ID
session_id = f"prod_{uuid.uuid4().hex[:8]}"
bob = BobShell(session_id=session_id)

bob.log("deployment_start", {"env": "production"})
bob.log("policy_applied", {"policy": "forge_app_v1"})
bob.log("deployment_complete", {"status": "success"})

print(f"Session ID: {session_id}")
bob.save(f"audit_{session_id}.jsonl")
```

#### Example 4: Detect Tampering

```python
from src.audit.bobshell import BobShell
import json

# Create and save audit log
bob = BobShell()
bob.log("action_1", {"data": "original"})
bob.log("action_2", {"data": "original"})
bob.save("audit.jsonl")

# Simulate tampering (modify file)
with open("audit.jsonl", "r") as f:
    lines = f.readlines()

# Tamper with second entry
entry = json.loads(lines[1])
entry['params']['data'] = "TAMPERED"
lines[1] = json.dumps(entry) + "\n"

with open("audit.jsonl", "w") as f:
    f.writelines(lines)

# Try to verify
bob2 = BobShell()
bob2.load("audit.jsonl")

if not bob2.verify():
    print("❌ Tampering detected!")
    print("Chain verification failed - do not trust this audit log")
```

---

## Complete Examples

### Example 1: Full Scan Pipeline

```python
from src.scanner.repo_scanner import scan_repo
from src.generator.policy_generator import generate_policy
from src.audit.bobshell import BobShell
import json
import os

def full_scan_pipeline(repo_path: str, output_dir: str):
    """Complete FORGE scan pipeline with audit logging."""
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize audit log
    bob = BobShell()
    bob.log("forge_scan_start", {"repo": repo_path})
    
    try:
        # Scan repository
        print(f"🔍 Scanning {repo_path}...")
        scan_result = scan_repo(repo_path=repo_path)
        
        bob.log("forge_scan_complete", {
            "files": scan_result['files_scanned'],
            "findings": len(scan_result['findings']),
            "owasp": scan_result['owasp_categories']
        })
        
        # Generate policy
        print("📝 Generating policy...")
        policy_yaml = generate_policy(scan_result)
        
        # Save policy
        repo_name = os.path.basename(repo_path)
        policy_path = os.path.join(output_dir, f"forge_{repo_name}.yaml")
        with open(policy_path, "w") as f:
            f.write(policy_yaml)
        
        bob.log("forge_policy_generated", {"path": policy_path})
        
        # Save scan results
        results_path = os.path.join(output_dir, f"forge_{repo_name}_results.json")
        with open(results_path, "w") as f:
            json.dump(scan_result, f, indent=2)
        
        # Save audit log
        audit_path = os.path.join(output_dir, f"forge_{repo_name}_bobshell.jsonl")
        bob.save(audit_path)
        
        # Verify audit chain
        if bob.verify():
            print("✅ Audit chain verified")
        else:
            print("❌ Audit chain verification failed!")
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"FORGE Scan Complete")
        print(f"{'='*60}")
        print(f"Files scanned:  {scan_result['files_scanned']}")
        print(f"Findings:       {len(scan_result['findings'])}")
        print(f"OWASP:          {', '.join(scan_result['owasp_categories'])}")
        print(f"Policy:         {policy_path}")
        print(f"Results:        {results_path}")
        print(f"Audit log:      {audit_path}")
        print(f"{'='*60}")
        
        return {
            "success": True,
            "scan_result": scan_result,
            "policy_path": policy_path,
            "audit_path": audit_path
        }
        
    except Exception as e:
        bob.log("forge_scan_error", {"error": str(e)})
        bob.save(os.path.join(output_dir, "forge_error_bobshell.jsonl"))
        raise

# Usage
result = full_scan_pipeline(
    repo_path="/path/to/my-app",
    output_dir="./forge-output"
)
```

### Example 2: Batch Scanning Multiple Repositories

```python
from src.scanner.repo_scanner import scan_repo
from src.generator.policy_generator import generate_policy
from src.audit.bobshell import BobShell
import os

def batch_scan(repo_paths: list, output_dir: str):
    """Scan multiple repositories and generate policies."""
    
    os.makedirs(output_dir, exist_ok=True)
    results = []
    
    # Create master audit log
    master_bob = BobShell(session_id="batch_scan")
    master_bob.log("batch_scan_start", {"repos": len(repo_paths)})
    
    for repo_path in repo_paths:
        repo_name = os.path.basename(repo_path)
        print(f"\n🔍 Scanning {repo_name}...")
        
        try:
            # Scan
            scan_result = scan_repo(repo_path=repo_path)
            
            # Generate policy
            policy_yaml = generate_policy(scan_result)
            
            # Save policy
            repo_output_dir = os.path.join(output_dir, repo_name)
            os.makedirs(repo_output_dir, exist_ok=True)
            
            policy_path = os.path.join(repo_output_dir, f"forge_{repo_name}.yaml")
            with open(policy_path, "w") as f:
                f.write(policy_yaml)
            
            # Create repo-specific audit log
            repo_bob = BobShell()
            repo_bob.log("forge_scan_complete", {
                "repo": repo_path,
                "findings": len(scan_result['findings'])
            })
            repo_bob.save(os.path.join(repo_output_dir, f"forge_{repo_name}_bobshell.jsonl"))
            
            # Log to master
            master_bob.log("repo_scanned", {
                "repo": repo_name,
                "findings": len(scan_result['findings']),
                "owasp": scan_result['owasp_categories']
            })
            
            results.append({
                "repo": repo_name,
                "success": True,
                "findings": len(scan_result['findings']),
                "policy": policy_path
            })
            
        except Exception as e:
            print(f"❌ Error scanning {repo_name}: {e}")
            master_bob.log("repo_scan_error", {"repo": repo_name, "error": str(e)})
            results.append({
                "repo": repo_name,
                "success": False,
                "error": str(e)
            })
    
    master_bob.log("batch_scan_complete", {"total": len(repo_paths)})
    master_bob.save(os.path.join(output_dir, "batch_scan_bobshell.jsonl"))
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Batch Scan Complete")
    print(f"{'='*60}")
    successful = sum(1 for r in results if r['success'])
    print(f"Repositories scanned: {len(repo_paths)}")
    print(f"Successful:           {successful}")
    print(f"Failed:               {len(repo_paths) - successful}")
    print(f"{'='*60}")
    
    return results

# Usage
repos = [
    "/path/to/app1",
    "/path/to/app2",
    "/path/to/app3"
]

results = batch_scan(repos, "./batch-output")
```

### Example 3: CI/CD Integration Script

```python
#!/usr/bin/env python3
"""
FORGE CI/CD integration script.
Fails build if HIGH severity vulnerabilities found.
"""

from src.scanner.repo_scanner import scan_repo
from src.generator.policy_generator import generate_policy
from src.audit.bobshell import BobShell
import sys
import os

def ci_scan(repo_path: str, fail_on_high: bool = True):
    """Scan repository in CI/CD pipeline."""
    
    print("🔷 FORGE CI/CD Security Scan")
    print("="*60)
    
    # Initialize audit
    bob = BobShell(session_id=os.getenv("CI_BUILD_ID", "ci_scan"))
    bob.log("ci_scan_start", {
        "repo": repo_path,
        "ci_system": os.getenv("CI_SYSTEM", "unknown")
    })
    
    # Scan
    scan_result = scan_repo(repo_path=repo_path)
    
    # Count severity levels
    high_count = sum(1 for f in scan_result['findings'] if f['severity'] == 'HIGH')
    medium_count = sum(1 for f in scan_result['findings'] if f['severity'] == 'MEDIUM')
    low_count = sum(1 for f in scan_result['findings'] if f['severity'] == 'LOW')
    
    # Log results
    bob.log("ci_scan_complete", {
        "findings": len(scan_result['findings']),
        "high": high_count,
        "medium": medium_count,
        "low": low_count
    })
    
    # Print results
    print(f"Files scanned: {scan_result['files_scanned']}")
    print(f"Total findings: {len(scan_result['findings'])}")
    print(f"  HIGH:   {high_count}")
    print(f"  MEDIUM: {medium_count}")
    print(f"  LOW:    {low_count}")
    print("="*60)
    
    # Generate policy
    policy_yaml = generate_policy(scan_result)
    with open("forge_policy.yaml", "w") as f:
        f.write(policy_yaml)
    print("✅ Policy saved: forge_policy.yaml")
    
    # Save audit
    bob.save("forge_ci_bobshell.jsonl")
    print("✅ Audit log saved: forge_ci_bobshell.jsonl")
    
    # Fail build if HIGH severity found
    if fail_on_high and high_count > 0:
        print(f"\n❌ BUILD FAILED: {high_count} HIGH severity vulnerabilities found!")
        bob.log("ci_build_failed", {"reason": "high_severity_findings"})
        bob.save("forge_ci_bobshell.jsonl")
        sys.exit(1)
    
    print("\n✅ Security scan passed")
    bob.log("ci_build_passed", {})
    bob.save("forge_ci_bobshell.jsonl")
    return 0

if __name__ == "__main__":
    repo = sys.argv[1] if len(sys.argv) > 1 else "."
    sys.exit(ci_scan(repo))
```

---

## Error Handling

### Common Exceptions

```python
from src.scanner.repo_scanner import scan_repo

try:
    result = scan_repo(repo_path="/invalid/path")
except FileNotFoundError as e:
    print(f"Repository not found: {e}")
except PermissionError as e:
    print(f"Permission denied: {e}")
except ValueError as e:
    print(f"Invalid parameter: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Handling Scan Warnings

```python
from src.scanner.repo_scanner import scan_repo

result = scan_repo(repo_path="/path/to/large/repo")

# Check for warnings
if result['warnings']:
    print("⚠️  Warnings during scan:")
    for warning in result['warnings']:
        print(f"  - {warning}")
        
        if "timeout" in warning.lower():
            print("    Consider increasing max_duration")
        elif "max files" in warning.lower():
            print("    Consider increasing max_files limit")
```

### Audit Log Verification Failures

```python
from src.audit.bobshell import BobShell

bob = BobShell()
bob.load("audit.jsonl")

if not bob.verify():
    print("❌ CRITICAL: Audit log verification failed!")
    print("Possible causes:")
    print("  1. File has been tampered with")
    print("  2. File corruption")
    print("  3. Incomplete log (missing entries)")
    print("\nDo NOT trust this audit log. Re-run scan.")
    
    # Optionally: inspect entries for anomalies
    entries = bob.get_entries()
    for i, entry in enumerate(entries):
        print(f"Entry {i}: {entry['action']} at {entry['timestamp']}")
```

---

## Best Practices

### 1. Always Use Audit Logging

```python
from src.audit.bobshell import BobShell

# ✅ Good: Create audit log for all operations
bob = BobShell()
bob.log("operation_start", {"user": "admin"})
# ... perform operations ...
bob.log("operation_complete", {"status": "success"})
bob.save("audit.jsonl")

# ❌ Bad: No audit trail
# ... perform operations without logging ...
```

### 2. Verify Audit Logs Before Trust

```python
from src.audit.bobshell import BobShell

# ✅ Good: Always verify before using
bob = BobShell()
bob.load("audit.jsonl")
if bob.verify():
    # Safe to use
    entries = bob.get_entries()
else:
    raise ValueError("Audit log verification failed!")

# ❌ Bad: Use without verification
bob = BobShell()
bob.load("audit.jsonl")
entries = bob.get_entries()  # Might be tampered!
```

### 3. Handle Large Repositories

```python
from src.scanner.repo_scanner import scan_repo

# ✅ Good: Set appropriate limits for large repos
result = scan_repo(
    repo_path="/path/to/large/repo",
    max_files=50000,
    max_duration=300  # 5 minutes
)

# ❌ Bad: Use defaults for large repos (may timeout)
result = scan_repo(repo_path="/path/to/large/repo")
```

### 4. Save All Artifacts

```python
import json
import os

# ✅ Good: Save scan results, policy, and audit log
output_dir = "./forge-output"
os.makedirs(output_dir, exist_ok=True)

# Save scan results
with open(f"{output_dir}/scan_results.json", "w") as f:
    json.dump(scan_result, f, indent=2)

# Save policy
with open(f"{output_dir}/policy.yaml", "w") as f:
    f.write(policy_yaml)

# Save audit log
bob.save(f"{output_dir}/audit.jsonl")

# ❌ Bad: Only save policy (lose scan details)
with open("policy.yaml", "w") as f:
    f.write(policy_yaml)
```

### 5. Use Strict Mode in Production

```python
from src.generator.policy_generator import generate_policy

# ✅ Good: Use strict mode for production
policy_yaml = generate_policy(
    scan_result=scan_result,
    strict_mode=True  # Lower rate limits, stricter rules
)

# ❌ Bad: Use default mode in production (too permissive)
policy_yaml = generate_policy(scan_result=scan_result)
```

---

## Next Steps

- Read [USAGE.md](./USAGE.md) for CLI usage
- Review [OWASP_MAPPING.md](./OWASP_MAPPING.md) for vulnerability details
- Check [examples/](../examples/) for working code samples
- See [SECURITY.md](../SECURITY.md) for security considerations

---

*Last updated: 2026-05-17*
