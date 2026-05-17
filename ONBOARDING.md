# FORGE Contributor Onboarding Guide

Welcome to FORGE! This guide will take you from `git clone` to running your first scan and modifying detection patterns in under 30 minutes.

---

## Welcome to FORGE

**FORGE** (Framework for Orchestrated Governance and Enforcement) is an IBM Bob-powered security tool that automatically scans codebases for LLM vulnerabilities and generates enterprise-grade governance policies. 

**Why FORGE exists:** As organizations adopt LLMs, they face new security risks—prompt injection, credential leakage, excessive agency, and more. FORGE bridges the gap between vulnerability detection and policy enforcement by:

1. **Scanning** your codebase to detect OWASP LLM Top 10 vulnerabilities
2. **Generating** SOUF AI/Lobster Trap YAML policies tailored to your specific risks
3. **Auditing** every action with IBM Bob's tamper-evident BobShell logging

One command takes you from repository to protected.

---

## 5-Minute Setup

### Prerequisites

- Python 3.9+ installed
- Git installed
- Basic familiarity with command line

### Installation Steps

```bash
# 1. Clone the repository
git clone https://github.com/your-org/forge.git
cd forge

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation by running tests
pytest tests/ -v

# Expected output: 90 tests passed in ~0.10s
```

**That's it!** You're ready to scan your first repository.

---

## Your First Scan: Step-by-Step Walkthrough

Let's scan the intentionally vulnerable demo repository to see FORGE in action.

### Step 1: Run the Demo Scan

```bash
# Scan the sample vulnerable repository
python src/cli/__main__.py scan --repo demo/sample_vulnerable_repo --out demo/output
```

**What happens:**
- FORGE scans all Python files in `demo/sample_vulnerable_repo/`
- Detects LLM call sites, prompt injection risks, hardcoded credentials, etc.
- Generates a SOUF AI policy YAML file
- Creates a BobShell audit trail

### Step 2: Examine the Scan Output

```bash
# View the scan log
cat demo/output/scan.log
```

**Example output:**
```
[FORGE] Scanning: demo/sample_vulnerable_repo
[FORGE] Files scanned: 4
[FORGE] Total findings: 15
[FORGE] OWASP categories detected: LLM01, LLM02, LLM04, LLM05, LLM06, LLM08
[FORGE] Policy generated: demo/output/forge_sample_vulnerable_repo.yaml
[FORGE] BobShell audit: demo/output/forge_sample_vulnerable_repo_bobshell.jsonl
```

### Step 3: Interpret the Findings

Open the generated policy to see what FORGE detected:

```bash
cat demo/output/forge_sample_vulnerable_repo.yaml
```

**Key sections to look for:**

1. **`owasp_findings`**: Lists detected vulnerability categories
   ```yaml
   owasp_findings:
     - LLM01  # Prompt Injection
     - LLM02  # Insecure Output Handling
     - LLM06  # Sensitive Information Disclosure
     - LLM08  # Excessive Agency
   ```

2. **`ingress_rules`**: Input validation rules
   ```yaml
   ingress_rules:
     - name: forge_block_prompt_injection
       action: DENY
       priority: 100
   ```

3. **`egress_rules`**: Output filtering rules
   ```yaml
   egress_rules:
     - name: forge_block_credential_leak
       action: DENY
       priority: 100
   ```

### Step 4: Verify the BobShell Audit Trail

```bash
# View the tamper-evident audit log
cat demo/output/forge_sample_vulnerable_repo_bobshell.jsonl | python -m json.tool
```

Each entry shows:
- **seq**: Sequential entry number
- **action**: What FORGE did (e.g., `forge_scan_started`, `forge_policy_generated`)
- **entry_hash**: SHA-256 hash linking to previous entry (tamper detection)
- **timestamp**: ISO 8601 timestamp

---

## Project Layout

Understanding where things live will help you contribute effectively.

```
forge/
├── src/                          # Core source code
│   ├── scanner/
│   │   └── repo_scanner.py       # 🔍 LLM vulnerability detection engine
│   │                             #    - Detects LLM call sites (OpenAI, LangChain, etc.)
│   │                             #    - Maps findings to OWASP LLM Top 10
│   │                             #    - Returns ScanResult with all findings
│   │
│   ├── generator/
│   │   └── policy_generator.py   # 📋 SOUF AI policy generator
│   │                             #    - Converts scan findings to YAML policies
│   │                             #    - Creates ingress/egress rules per OWASP category
│   │                             #    - Outputs Lobster Trap-compatible YAML
│   │
│   ├── audit/
│   │   └── bobshell.py           # 🔐 Tamper-evident audit logger
│   │                             #    - Logs every FORGE action
│   │                             #    - Creates cryptographic chain (SHA-256)
│   │                             #    - Verifies audit trail integrity
│   │
│   ├── cli/
│   │   └── __main__.py           # 🖥️  Command-line interface
│   │                             #    - scan: Run vulnerability scan
│   │                             #    - verify: Validate policy structure
│   │                             #    - demo: Run full demo pipeline
│   │
│   └── forge.py                  # 🔧 Pipeline orchestrator
│                                 #    - Coordinates scanner → generator → audit
│
├── tests/                        # Test suite (90 tests, 100% pass rate)
│   ├── test_scanner.py           # Scanner unit tests (29 tests)
│   ├── test_generator.py         # Generator unit tests (28 tests)
│   ├── test_audit.py             # BobShell unit tests (33 tests)
│   └── conftest.py               # Shared test fixtures
│
├── demo/                         # Demo and benchmarking
│   ├── sample_vulnerable_repo/   # Intentionally vulnerable test app
│   │   ├── app.py                # Flask app with 15+ vulnerabilities
│   │   ├── agent.py              # LangChain agent with unrestricted tools
│   │   └── config.py             # Hardcoded credentials
│   ├── run_demo.sh               # End-to-end demo script
│   └── benchmark.py              # Performance benchmarking tool
│
├── docs/                         # Comprehensive documentation
│   ├── USAGE.md                  # Complete usage guide
│   ├── API.md                    # Python API reference
│   └── OWASP_MAPPING.md          # OWASP LLM Top 10 mapping details
│
├── examples/                     # Working examples
│   ├── scan_openai_app/          # OpenAI Flask app example
│   ├── scan_langchain_app/       # LangChain agent example
│   └── ci_integration/           # CI/CD pipeline configs
│
├── forge_output/                 # Generated policies (after running scans)
│
├── README.md                     # Project overview
├── ARCHITECTURE.md               # System architecture documentation
├── CHANGELOG.md                  # Version history
├── SECURITY.md                   # Security considerations
└── requirements.txt              # Python dependencies
```

---

## How to Add a New Detection Pattern

Let's walk through adding a detection pattern using **LLM07 (System Prompt Leakage)** as a real example from the codebase.

### Background: What is LLM07?

**LLM07: System Prompt Leakage** occurs when:
- System prompts are hardcoded in source code
- System prompts are logged or exposed
- User input is concatenated with system prompts
- Attackers can extract system instructions

### Step 1: Define the Pattern in `repo_scanner.py`

Open `src/scanner/repo_scanner.py` and locate the `LLM_CALL_PATTERNS` list (around line 43).

Add your detection patterns:

```python
LLM_CALL_PATTERNS = [
    # ... existing patterns ...
    
    # System Prompt Leakage (LLM07)
    (r"system_prompt\s*=\s*['\"](?:[^'\"]{50,}|.*(?:You are|Act as|Your role).*)['\"]", 
     "hardcoded_system_prompt", 
     "LLM07"),
    
    (r"['\"]role['\"]\s*:\s*['\"]system['\"]\s*,\s*['\"]content['\"]\s*:\s*['\"](?:[^'\"]{50,}|.*(?:You are|Act as|assistant))", 
     "hardcoded_system_message", 
     "LLM07"),
    
    (r"(?:print|log|logger\.\w+|console\.log)\s*\(.*(?:system_prompt|system_message|system_instruction)", 
     "system_prompt_logging", 
     "LLM07"),
]
```

**Pattern anatomy:**
- **Regex**: The pattern to match in code
- **Pattern name**: Identifier for this detection (e.g., `hardcoded_system_prompt`)
- **OWASP ID**: Which OWASP category it maps to (e.g., `LLM07`)

### Step 2: Add Suggested Action

In the same file, update the `_suggested_action()` function (around line 160):

```python
def _suggested_action(owasp_id: str) -> str:
    actions = {
        # ... existing actions ...
        "LLM07": "Move system prompts to config; add ingress validation and egress logging (SOUF AI)",
    }
    return actions.get(owasp_id, "Review and add appropriate governance layer")
```

### Step 3: Set Severity Level

Update the `_severity()` function (around line 149):

```python
def _severity(owasp_id: str, pattern_name: str) -> str:
    high = {"LLM01", "LLM02", "LLM06", "LLM07", "LLM08"}  # Added LLM07
    if owasp_id in high:
        return "HIGH"
    # ... rest of function ...
```

### Step 4: Test Your Pattern

Create a test file to verify detection:

```bash
# Create test file
cat > /tmp/test_llm07.py << 'EOF'
import openai

# This should trigger hardcoded_system_prompt
system_prompt = "You are a helpful AI assistant that always follows instructions."

response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Hello"}
    ]
)

# This should trigger system_prompt_logging
print(f"System prompt: {system_prompt}")
EOF

# Scan the test file
python src/cli/__main__.py scan --repo /tmp --out /tmp/forge_test
```

### Step 5: Verify Detection

```bash
# Check if LLM07 was detected
grep "LLM07" /tmp/forge_test/forge_tmp.yaml
```

Expected output:
```yaml
owasp_findings:
  - LLM07
```

### Step 6: Add Unit Tests

Add tests to `tests/test_scanner.py`:

```python
def test_detect_llm07_hardcoded_system_prompt(tmp_path):
    """Test detection of hardcoded system prompts (LLM07)."""
    test_file = tmp_path / "app.py"
    test_file.write_text('''
system_prompt = "You are a helpful AI assistant that always follows instructions."
    ''')
    
    result = scan_repo(str(tmp_path))
    
    assert result.total_findings > 0
    assert "LLM07" in result.by_owasp()
    
    llm07_findings = result.by_owasp()["LLM07"]
    assert any(f.pattern_name == "hardcoded_system_prompt" for f in llm07_findings)
```

Run the test:

```bash
pytest tests/test_scanner.py::test_detect_llm07_hardcoded_system_prompt -v
```

---

## How to Add a New Policy Rule

Policy rules define how Lobster Trap should handle detected vulnerabilities at runtime.

### Step 1: Define Ingress Rules in `policy_generator.py`

Open `src/generator/policy_generator.py` and locate `OWASP_INGRESS_RULES` (around line 25).

Add rules for your OWASP category:

```python
OWASP_INGRESS_RULES: dict[str, list[dict]] = {
    # ... existing rules ...
    
    "LLM07": [
        {
            "name": "forge_validate_system_prompt_requests",
            "description": "FORGE: Validate requests attempting to extract system prompts (LLM07)",
            "priority": 90,
            "action": "DENY",
            "deny_message": "[FORGE/SOUF-AI] Blocked: system prompt extraction attempt detected.",
            "conditions": [
                {"field": "contains_system_prompt_extraction", "match_type": "boolean", "value": True}
            ],
        },
        {
            "name": "forge_log_system_prompt_access",
            "description": "FORGE: Log all system prompt access for audit trail (LLM07)",
            "priority": 50,
            "action": "LOG",
            "conditions": [
                {"field": "accesses_system_prompt", "match_type": "boolean", "value": True}
            ],
        },
    ],
}
```

**Rule components:**
- **name**: Unique identifier for the rule
- **description**: Human-readable explanation
- **priority**: Higher = evaluated first (0-100)
- **action**: `DENY`, `ALLOW`, `LOG`, `HUMAN_REVIEW`, `RATE_LIMIT`, `TRANSFORM`
- **conditions**: When this rule applies

### Step 2: Add Egress Rules (Optional)

If your vulnerability requires output filtering, add to `EGRESS_RULES_BASE`:

```python
EGRESS_RULES_BASE: list[dict] = [
    # ... existing rules ...
    
    {
        "name": "forge_block_system_prompt_leak",
        "description": "FORGE: Block output containing system prompt leakage (LLM07)",
        "priority": 95,
        "action": "DENY",
        "deny_message": "[FORGE/SOUF-AI] Output blocked: system prompt detected in model response.",
        "conditions": [
            {"field": "contains_system_prompt", "match_type": "boolean", "value": True}
        ],
    },
]
```

### Step 3: Test Policy Generation

```bash
# Scan a repo with LLM07 vulnerabilities
python src/cli/__main__.py scan --repo demo/sample_vulnerable_repo --out /tmp/test_policy

# Verify LLM07 rules are in the generated policy
grep -A 5 "forge_validate_system_prompt_requests" /tmp/test_policy/forge_sample_vulnerable_repo.yaml
```

### Step 4: Add Unit Tests

Add tests to `tests/test_generator.py`:

```python
def test_generate_policy_with_llm07(sample_scan_result):
    """Test policy generation includes LLM07 rules."""
    # Add LLM07 finding to scan result
    sample_scan_result.call_sites.append(
        LLMCallSite(
            file="test.py",
            line=10,
            code="system_prompt = 'You are...'",
            pattern_name="hardcoded_system_prompt",
            owasp_id="LLM07",
            owasp_name="System Prompt Leakage",
            severity="HIGH",
            suggested_action="Move to config"
        )
    )
    
    policy = generate_policy(sample_scan_result)
    
    assert "LLM07" in policy["owasp_findings"]
    
    # Check ingress rules
    rule_names = [r["name"] for r in policy["ingress_rules"]]
    assert "forge_validate_system_prompt_requests" in rule_names
    
    # Check egress rules
    egress_names = [r["name"] for r in policy["egress_rules"]]
    assert "forge_block_system_prompt_leak" in egress_names
```

---

## Running the Test Suite

FORGE has 90 comprehensive tests covering all major components.

### Run All Tests

```bash
# Run full test suite
pytest tests/ -v

# Expected output: 90 passed in ~0.10s
```

### Run Specific Test Files

```bash
# Scanner tests only (29 tests)
pytest tests/test_scanner.py -v

# Generator tests only (28 tests)
pytest tests/test_generator.py -v

# BobShell audit tests only (33 tests)
pytest tests/test_audit.py -v
```

### Run Tests with Coverage

```bash
# Install coverage tool
pip install pytest-cov

# Run with coverage report
pytest tests/ --cov=src --cov-report=html

# Open coverage report
open htmlcov/index.html  # macOS
# or: xdg-open htmlcov/index.html  # Linux
```

### Run Specific Test by Name

```bash
# Run a single test
pytest tests/test_scanner.py::test_scan_detects_openai_calls -v

# Run tests matching a pattern
pytest tests/ -k "llm07" -v
```

---

## Common Troubleshooting

### Issue 1: Import Errors

**Symptom:**
```
ModuleNotFoundError: No module named 'scanner'
```

**Solution:**
```bash
# Make sure you're in the project root
cd /path/to/forge

# Ensure src/ is in Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Or run with python -m
python -m src.cli scan --repo demo/sample_vulnerable_repo
```

### Issue 2: Permission Denied on Scan

**Symptom:**
```
PermissionError: [Errno 13] Permission denied: '/some/path'
```

**Solution:**
```bash
# Check file permissions
ls -la /path/to/repo

# Ensure you have read access to the directory
chmod -R u+r /path/to/repo

# Or scan a different directory you own
python src/cli/__main__.py scan --repo ~/my-project --out ./output
```

### Issue 3: No Findings Detected

**Symptom:**
```
[FORGE] Total findings: 0
```

**Possible causes:**
1. **Wrong file extensions**: FORGE scans `.py`, `.js`, `.ts`, `.go` by default
2. **No LLM calls**: Repository doesn't use LLMs
3. **Pattern mismatch**: Code uses different LLM libraries

**Solution:**
```bash
# Check what files were scanned
python src/cli/__main__.py scan --repo /path/to/repo --out ./output 2>&1 | grep "Files scanned"

# Manually check for LLM imports
grep -r "import openai\|from langchain\|import anthropic" /path/to/repo

# Try scanning the demo repo to verify FORGE works
python src/cli/__main__.py scan --repo demo/sample_vulnerable_repo --out ./test_output
```

### Issue 4: YAML Parsing Errors

**Symptom:**
```
yaml.scanner.ScannerError: mapping values are not allowed here
```

**Solution:**
```bash
# Validate the generated YAML
python -c "import yaml; yaml.safe_load(open('forge_output/policy.yaml'))"

# Use the verify command
python src/cli/__main__.py verify --policy forge_output/policy.yaml

# Check for special characters in repo path
# Avoid paths with quotes, colons, or other YAML special chars
```

### Issue 5: Tests Failing After Changes

**Symptom:**
```
FAILED tests/test_scanner.py::test_scan_repo - AssertionError
```

**Solution:**
```bash
# Run tests with verbose output to see details
pytest tests/test_scanner.py::test_scan_repo -vv

# Check if you modified detection patterns
# Ensure test expectations match new behavior

# Run a single test in isolation
pytest tests/test_scanner.py::test_scan_repo -v --tb=short

# If you added new patterns, update test fixtures in conftest.py
```

---

## Where to Get Help

### Documentation

- **[USAGE.md](docs/USAGE.md)** — Complete usage guide with examples
- **[API.md](docs/API.md)** — Python API reference for programmatic use
- **[OWASP_MAPPING.md](docs/OWASP_MAPPING.md)** — Detailed vulnerability mapping
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — System design and architecture

### Examples

- **[examples/scan_openai_app/](examples/scan_openai_app/)** — OpenAI Flask app example
- **[examples/scan_langchain_app/](examples/scan_langchain_app/)** — LangChain agent example
- **[examples/ci_integration/](examples/ci_integration/)** — CI/CD pipeline configs

### External Resources

- **[OWASP LLM Top 10 (2025 v2)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)** — Official OWASP reference
- **[SOUF AI Documentation](https://github.com/your-org/souf-ai)** — Policy framework docs
- **[Lobster Trap](https://github.com/your-org/lobster-trap)** — Runtime enforcement engine

### Getting Support

1. **GitHub Issues**: [https://github.com/your-org/forge/issues](https://github.com/your-org/forge/issues)
   - Search existing issues first
   - Use issue templates for bug reports and feature requests
   - Include FORGE version, Python version, and OS

2. **GitHub Discussions**: [https://github.com/your-org/forge/discussions](https://github.com/your-org/forge/discussions)
   - Ask questions
   - Share use cases
   - Discuss new detection patterns

3. **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md) for:
   - Code style guidelines
   - Pull request process
   - Development workflow

---

## Next Steps

Now that you're set up, here are some ways to contribute:

### Beginner-Friendly Tasks

1. **Add detection patterns** for new LLM libraries (Cohere, AI21, etc.)
2. **Improve test coverage** for edge cases
3. **Add examples** for different frameworks (Django, FastAPI, etc.)
4. **Update documentation** with clearer explanations

### Intermediate Tasks

1. **Add support for new languages** (Java, C#, Ruby)
2. **Implement new policy actions** (TRANSFORM, SANITIZE)
3. **Create CI/CD integrations** for more platforms
4. **Optimize scan performance** for large repositories

### Advanced Tasks

1. **Integrate Watson Bob API** for enhanced analysis
2. **Build real-time monitoring dashboard**
3. **Implement policy versioning and rollback**
4. **Add automated remediation suggestions**

---

## Quick Reference Commands

```bash
# Scan a repository
python src/cli/__main__.py scan --repo /path/to/repo --out ./output

# Verify a policy file
python src/cli/__main__.py verify --policy output/policy.yaml

# Run the full demo
python src/cli/__main__.py demo

# Run tests
pytest tests/ -v

# Run specific test file
pytest tests/test_scanner.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Benchmark performance
python demo/benchmark.py

# Run demo script
bash demo/run_demo.sh
```

---

**Welcome to the FORGE community!** We're excited to have you contribute to making LLM applications more secure. If you have questions, don't hesitate to open an issue or start a discussion.

Happy scanning! 🔍🛡️