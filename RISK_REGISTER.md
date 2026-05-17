# FORGE Security Risk Register

**Generated:** 2026-05-17  
**Audit Type:** Self-Assessment (OWASP ASVS v4.0.3)  
**Scope:** FORGE codebase security vulnerabilities (not scanned repositories)

## Executive Summary

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 2 | 2 Open |
| HIGH | 5 | 4 Open, 1 Mitigated |
| MEDIUM | 4 | 4 Open |
| LOW | 2 | 2 Open |
| **TOTAL** | **13** | **12 Open, 1 Mitigated** |

---

## CRITICAL Risks

### RISK-001: ReDoS (Regular Expression Denial of Service)

**Severity:** CRITICAL  
**Category:** Resource Exhaustion  
**Status:** Open

**Description:**  
Multiple unanchored regex patterns in `LLM_CALL_PATTERNS` and `GOVERNANCE_ANTI_PATTERNS` are vulnerable to catastrophic backtracking. An attacker can craft malicious code files that cause exponential regex evaluation time, leading to DoS.

**Affected Files:**
- `src/scanner/repo_scanner.py:72-82` (fstring_injection, str_format_injection, prompt_concat patterns)
- `src/scanner/repo_scanner.py:77-81` (system_prompt patterns with `.*` and `{50,}` quantifiers)

**Reproduction:**
```python
# Create a file with nested repetition groups
malicious_code = 'f"' + 'a' * 10000 + '{user_input}' + 'b' * 10000 + '"'
# Pattern r"f['\"].*\{(user_input|...)\}" will cause catastrophic backtracking
```

**Mitigation:**
1. Add regex timeout using `re.compile(pattern, re.TIMEOUT)` (Python 3.11+) or implement manual timeout
2. Anchor patterns with `^` and `$` where appropriate
3. Replace greedy quantifiers (`.*`) with possessive/atomic groups or lazy quantifiers (`.*?`)
4. Add maximum line length check before regex evaluation (e.g., skip lines > 1000 chars)
5. Use `re.search()` with `pos` and `endpos` parameters to limit search scope

**Code Example:**
```python
# In scan_file_lines(), add before regex matching:
MAX_LINE_LENGTH = 1000
if len(line) > MAX_LINE_LENGTH:
    continue  # Skip suspiciously long lines
```

---

### RISK-002: Path Traversal in Output Directory Creation

**Severity:** CRITICAL  
**Category:** Input Validation  
**Status:** Open

**Description:**  
The `--out` CLI argument and `out_dir` parameter in `run_forge()` are not validated before directory creation. An attacker can specify paths like `../../etc/forge_malicious` to write files outside the intended directory, potentially overwriting system files or creating files in sensitive locations.

**Affected Files:**
- `src/cli/__main__.py:118-124` (cmd_scan function)
- `src/forge.py` (run_forge function - not shown but called from CLI)

**Reproduction:**
```bash
forge scan --repo /tmp/test --out "../../../tmp/malicious"
# Creates files in /tmp/malicious instead of intended location
```

**Mitigation:**
1. Use `validate_path()` function with `must_exist=False` for output directory (already partially implemented)
2. Add additional check to ensure output path is within a safe directory tree
3. Reject paths containing `..` components after resolution
4. Create output directory with restricted permissions (0o755)

**Code Fix:**
```python
# In cmd_scan(), line 121:
try:
    out_path = validate_path(out_dir, must_exist=False)
    # Additional check: ensure it's not trying to escape
    if '..' in Path(out_dir).parts:
        raise ValueError("Path traversal detected in output directory")
except ValueError as e:
    print(f"ERROR: Invalid output directory path: {e}", file=sys.stderr)
    sys.exit(1)
```

---

## HIGH Risks

### RISK-003: Weak Hash Chain Validation in BobShell

**Severity:** HIGH  
**Category:** Cryptographic Weakness  
**Status:** Mitigated

**Description:**  
While BobShell implements hash chain validation, it uses SHA-256 without additional cryptographic protections like HMAC or digital signatures. An attacker with write access to the JSONL file could recompute the entire chain with modified data. However, timestamp validation provides some protection against backdating.

**Affected Files:**
- `src/audit/bobshell.py:89-93` (_sha256 function)
- `src/audit/bobshell.py:191-231` (verify method)

**Reproduction:**
```python
# Attacker modifies entry, recomputes hashes
entry["params"]["repo_path"] = "/fake/path"
entry["output_hash"] = hashlib.sha256(modified_output).hexdigest()
# Recompute entry_hash and update chain
```

**Mitigation:**
1. ✅ **Already Implemented:** Timestamp validation prevents backdating (lines 50-86)
2. Add HMAC-SHA256 with secret key stored separately
3. Implement digital signatures using asymmetric cryptography
4. Add Merkle tree root hash for batch verification
5. Store chain root hash in separate tamper-evident location

**Status Note:** Marked as "Mitigated" due to existing timestamp validation, but recommend additional cryptographic hardening for production use.

---

### RISK-004: Unvalidated YAML Deserialization

**Severity:** HIGH  
**Category:** Input Validation  
**Status:** Open

**Description:**  
The `cmd_verify()` function uses `yaml.safe_load()` which is safe from code execution, but doesn't validate the YAML structure. Malformed or malicious YAML could cause crashes, memory exhaustion (billion laughs attack), or unexpected behavior.

**Affected Files:**
- `src/cli/__main__.py:187-188` (cmd_verify function)

**Reproduction:**
```yaml
# Billion laughs attack (YAML bomb)
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
# ... continues with exponential expansion
```

**Mitigation:**
1. Add YAML size limit before parsing (e.g., max 1MB)
2. Implement schema validation using `jsonschema` or `pydantic`
3. Set resource limits for YAML parser
4. Validate required fields and types after parsing
5. Add try-except with specific error handling

**Code Fix:**
```python
# In cmd_verify(), before yaml.safe_load():
MAX_YAML_SIZE = 1024 * 1024  # 1MB
file_size = policy_path.stat().st_size
if file_size > MAX_YAML_SIZE:
    print(f"ERROR: Policy file too large ({file_size} bytes)", file=sys.stderr)
    sys.exit(1)

try:
    with open(policy_path) as f:
        policy = yaml.safe_load(f)
except yaml.YAMLError as e:
    print(f"ERROR: Invalid YAML: {e}", file=sys.stderr)
    sys.exit(1)
```

---

### RISK-005: Information Disclosure in Error Messages

**Severity:** HIGH  
**Category:** Information Disclosure  
**Status:** Open

**Description:**  
Error messages throughout the codebase expose internal file paths, system information, and stack traces. This information aids attackers in reconnaissance and can reveal sensitive directory structures.

**Affected Files:**
- `src/cli/__main__.py:114, 123, 184` (error messages with full paths)
- `src/cli/__main__.py:105-106` (OSError/RuntimeError messages)
- `src/scanner/repo_scanner.py:266, 291, 296` (logging warnings with file counts)

**Reproduction:**
```bash
forge scan --repo /etc/passwd --out /tmp/out
# Error reveals: "ERROR: Invalid repository path: Path is not a directory: /etc/passwd"
```

**Mitigation:**
1. Sanitize error messages to remove absolute paths
2. Use generic error messages for security-sensitive operations
3. Log detailed errors to secure log file, show generic message to user
4. Implement error code system instead of descriptive messages
5. Add `--debug` flag for verbose output (disabled by default)

**Code Fix:**
```python
# In validate_path():
except (OSError, RuntimeError) as e:
    # Don't expose internal error details
    raise ValueError(f"Invalid path: {Path(path_str).name}")  # Only show filename
```

---

### RISK-006: Race Condition in Concurrent File Access

**Severity:** HIGH  
**Category:** Concurrency  
**Status:** Open

**Description:**  
The scanner uses `rglob()` to iterate files and checks `path.is_file()` separately. Between the check and read, a file could be deleted, replaced, or modified (TOCTOU - Time of Check Time of Use). This could lead to crashes or reading unintended content.

**Affected Files:**
- `src/scanner/repo_scanner.py:262-285` (scan_repo function)
- `src/scanner/repo_scanner.py:192-203` (scan_file_lines function)

**Reproduction:**
```bash
# Terminal 1: Start scan
forge scan --repo /tmp/test

# Terminal 2: During scan, delete/modify files
while true; do rm /tmp/test/file.py; touch /tmp/test/file.py; done
```

**Mitigation:**
1. Use try-except around all file operations (partially implemented)
2. Open file first, then check if it's a regular file using `os.fstat()`
3. Use file locking for critical operations
4. Add retry logic with exponential backoff
5. Validate file hasn't changed after reading (compare mtime)

**Code Fix:**
```python
# In scan_file_lines():
try:
    # Open file first to get file descriptor
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        # Check it's a regular file using the open descriptor
        import stat
        mode = os.fstat(f.fileno()).st_mode
        if not stat.S_ISREG(mode):
            return []
        text = f.read()
except (OSError, PermissionError, FileNotFoundError):
    return []
```

---

### RISK-007: Symlink Following to Sensitive Files

**Severity:** HIGH  
**Category:** Input Validation  
**Status:** Open

**Description:**  
While `validate_path()` warns about symlinks to sensitive directories, it still allows scanning them. An attacker could create symlinks in a repository pointing to `/etc/shadow`, `/root/.ssh/id_rsa`, or other sensitive files, causing FORGE to read and potentially log sensitive data.

**Affected Files:**
- `src/cli/__main__.py:94-101` (symlink warning but no blocking)
- `src/scanner/repo_scanner.py:262-285` (no symlink validation in scan loop)

**Reproduction:**
```bash
# In malicious repo:
ln -s /etc/shadow evil.py
ln -s /root/.ssh/id_rsa config.py

forge scan --repo /tmp/malicious_repo
# FORGE will read and scan these sensitive files
```

**Mitigation:**
1. Add `--follow-symlinks` flag (default: False)
2. Block scanning of symlinks to sensitive directories by default
3. Use `Path.resolve(strict=True)` and validate resolved path
4. Maintain allowlist of safe directories
5. Add `--no-follow-symlinks` option for security-conscious users

**Code Fix:**
```python
# In scan_repo(), after line 269:
if path.is_symlink():
    target = path.resolve()
    sensitive_dirs = ['/etc', '/root', '/sys', '/proc', '/dev', '/var']
    if any(str(target).startswith(d) for d in sensitive_dirs):
        logger.warning(f"Skipping symlink to sensitive location: {path}")
        continue
```

---

## MEDIUM Risks

### RISK-008: Insufficient Input Validation in BobShell.log()

**Severity:** MEDIUM  
**Category:** Input Validation  
**Status:** Open

**Description:**  
While `BobShell.log()` validates action string length (256 chars), it doesn't validate the `params` dict content. Large or deeply nested params could cause memory exhaustion or JSON serialization issues.

**Affected Files:**
- `src/audit/bobshell.py:134-189` (log method)

**Reproduction:**
```python
# Create deeply nested dict
params = {"a": {}}
current = params["a"]
for i in range(10000):
    current["b"] = {}
    current = current["b"]

bobshell.log("scan", params, "output")  # May cause stack overflow
```

**Mitigation:**
1. Add maximum depth check for nested dicts (e.g., max 10 levels)
2. Limit total params size (e.g., max 10KB when serialized)
3. Validate params keys are strings and values are JSON-serializable
4. Add recursion limit for dict traversal

**Code Fix:**
```python
# In BobShell.log(), after line 141:
def _validate_params_depth(obj, max_depth=10, current_depth=0):
    if current_depth > max_depth:
        raise ValueError(f"Params nested too deeply (max {max_depth} levels)")
    if isinstance(obj, dict):
        for v in obj.values():
            _validate_params_depth(v, max_depth, current_depth + 1)

_validate_params_depth(params)
params_json = json.dumps(params)
if len(params_json) > 10240:  # 10KB
    raise ValueError("Params too large (max 10KB)")
```

---

### RISK-009: No Rate Limiting on CLI Operations

**Severity:** MEDIUM  
**Category:** Resource Exhaustion  
**Status:** Open

**Description:**  
The CLI has no rate limiting or concurrency controls. An attacker could spawn multiple `forge scan` processes simultaneously, causing resource exhaustion (CPU, memory, disk I/O).

**Affected Files:**
- `src/cli/__main__.py:109-177` (cmd_scan function)
- `src/scanner/repo_scanner.py:232-312` (scan_repo function)

**Reproduction:**
```bash
# Spawn 100 concurrent scans
for i in {1..100}; do
    forge scan --repo /large/repo --out /tmp/out$i &
done
# System becomes unresponsive
```

**Mitigation:**
1. Implement file-based locking to limit concurrent scans (e.g., max 3)
2. Add `--max-workers` flag with default limit
3. Use process pool with size limit
4. Add memory usage monitoring and abort if threshold exceeded
5. Implement exponential backoff for failed operations

**Code Fix:**
```python
# Add to cmd_scan():
import fcntl
LOCK_FILE = Path.home() / ".forge.lock"
try:
    lock_fd = open(LOCK_FILE, 'w')
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except IOError:
    print("ERROR: Another FORGE scan is running. Please wait.", file=sys.stderr)
    sys.exit(1)
```

---

### RISK-010: Dependency Confusion / Supply Chain Attack

**Severity:** MEDIUM  
**Category:** Supply Chain  
**Status:** Open

**Description:**  
`requirements.txt` only specifies `PyYAML>=6.0` without upper bound or hash pinning. An attacker could publish a malicious PyYAML version (e.g., 7.0) that gets installed, compromising FORGE and all scanned repositories.

**Affected Files:**
- `requirements.txt:1` (unpinned dependency)

**Reproduction:**
```bash
# Attacker publishes malicious PyYAML 7.0
pip install PyYAML  # Installs compromised version
forge scan --repo /sensitive/repo  # Malicious code executes
```

**Mitigation:**
1. Pin exact versions: `PyYAML==6.0.1`
2. Add hash verification: `PyYAML==6.0.1 --hash=sha256:...`
3. Use `pip-audit` in CI/CD to check for vulnerabilities
4. Add `requirements-lock.txt` with all transitive dependencies
5. Use `pip-tools` for dependency management

**Code Fix:**
```txt
# requirements.txt:
PyYAML==6.0.1 \
    --hash=sha256:062582fca9fabdd2c8b54a3ef1c978d786e0f6b3a1510e0ac93ef59e0ddae2bc
```

---

### RISK-011: Uncontrolled Resource Consumption in File Reading

**Severity:** MEDIUM  
**Category:** Resource Exhaustion  
**Status:** Open

**Description:**  
While `MAX_FILE_SIZE_BYTES` is set to 10MB, the scanner reads entire files into memory. Scanning a repository with many large files (e.g., 1000 files × 10MB = 10GB) could exhaust memory.

**Affected Files:**
- `src/scanner/repo_scanner.py:192-203` (scan_file_lines reads entire file)
- `src/scanner/repo_scanner.py:279` (reads file again for line count)

**Reproduction:**
```bash
# Create repo with 1000 × 10MB files
for i in {1..1000}; do
    dd if=/dev/zero of=file$i.py bs=1M count=10
done
forge scan --repo /tmp/large_repo  # Memory exhaustion
```

**Mitigation:**
1. Implement streaming/chunked file reading
2. Add total memory usage limit (e.g., max 1GB)
3. Process files in batches with memory cleanup
4. Use memory-mapped files for large files
5. Add `--max-memory` CLI flag

**Code Fix:**
```python
# In scan_file_lines(), replace read_text() with streaming:
def scan_file_lines_streaming(file_path, patterns, compiled, max_size_bytes):
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f, 1):
                if i > 100000:  # Max lines per file
                    break
                # Process line...
    except Exception:
        return []
    return findings
```

---

## LOW Risks

### RISK-012: Weak Session ID Generation

**Severity:** LOW  
**Category:** Cryptographic Weakness  
**Status:** Open

**Description:**  
BobShell session IDs use `uuid.uuid4().hex[:12]` (48 bits of entropy). While sufficient for non-security-critical session tracking, it's predictable and could be brute-forced for session hijacking if exposed.

**Affected Files:**
- `src/audit/bobshell.py:128-129` (session_id generation)

**Reproduction:**
```python
# Predict session IDs
import uuid
for _ in range(1000000):
    sid = f"bob_{uuid.uuid4().hex[:12]}"
    # Try to access session
```

**Mitigation:**
1. Use full UUID (128 bits): `uuid.uuid4().hex`
2. Add timestamp prefix for uniqueness: `f"bob_{int(time.time())}_{uuid.uuid4().hex}"`
3. Use `secrets.token_hex(16)` for cryptographically secure random
4. Add session expiration mechanism

**Code Fix:**
```python
# In BobShell.__init__():
import secrets
self.session_id = session_id or f"bob_{secrets.token_hex(16)}"
```

---

### RISK-013: Verbose Logging Exposes Internal State

**Severity:** LOW  
**Category:** Information Disclosure  
**Status:** Open

**Description:**  
The scanner logs warnings with file counts and duration when limits are exceeded. This information helps attackers understand FORGE's resource limits and craft attacks to stay under detection thresholds.

**Affected Files:**
- `src/scanner/repo_scanner.py:266` (max files warning)
- `src/scanner/repo_scanner.py:291, 296` (timeout warnings)

**Reproduction:**
```bash
forge scan --repo /large/repo 2>&1 | grep "exceeded"
# Output: "Scan stopped: exceeded max files limit (10000)"
# Attacker learns: "I need to keep malicious repo under 10000 files"
```

**Mitigation:**
1. Use generic warning messages: "Scan limit reached"
2. Log detailed info only in debug mode
3. Add `--quiet` flag to suppress warnings
4. Rate-limit warning messages to prevent information leakage
5. Log to secure file instead of stdout

**Code Fix:**
```python
# In scan_repo(), line 266:
logging.warning("Scan stopped: resource limit reached")  # Generic message
logging.debug(f"Exceeded max files limit ({max_files})")  # Detailed in debug
```

---

## Recommendations

### Immediate Actions (Critical/High)
1. **RISK-001**: Implement regex timeout and line length limits
2. **RISK-002**: Strengthen output path validation
3. **RISK-004**: Add YAML size limits and schema validation
4. **RISK-005**: Sanitize all error messages
5. **RISK-007**: Block symlinks to sensitive directories by default

### Short-term Actions (Medium)
6. **RISK-008**: Add params validation in BobShell
7. **RISK-009**: Implement concurrent scan limiting
8. **RISK-010**: Pin dependencies with hashes
9. **RISK-011**: Implement streaming file reading

### Long-term Actions (Low + Enhancements)
10. **RISK-003**: Add HMAC or digital signatures to BobShell
11. **RISK-012**: Use cryptographically secure session IDs
12. **RISK-013**: Implement proper logging levels
13. Add comprehensive input fuzzing tests
14. Implement security-focused CI/CD pipeline
15. Conduct third-party security audit

---

## Compliance Notes

This risk register follows OWASP ASVS v4.0.3 categories:
- **V5**: Validation, Sanitization and Encoding
- **V8**: Data Protection
- **V9**: Communication
- **V10**: Malicious Code
- **V14**: Configuration

All risks should be reviewed and accepted/mitigated before production deployment.

---

**Document Version:** 1.0  
**Last Updated:** 2026-05-17  
**Next Review:** 2026-06-17