# FORGE Security Documentation

## Overview

FORGE is a security-focused tool that scans repositories for LLM vulnerabilities and generates governance policies. This document outlines the security model, guarantees, limitations, and procedures for reporting vulnerabilities.

**Version:** 1.0  
**Last Updated:** 2026-05-17

---

## Threat Model

### Assets Protected

1. **Repository Source Code**: Scanned codebases may contain sensitive information
2. **Generated Policies**: YAML policies control LLM access and must be tamper-proof
3. **Audit Trail**: BobShell logs provide compliance evidence and must be tamper-evident
4. **User System**: FORGE runs with user privileges and must not compromise the host

### Threat Actors

1. **Malicious Repository Owner**: Attempts to exploit FORGE via crafted repository content
2. **Path Traversal Attacker**: Attempts to access files outside intended scope
3. **Audit Log Tamperer**: Attempts to modify BobShell logs to hide malicious activity
4. **Resource Exhaustion Attacker**: Attempts to cause DoS via large/malicious repositories

### Attack Vectors

#### 1. Path Traversal (MITIGATED)
**Attack**: Provide paths like `../../etc/passwd` to read sensitive files  
**Mitigation**:
- All paths validated via `validate_path()` function
- Paths resolved to absolute form and checked against CWD
- Symlinks followed safely with warnings for sensitive targets
- Explicit checks prevent access outside intended directories

**Code Location**: `src/cli/__main__.py:validate_path()`

#### 2. Resource Exhaustion (MITIGATED)
**Attack**: Provide massive repositories or files to cause DoS  
**Mitigation**:
- Maximum file size: 10 MB (configurable via `MAX_FILE_SIZE_BYTES`)
- Maximum files per scan: 10,000 (configurable via `MAX_FILES_PER_SCAN`)
- Maximum scan duration: 60 seconds (configurable via `MAX_SCAN_DURATION_SECONDS`)
- Timeout handling with graceful degradation

**Code Location**: `src/scanner/repo_scanner.py`

#### 3. Audit Log Tampering (MITIGATED)
**Attack**: Modify BobShell entries to hide malicious activity  
**Mitigation**:
- Cryptographic chain linking (SHA-256)
- Hash format validation on all operations
- Timestamp validation (prevents backdating/future-dating)
- Version field for schema evolution
- Verification detects any modification

**Code Location**: `src/audit/bobshell.py`

#### 4. Malicious File Content (PARTIALLY MITIGATED)
**Attack**: Repository contains files designed to exploit regex engine  
**Mitigation**:
- Pre-compiled regex patterns (performance + safety)
- File size limits prevent catastrophic backtracking
- UTF-8 decoding with error replacement (no crashes)
- Binary files skipped automatically

**Residual Risk**: Complex regex patterns may still be vulnerable to ReDoS. Future work: use re2 library.

---

## Security Guarantees

### ✅ Strong Guarantees

1. **Path Isolation**: FORGE cannot access files outside the specified repository path (unless explicitly provided as absolute path)
2. **Tamper Evidence**: Any modification to BobShell audit logs is cryptographically detectable
3. **Resource Bounds**: Scans cannot consume unbounded memory, disk, or CPU time
4. **No Code Execution**: FORGE never executes code from scanned repositories

### ⚠️ Conditional Guarantees

1. **Timeout Enforcement**: Guaranteed on Unix-like systems (SIGALRM). On Windows, uses manual checks (less precise).
2. **Symlink Safety**: Warnings issued for symlinks to sensitive directories, but not blocked (user responsibility).

### ❌ Non-Guarantees

1. **Regex DoS**: Complex repository content may trigger slow regex matching (mitigated by file size limits)
2. **Disk Space**: FORGE does not limit output file sizes (policies are typically < 100 KB)
3. **Network Access**: FORGE does not make network requests, but this is not enforced

---

## Security Limitations

### Known Limitations

1. **Regex Engine**: Uses Python's `re` module, which is vulnerable to catastrophic backtracking. Mitigated by file size limits but not eliminated.

2. **Timestamp Validation**: Relies on system clock. If system clock is manipulated, timestamp validation may be bypassed.

3. **Windows Timeout**: On Windows, timeout enforcement uses manual checks (less precise than Unix SIGALRM).

4. **Symlink Resolution**: Symlinks are resolved and followed. Malicious symlinks could potentially access unintended files if user has permissions.

5. **Output Directory**: No validation of output directory disk space. Large scans could fill disk.

### Out of Scope

The following are explicitly **not** protected against:

1. **Compromised Python Interpreter**: If Python itself is compromised, FORGE cannot guarantee security
2. **Kernel-Level Attacks**: FORGE operates in userspace and cannot defend against kernel exploits
3. **Side-Channel Attacks**: Timing attacks, cache attacks, etc. are not mitigated
4. **Social Engineering**: FORGE cannot prevent users from running it on malicious repositories

---

## Security Features

### Input Validation (`src/cli/__main__.py`)

```python
def validate_path(path_str: str, must_exist: bool = True, 
                  must_be_dir: bool = False, must_be_file: bool = False) -> Path:
    """
    Security checks:
    - Prevents path traversal (../, absolute paths outside CWD)
    - Resolves symlinks safely
    - Validates existence and type
    - Warns about symlinks to sensitive directories
    """
```

**Usage**:
```python
repo_path = validate_path(args.repo, must_exist=True, must_be_dir=True)
```

### Resource Limits (`src/scanner/repo_scanner.py`)

```python
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_FILES_PER_SCAN = 10_000
MAX_SCAN_DURATION_SECONDS = 60
```

**Enforcement**:
- File size checked before reading
- File count checked in scan loop
- Timeout via SIGALRM (Unix) or manual check (Windows)

### Cryptographic Audit Trail (`src/audit/bobshell.py`)

```python
BOBSHELL_VERSION = "1.0"  # Schema version

def _validate_hash(hash_str: str) -> bool:
    """Validates SHA-256 hash format (64 hex chars)"""

def _validate_timestamp(timestamp: str) -> bool:
    """Validates timestamp format and prevents manipulation"""
```

**Chain Structure**:
```
Entry 0: prev_hash = GENESIS_HASH (64 zeros)
         entry_hash = SHA256(version + seq + ts + action + params + output_hash + prev_hash)

Entry N: prev_hash = Entry N-1's entry_hash
         entry_hash = SHA256(...)
```

---

## Secure Usage Guidelines

### For Users

1. **Verify Repository Source**: Only scan repositories from trusted sources
2. **Review Generated Policies**: Always review YAML policies before deploying to production
3. **Check BobShell Logs**: Verify `chain_verified: true` in audit logs
4. **Use Absolute Paths**: When scanning outside CWD, use explicit absolute paths
5. **Monitor Resource Usage**: Watch for scans that hit timeout/file limits

### For Developers

1. **Never Execute Repository Code**: FORGE is a static analyzer only
2. **Validate All Inputs**: Use `validate_path()` for all file system operations
3. **Respect Resource Limits**: Don't bypass `MAX_*` constants without security review
4. **Test Security Features**: Run security-focused tests before releases
5. **Update Dependencies**: Keep PyYAML and other dependencies patched

### For Integrators

1. **Run in Sandboxed Environment**: Consider running FORGE in containers/VMs
2. **Limit File System Access**: Use OS-level restrictions (chroot, AppArmor, SELinux)
3. **Monitor Audit Logs**: Integrate BobShell logs into SIEM systems
4. **Set Resource Limits**: Use ulimit/cgroups to enforce additional limits
5. **Validate Outputs**: Verify generated policies before deployment

---

## Vulnerability Disclosure Policy

### Reporting a Vulnerability

If you discover a security vulnerability in FORGE, please report it responsibly:

**Email**: security@forge-project.example.com  
**PGP Key**: [Available at https://forge-project.example.com/pgp]

**Please Include**:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if available)

**Do NOT**:
- Publicly disclose the vulnerability before we've had a chance to address it
- Exploit the vulnerability beyond proof-of-concept testing
- Access data that doesn't belong to you

### Response Timeline

- **24 hours**: Initial acknowledgment
- **7 days**: Preliminary assessment and severity rating
- **30 days**: Fix developed and tested (for high-severity issues)
- **90 days**: Public disclosure (coordinated with reporter)

### Severity Ratings

**Critical**: Remote code execution, arbitrary file read/write  
**High**: Path traversal, audit log bypass, DoS  
**Medium**: Information disclosure, resource exhaustion  
**Low**: Minor information leaks, non-security bugs

### Hall of Fame

We maintain a security researchers hall of fame at:  
https://forge-project.example.com/security/hall-of-fame

---

## Security Checklist for Releases

Before each release, verify:

- [ ] All input validation tests pass
- [ ] Resource limit tests pass (timeout, file size, file count)
- [ ] BobShell tamper detection tests pass
- [ ] Path traversal tests pass
- [ ] No new dependencies with known vulnerabilities
- [ ] Security documentation is up-to-date
- [ ] CHANGELOG includes security-relevant changes

---

## Compliance and Auditing

### Audit Trail Format

BobShell logs are JSON Lines format with cryptographic chain:

```json
{
  "version": "1.0",
  "seq": 0,
  "timestamp": "2026-05-17T05:00:00",
  "action": "forge_scan_start",
  "params": {"repo": "/path/to/repo"},
  "output_hash": "abc123...",
  "prev_hash": "000000...",
  "entry_hash": "def456...",
  "bob_session_id": "bob_xyz123"
}
```

### Verification

```python
from audit.bobshell import BobShell

# Load and verify
bob = BobShell()
# ... load entries ...
assert bob.verify() == True  # Chain intact
```

### Compliance Standards

FORGE audit logs support:
- **SOC 2 Type II**: Tamper-evident logging
- **ISO 27001**: Security event logging
- **GDPR**: Audit trail for data processing
- **HIPAA**: Access logging (when scanning healthcare repos)

---

## Security Updates

### Current Version: 1.0

**Security Fixes in 1.0**:
- Added path traversal prevention
- Added resource exhaustion limits
- Added cryptographic audit trail validation
- Added timestamp manipulation detection

### Planned Security Enhancements

**Version 1.1** (Q3 2026):
- [ ] Switch to `re2` library for ReDoS protection
- [ ] Add output file size limits
- [ ] Add network access monitoring
- [ ] Add sandboxing support (seccomp, pledge)

**Version 2.0** (Q1 2027):
- [ ] Add digital signatures for policies
- [ ] Add encrypted audit logs
- [ ] Add multi-party verification
- [ ] Add hardware security module (HSM) support

---

## References

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-400: Resource Exhaustion](https://cwe.mitre.org/data/definitions/400.html)
- [NIST SP 800-53: Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

---

## Contact

**Security Team**: security@forge-project.example.com  
**General Support**: support@forge-project.example.com  
**Documentation**: https://forge-project.example.com/docs

---

*This security documentation is maintained as part of the FORGE project and is updated with each release.*
