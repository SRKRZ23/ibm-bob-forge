# Changelog

All notable changes to FORGE will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-17

### Added

#### Core Architecture & Documentation
- **ARCHITECTURE.md** - Comprehensive system architecture documentation covering:
  - Component design (Scanner, Generator, BobShell, CLI)
  - Data flow and processing pipeline
  - Security model and threat analysis
  - Technology stack and dependencies
  - Design decisions and trade-offs

#### Security Hardening
- **Input Validation** (`src/cli/__main__.py`):
  - `validate_path()` function with path traversal prevention
  - Symlink safety checks
  - Absolute path resolution
  - Protection against directory traversal attacks (e.g., `../../../etc/passwd`)

- **Resource Limits** (`src/scanner/repo_scanner.py`):
  - `MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024` (10MB per file)
  - `MAX_FILES_PER_SCAN = 10000` (maximum files to scan)
  - `MAX_SCAN_DURATION_SECONDS = 60` (scan timeout)
  - Enforcement with warnings when limits exceeded

- **Cryptographic Improvements** (`src/audit/bobshell.py`):
  - `_validate_hash()` - SHA-256 hash validation
  - `_validate_timestamp()` - ISO 8601 timestamp validation
  - `BOBSHELL_VERSION = "1.0"` - Version field for audit entries
  - Enhanced `log()` method with input validation
  - Enhanced `verify()` method with comprehensive chain validation

- **SECURITY.md** - Comprehensive security documentation:
  - Threat model and attack surface analysis
  - Security guarantees and limitations
  - Vulnerability disclosure policy
  - Security best practices for users

#### Test Suite
- **90 comprehensive unit tests** across 3 test files:
  - `tests/test_scanner.py` - 29 tests for repository scanning
  - `tests/test_generator.py` - 28 tests for policy generation
  - `tests/test_audit.py` - 33 tests for BobShell audit logging
  - `tests/conftest.py` - Shared test fixtures
  - `pyproject.toml` - Pytest configuration
  - **100% backward compatible** - All tests pass without modifying existing code

#### Comprehensive Documentation (60K+ content)
- **docs/USAGE.md** (12K) - Complete usage guide:
  - Installation instructions
  - First scan walkthrough with 3 real command examples
  - Interpreting scan results and policy output
  - CI/CD integration (GitHub Actions, GitLab CI, Jenkins, pre-commit hooks)
  - Troubleshooting guide
  - Advanced usage patterns

- **docs/API.md** (23K) - Python API reference:
  - `scan_repo()` API with 4 code examples
  - `generate_policy()` API with 4 code examples
  - `BobShell` class API with 4 code examples
  - 3 complete integration examples (full pipeline, batch scanning, CI/CD)
  - Error handling patterns
  - Best practices

- **docs/OWASP_MAPPING.md** (25K) - Detailed OWASP LLM Top 10 mapping:
  - Complete coverage: LLM01, LLM02, LLM04, LLM05, LLM06, LLM08
  - Detection patterns → YAML policy rules → Lobster Trap actions
  - Vulnerable code examples with secure remediation for each category
  - Quick reference table and policy generation matrix
  - Lobster Trap action reference

#### Working Examples (3 directories, 14 files)
- **examples/scan_openai_app/** - OpenAI Flask application:
  - `app.py` - Vulnerable application with 8 security issues
  - `requirements.txt` - Unpinned dependencies
  - `expected_scan_output.txt` - Detailed scan results
  - `forge_scan_openai_app.yaml` - Generated SOUF AI policy
  - `README.md` - Usage and testing instructions

- **examples/scan_langchain_app/** - LangChain agent:
  - `agent.py` - Vulnerable agent with 10 security issues
  - `requirements.txt` - Unpinned dependencies
  - `expected_scan_output.txt` - Detailed scan results
  - `forge_scan_langchain_app.yaml` - Generated SOUF AI policy
  - `README.md` - Usage and testing instructions

- **examples/ci_integration/** - CI/CD pipeline configurations:
  - `.github/workflows/forge-scan.yml` - GitHub Actions workflow
  - `.gitlab-ci.yml` - GitLab CI pipeline
  - `Jenkinsfile` - Jenkins declarative pipeline
  - `pre-commit-hook.sh` - Local git pre-commit hook
  - `README.md` - Integration guide and best practices

#### Demo & Benchmarking
- **demo/sample_vulnerable_repo/** - Intentionally vulnerable repository:
  - `app.py` - Flask app with 15+ vulnerabilities
  - `agent.py` - LangChain agent with unrestricted tools
  - `config.py` - Hardcoded credentials and secrets
  - `requirements.txt` - Unpinned dependencies
  - `README.md` - Documentation of vulnerabilities

- **demo/run_demo.sh** - End-to-end demo script:
  - Automated scan → policy generation → audit verification workflow
  - Colored terminal output with progress indicators
  - Comprehensive demo report generation
  - Exit codes for CI/CD integration

- **demo/benchmark.py** - Performance benchmarking tool:
  - Measures scan time, policy generation time, audit logging time
  - Calculates throughput metrics (files/sec, lines/sec)
  - Generates detailed performance report
  - JSON output for automated analysis

#### README Updates
- Added comprehensive documentation section with links to:
  - All 3 core documentation files
  - All 3 example directories
  - Getting started guide for different user types (first-time users, developers, security teams, DevOps)

### Changed
- Enhanced CLI with path validation before scanning
- Improved error messages with actionable guidance
- Scanner now enforces resource limits with clear warnings

### Security
- All security improvements are **backward compatible**
- No breaking changes to existing APIs
- All 90 tests pass without modifications to test suite
- Input validation prevents path traversal attacks
- Resource limits prevent DoS attacks
- Cryptographic validation ensures audit log integrity

### Testing
- **Test Coverage**: 90 tests covering all major components
- **Test Results**: 100% pass rate (90/90 tests passing)
- **Test Duration**: ~0.10s total execution time
- **Backward Compatibility**: All tests pass without code changes

### Documentation
- **Total Documentation**: 60,000+ bytes across 6 markdown files
- **Code Examples**: 20+ working code examples
- **CI/CD Examples**: 4 complete pipeline configurations
- **Vulnerability Examples**: 15+ intentional vulnerabilities for testing

### Performance
- Scan performance: ~50ms for small repositories
- Policy generation: <10ms
- Audit logging: <5ms per entry
- Total pipeline: <100ms for typical repositories

---

## [Unreleased]

### Planned
- Integration with Watson Bob API for enhanced codebase understanding
- Support for additional programming languages (Java, C#, Ruby)
- Real-time monitoring dashboard
- Policy versioning and rollback
- Automated remediation suggestions

---

*For more information, see [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md)*
