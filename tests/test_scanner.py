"""
Unit tests for FORGE Scanner (repo_scanner.py).

Tests cover:
- Empty repository scanning
- Detection of various LLM SDK calls (OpenAI, Anthropic, LangChain)
- OWASP vulnerability pattern detection
- Binary file and directory skipping
- Large file handling
- Edge cases
"""
import pytest
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scanner.repo_scanner import (
    scan_repo,
    scan_file_lines,
    _should_skip,
    _severity,
    _suggested_action,
    ScanResult,
    LLMCallSite,
    OWASP_LLM,
    LLM_CALL_PATTERNS,
    GOVERNANCE_ANTI_PATTERNS,
)
import re


class TestScannerUtilityFunctions:
    """Test utility functions in repo_scanner."""
    
    def test_should_skip_git_directory(self, tmp_path):
        """Test that .git directories are skipped."""
        git_path = tmp_path / ".git" / "config"
        assert _should_skip(git_path) is True
    
    def test_should_skip_pycache(self, tmp_path):
        """Test that __pycache__ directories are skipped."""
        cache_path = tmp_path / "__pycache__" / "module.pyc"
        assert _should_skip(cache_path) is True
    
    def test_should_skip_node_modules(self, tmp_path):
        """Test that node_modules directories are skipped."""
        node_path = tmp_path / "node_modules" / "package" / "index.js"
        assert _should_skip(node_path) is True
    
    def test_should_skip_binary_extensions(self, tmp_path):
        """Test that binary file extensions are skipped."""
        assert _should_skip(tmp_path / "image.png") is True
        assert _should_skip(tmp_path / "data.bin") is True
        assert _should_skip(tmp_path / "lib.so") is True
        assert _should_skip(tmp_path / "archive.zip") is True
    
    def test_should_not_skip_source_files(self, tmp_path):
        """Test that source files are not skipped."""
        assert _should_skip(tmp_path / "app.py") is False
        assert _should_skip(tmp_path / "script.js") is False
        assert _should_skip(tmp_path / "component.ts") is False
    
    def test_severity_high_for_critical_owasp(self):
        """Test that critical OWASP categories get HIGH severity."""
        assert _severity("LLM01", "any") == "HIGH"
        assert _severity("LLM02", "any") == "HIGH"
        assert _severity("LLM06", "any") == "HIGH"
        assert _severity("LLM08", "any") == "HIGH"
    
    def test_severity_high_for_critical_patterns(self):
        """Test that critical patterns get HIGH severity."""
        assert _severity("LLM05", "hardcoded_api_key") == "HIGH"
        assert _severity("LLM05", "pii_in_prompt_template") == "HIGH"
    
    def test_severity_medium_for_dos_supply_chain(self):
        """Test that LLM04/LLM05 get MEDIUM severity."""
        assert _severity("LLM04", "any") == "MEDIUM"
        assert _severity("LLM05", "any") == "MEDIUM"
    
    def test_severity_low_for_others(self):
        """Test that other categories get LOW severity."""
        assert _severity("LLM09", "any") == "LOW"
        assert _severity("LLM10", "any") == "LOW"
    
    def test_suggested_action_for_llm01(self):
        """Test suggested action for prompt injection."""
        action = _suggested_action("LLM01")
        assert "SOUF AI" in action
        assert "input sanitisation" in action.lower()
    
    def test_suggested_action_for_llm06(self):
        """Test suggested action for credential exposure."""
        action = _suggested_action("LLM06")
        assert "env vars" in action.lower()
        assert "PII filter" in action


class TestScanFileLines:
    """Test the scan_file_lines function."""
    
    def test_scan_detects_openai_sdk(self, tmp_path):
        """Test detection of OpenAI SDK calls."""
        test_file = tmp_path / "test.py"
        test_file.write_text('''
import openai
response = openai.ChatCompletion.create(model="gpt-4")
''')
        
        patterns = [(p[0], p[1], p[2]) for p in LLM_CALL_PATTERNS]
        compiled = [re.compile(p[0]) for p in LLM_CALL_PATTERNS]
        
        findings = scan_file_lines(test_file, patterns, compiled)
        
        assert len(findings) > 0
        assert any(f.pattern_name == "openai_sdk" for f in findings)
        assert any(f.owasp_id == "LLM02" for f in findings)
    
    def test_scan_detects_fstring_injection(self, tmp_path):
        """Test detection of f-string prompt injection."""
        test_file = tmp_path / "test.py"
        test_file.write_text('''
def process(user_input):
    prompt = f"Summarize: {user_input}"
    return llm.complete(prompt)
''')
        
        patterns = [(p[0], p[1], p[2]) for p in LLM_CALL_PATTERNS]
        compiled = [re.compile(p[0]) for p in LLM_CALL_PATTERNS]
        
        findings = scan_file_lines(test_file, patterns, compiled)
        
        assert len(findings) > 0
        assert any(f.pattern_name == "fstring_injection" for f in findings)
        assert any(f.owasp_id == "LLM01" for f in findings)
    
    def test_scan_detects_hardcoded_api_key(self, tmp_path):
        """Test detection of hardcoded API keys."""
        test_file = tmp_path / "config.py"
        test_file.write_text('''
api_key = "sk-proj-abc123xyz789abcdefghijklmnop"
''')
        
        patterns = [(p[0], p[1], p[2]) for p in GOVERNANCE_ANTI_PATTERNS]
        compiled = [re.compile(p[0]) for p in GOVERNANCE_ANTI_PATTERNS]
        
        findings = scan_file_lines(test_file, patterns, compiled)
        
        assert len(findings) > 0
        assert any(f.pattern_name == "hardcoded_api_key" for f in findings)
        assert any(f.owasp_id == "LLM06" for f in findings)
    
    def test_scan_handles_invalid_utf8(self, tmp_path):
        """Test that scanner handles files with invalid UTF-8."""
        test_file = tmp_path / "binary.py"
        test_file.write_bytes(b'\x80\x81\x82\x83')
        
        patterns = [(p[0], p[1], p[2]) for p in LLM_CALL_PATTERNS]
        compiled = [re.compile(p[0]) for p in LLM_CALL_PATTERNS]
        
        # Should not crash, should return empty list
        findings = scan_file_lines(test_file, patterns, compiled)
        assert findings == []


class TestScanRepo:
    """Test the main scan_repo function."""
    
    def test_scan_empty_repo(self, empty_repo):
        """Test scanning an empty repository."""
        result = scan_repo(str(empty_repo))
        
        assert isinstance(result, ScanResult)
        assert result.total_files_scanned == 0
        assert result.total_findings == 0
        assert len(result.call_sites) == 0
        assert len(result.governance_gaps) == 0
    
    def test_scan_repo_with_openai(self, repo_with_openai):
        """Test scanning a repository with OpenAI calls."""
        result = scan_repo(str(repo_with_openai))
        
        assert result.total_files_scanned >= 2
        assert result.total_findings > 0
        
        # Should detect OpenAI SDK call
        assert any(cs.pattern_name == "openai_sdk" for cs in result.call_sites)
        
        # Should detect f-string injection
        assert any(cs.owasp_id == "LLM01" for cs in result.call_sites)
        
        # Should detect hardcoded API key
        assert any(gg.pattern_name == "hardcoded_api_key" for gg in result.governance_gaps)
        assert any(gg.owasp_id == "LLM06" for gg in result.governance_gaps)
    
    def test_scan_repo_with_anthropic(self, repo_with_anthropic):
        """Test scanning a repository with Anthropic calls."""
        result = scan_repo(str(repo_with_anthropic))
        
        assert result.total_findings > 0
        
        # Should detect Anthropic client
        assert any(cs.pattern_name in ["anthropic_client", "anthropic_messages_create"] 
                   for cs in result.call_sites)
    
    def test_scan_repo_with_langchain(self, repo_with_langchain):
        """Test scanning a repository with LangChain usage."""
        result = scan_repo(str(repo_with_langchain))
        
        assert result.total_findings > 0
        
        # Should detect LangChain import (LLM05)
        assert any(cs.owasp_id == "LLM05" for cs in result.call_sites)
        
        # Should detect unsafe code execution (LLM08)
        assert any(gg.owasp_id == "LLM08" for gg in result.governance_gaps)
    
    def test_scan_repo_with_multiple_vulnerabilities(self, repo_with_vulnerabilities):
        """Test scanning a repository with multiple vulnerability types."""
        result = scan_repo(str(repo_with_vulnerabilities))
        
        owasp_found = set(result.by_owasp().keys())
        
        # Should detect multiple OWASP categories
        assert "LLM01" in owasp_found  # Prompt injection
        assert "LLM02" in owasp_found  # Insecure output
        assert "LLM04" in owasp_found  # DoS
        assert "LLM05" in owasp_found  # Supply chain
        assert "LLM06" in owasp_found  # Credential exposure
        assert "LLM08" in owasp_found  # Excessive agency
        
        # Verify severity distribution
        summary = result.summary()
        assert summary["severity_breakdown"]["HIGH"] > 0
    
    def test_scan_skips_binary_files(self, repo_with_binary_files):
        """Test that binary files and excluded directories are skipped."""
        result = scan_repo(str(repo_with_binary_files))
        
        # Should only scan app.py, not binary files or node_modules
        assert result.total_files_scanned == 1
        
        # Should still detect the LLM call in app.py
        assert result.total_findings > 0
    
    def test_scan_handles_large_files(self, repo_with_large_file):
        """Test scanning large files with many findings."""
        result = scan_repo(str(repo_with_large_file))
        
        # Should scan the large file
        assert result.total_files_scanned >= 1
        assert result.total_lines_scanned > 1000
        
        # Should detect multiple findings
        assert result.total_findings > 10
    
    def test_scan_result_by_owasp_grouping(self, repo_with_vulnerabilities):
        """Test that by_owasp() correctly groups findings."""
        result = scan_repo(str(repo_with_vulnerabilities))
        
        by_owasp = result.by_owasp()
        
        # Verify grouping
        assert isinstance(by_owasp, dict)
        for owasp_id, findings in by_owasp.items():
            assert all(f.owasp_id == owasp_id for f in findings)
    
    def test_scan_result_summary(self, repo_with_vulnerabilities):
        """Test that summary() produces correct statistics."""
        result = scan_repo(str(repo_with_vulnerabilities))
        
        summary = result.summary()
        
        # Verify summary structure
        assert "repo" in summary
        assert "scan_time_ms" in summary
        assert "files_scanned" in summary
        assert "lines_scanned" in summary
        assert "call_sites" in summary
        assert "governance_gaps" in summary
        assert "total_findings" in summary
        assert "owasp_breakdown" in summary
        assert "severity_breakdown" in summary
        
        # Verify counts match
        assert summary["total_findings"] == result.total_findings
        assert summary["call_sites"] == len(result.call_sites)
        assert summary["governance_gaps"] == len(result.governance_gaps)
    
    def test_scan_performance(self, repo_with_vulnerabilities):
        """Test that scanning completes in reasonable time."""
        result = scan_repo(str(repo_with_vulnerabilities))
        
        # Should complete in under 1 second for small repos
        assert result.scan_time_ms < 1000


class TestLLMCallSite:
    """Test the LLMCallSite dataclass."""
    
    def test_llm_call_site_creation(self):
        """Test creating an LLMCallSite object."""
        site = LLMCallSite(
            file="/test/app.py",
            line=42,
            code='prompt = f"Test: {input}"',
            pattern_name="fstring_injection",
            owasp_id="LLM01",
            owasp_name="Prompt Injection",
            severity="HIGH",
            suggested_action="Add input sanitisation"
        )
        
        assert site.file == "/test/app.py"
        assert site.line == 42
        assert site.owasp_id == "LLM01"
        assert site.severity == "HIGH"


class TestScanResultDataclass:
    """Test the ScanResult dataclass."""
    
    def test_scan_result_total_findings(self):
        """Test that total_findings property works correctly."""
        result = ScanResult(
            repo_path="/test",
            scan_time_ms=100.0,
            total_files_scanned=5,
            total_lines_scanned=500,
            call_sites=[
                LLMCallSite("/test/a.py", 1, "code", "p1", "LLM01", "name", "HIGH", "action"),
                LLMCallSite("/test/b.py", 2, "code", "p2", "LLM02", "name", "HIGH", "action"),
            ],
            governance_gaps=[
                LLMCallSite("/test/c.py", 3, "code", "p3", "LLM06", "name", "HIGH", "action"),
            ]
        )
        
        assert result.total_findings == 3
        assert result.total_findings == len(result.call_sites) + len(result.governance_gaps)


class TestOWASPMapping:
    """Test OWASP LLM Top 10 mapping."""
    
    def test_owasp_llm_dict_complete(self):
        """Test that OWASP_LLM dict has all 10 categories."""
        assert len(OWASP_LLM) == 10
        
        for i in range(1, 11):
            owasp_id = f"LLM{i:02d}"
            assert owasp_id in OWASP_LLM
            assert isinstance(OWASP_LLM[owasp_id], str)
            assert len(OWASP_LLM[owasp_id]) > 0
    
    def test_pattern_owasp_mapping_valid(self):
        """Test that all patterns map to valid OWASP IDs."""
        all_patterns = LLM_CALL_PATTERNS + GOVERNANCE_ANTI_PATTERNS
        
        for pattern_tuple in all_patterns:
            owasp_id = pattern_tuple[2]
            assert owasp_id in OWASP_LLM, f"Invalid OWASP ID: {owasp_id}"
