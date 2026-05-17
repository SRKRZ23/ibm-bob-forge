"""
Unit tests for FORGE Policy Generator (policy_generator.py).

Tests cover:
- Policy generation for each OWASP category
- YAML output structure validation
- Rate limit configuration
- Rule deduplication
- Strict mode behavior
"""
import pytest
import yaml
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from generator.policy_generator import (
    generate_policy,
    policy_to_yaml,
    _deduplicate_rules,
    OWASP_INGRESS_RULES,
    EGRESS_RULES_BASE,
)
from scanner.repo_scanner import ScanResult, LLMCallSite


class TestPolicyGeneration:
    """Test the main generate_policy function."""
    
    def test_generate_policy_basic(self, sample_scan_result):
        """Test basic policy generation from scan results."""
        policy = generate_policy(sample_scan_result)
        
        # Verify basic structure
        assert "version" in policy
        assert policy["version"] == "1.0"
        assert "policy_name" in policy
        assert "generated_by" in policy
        assert policy["generated_by"] == "FORGE v1.0"
        assert "generated_at" in policy
        assert "source_repo" in policy
        assert "owasp_findings" in policy
        assert "default_action" in policy
        assert policy["default_action"] == "ALLOW"
    
    def test_generate_policy_includes_detected_owasp(self, sample_scan_result):
        """Test that policy includes detected OWASP categories."""
        policy = generate_policy(sample_scan_result)
        
        owasp_findings = policy["owasp_findings"]
        assert "LLM01" in owasp_findings
        assert "LLM02" in owasp_findings
        assert "LLM06" in owasp_findings
        assert isinstance(owasp_findings, list)
        assert owasp_findings == sorted(owasp_findings)  # Should be sorted
    
    def test_generate_policy_has_ingress_rules(self, sample_scan_result):
        """Test that policy includes ingress rules."""
        policy = generate_policy(sample_scan_result)
        
        assert "ingress_rules" in policy
        assert isinstance(policy["ingress_rules"], list)
        assert len(policy["ingress_rules"]) > 0
        
        # Verify rule structure
        for rule in policy["ingress_rules"]:
            assert "name" in rule
            assert "description" in rule
            assert "priority" in rule
            assert "action" in rule
            assert "conditions" in rule
            assert isinstance(rule["conditions"], list)
    
    def test_generate_policy_has_egress_rules(self, sample_scan_result):
        """Test that policy includes egress rules."""
        policy = generate_policy(sample_scan_result)
        
        assert "egress_rules" in policy
        assert isinstance(policy["egress_rules"], list)
        assert len(policy["egress_rules"]) > 0
        
        # Should include baseline egress rules
        rule_names = [r["name"] for r in policy["egress_rules"]]
        assert "forge_block_credential_leak" in rule_names
        assert "forge_block_pii_output" in rule_names
    
    def test_generate_policy_has_rate_limits(self, sample_scan_result):
        """Test that policy includes rate limit configuration."""
        policy = generate_policy(sample_scan_result)
        
        assert "rate_limits" in policy
        rate_limits = policy["rate_limits"]
        
        assert "requests_per_minute" in rate_limits
        assert "requests_per_hour" in rate_limits
        assert "burst_threshold" in rate_limits
        
        assert isinstance(rate_limits["requests_per_minute"], int)
        assert rate_limits["requests_per_minute"] > 0
    
    def test_generate_policy_has_network_config(self, sample_scan_result):
        """Test that policy includes network configuration."""
        policy = generate_policy(sample_scan_result)
        
        assert "network" in policy
        network = policy["network"]
        
        assert "egress_policy" in network
        assert network["egress_policy"] == "allowlist"
        assert "allowed_domains" in network
        assert "denied_domains" in network
        assert isinstance(network["allowed_domains"], list)
        assert isinstance(network["denied_domains"], list)
    
    def test_generate_policy_has_filesystem_config(self, sample_scan_result):
        """Test that policy includes filesystem configuration."""
        policy = generate_policy(sample_scan_result)
        
        assert "filesystem" in policy
        filesystem = policy["filesystem"]
        
        assert "denied_paths" in filesystem
        assert "allowed_read_paths" in filesystem
        assert "allowed_write_paths" in filesystem
        
        # Should deny sensitive paths
        denied = filesystem["denied_paths"]
        assert any("/etc/" in p for p in denied)
        assert any(".ssh" in p for p in denied)
        assert any(".env" in p for p in denied)


class TestOWASPSpecificRules:
    """Test policy generation for specific OWASP categories."""
    
    def test_llm01_prompt_injection_rules(self):
        """Test that LLM01 findings generate prompt injection rules."""
        scan = ScanResult(
            repo_path="/test",
            scan_time_ms=100.0,
            total_files_scanned=1,
            total_lines_scanned=50,
            call_sites=[
                LLMCallSite(
                    file="/test/app.py",
                    line=10,
                    code='prompt = f"Test: {user_input}"',
                    pattern_name="fstring_injection",
                    owasp_id="LLM01",
                    owasp_name="Prompt Injection",
                    severity="HIGH",
                    suggested_action="Add input sanitisation"
                )
            ],
            governance_gaps=[]
        )
        
        policy = generate_policy(scan)
        
        # Should include LLM01 rules
        rule_names = [r["name"] for r in policy["ingress_rules"]]
        assert "forge_block_prompt_injection" in rule_names
        assert "forge_review_role_override" in rule_names
    
    def test_llm02_output_handling_rules(self):
        """Test that LLM02 findings generate output validation rules."""
        scan = ScanResult(
            repo_path="/test",
            scan_time_ms=100.0,
            total_files_scanned=1,
            total_lines_scanned=50,
            call_sites=[
                LLMCallSite(
                    file="/test/app.py",
                    line=10,
                    code='return response.content',
                    pattern_name="raw_output_use",
                    owasp_id="LLM02",
                    owasp_name="Insecure Output Handling",
                    severity="HIGH",
                    suggested_action="Add output validation"
                )
            ],
            governance_gaps=[]
        )
        
        policy = generate_policy(scan)
        
        # Should include LLM02 rules
        rule_names = [r["name"] for r in policy["ingress_rules"]]
        assert "forge_log_llm_output_requests" in rule_names
    
    def test_llm04_dos_reduces_rate_limits(self):
        """Test that LLM04 findings reduce rate limits."""
        scan = ScanResult(
            repo_path="/test",
            scan_time_ms=100.0,
            total_files_scanned=1,
            total_lines_scanned=50,
            call_sites=[
                LLMCallSite(
                    file="/test/app.py",
                    line=10,
                    code='while True: llm.complete(...)',
                    pattern_name="unbounded_loop_llm",
                    owasp_id="LLM04",
                    owasp_name="Model Denial of Service",
                    severity="MEDIUM",
                    suggested_action="Add rate limiting"
                )
            ],
            governance_gaps=[]
        )
        
        policy = generate_policy(scan)
        
        # Should have reduced rate limits
        assert policy["rate_limits"]["requests_per_minute"] == 30
        
        # Should include rate limit rule
        rule_names = [r["name"] for r in policy["ingress_rules"]]
        assert "forge_rate_limit_high_risk" in rule_names
    
    def test_llm05_supply_chain_rules(self):
        """Test that LLM05 findings generate supply chain rules."""
        scan = ScanResult(
            repo_path="/test",
            scan_time_ms=100.0,
            total_files_scanned=1,
            total_lines_scanned=50,
            call_sites=[
                LLMCallSite(
                    file="/test/app.py",
                    line=10,
                    code='from langchain import *',
                    pattern_name="langchain_import",
                    owasp_id="LLM05",
                    owasp_name="Supply Chain Vulnerabilities",
                    severity="MEDIUM",
                    suggested_action="Pin dependency versions"
                )
            ],
            governance_gaps=[]
        )
        
        policy = generate_policy(scan)
        
        # Should include LLM05 rules
        rule_names = [r["name"] for r in policy["ingress_rules"]]
        assert "forge_block_supply_chain_paths" in rule_names
    
    def test_llm06_credential_exposure_rules(self):
        """Test that LLM06 findings generate credential protection rules."""
        scan = ScanResult(
            repo_path="/test",
            scan_time_ms=100.0,
            total_files_scanned=1,
            total_lines_scanned=50,
            call_sites=[],
            governance_gaps=[
                LLMCallSite(
                    file="/test/config.py",
                    line=5,
                    code='API_KEY = "sk-proj-abc123"',
                    pattern_name="hardcoded_api_key",
                    owasp_id="LLM06",
                    owasp_name="Sensitive Information Disclosure",
                    severity="HIGH",
                    suggested_action="Move to env vars"
                )
            ]
        )
        
        policy = generate_policy(scan)
        
        # Should include LLM06 rules
        rule_names = [r["name"] for r in policy["ingress_rules"]]
        assert "forge_block_credential_access" in rule_names
    
    def test_llm08_excessive_agency_rules(self):
        """Test that LLM08 findings generate agentic control rules."""
        scan = ScanResult(
            repo_path="/test",
            scan_time_ms=100.0,
            total_files_scanned=1,
            total_lines_scanned=50,
            call_sites=[],
            governance_gaps=[
                LLMCallSite(
                    file="/test/agent.py",
                    line=10,
                    code='subprocess.run(cmd, shell=True)',
                    pattern_name="unsafe_code_exec",
                    owasp_id="LLM08",
                    owasp_name="Excessive Agency",
                    severity="HIGH",
                    suggested_action="Add human-in-the-loop"
                )
            ]
        )
        
        policy = generate_policy(scan)
        
        # Should include LLM08 rules
        rule_names = [r["name"] for r in policy["ingress_rules"]]
        assert "forge_review_agentic_tool_calls" in rule_names
        assert "forge_block_dangerous_agentic_commands" in rule_names


class TestPolicyConfiguration:
    """Test policy configuration options."""
    
    def test_custom_policy_name(self, sample_scan_result):
        """Test that custom policy name is used."""
        policy = generate_policy(sample_scan_result, policy_name="custom_policy")
        
        assert policy["policy_name"] == "custom_policy"
    
    def test_default_policy_name_from_repo(self, sample_scan_result):
        """Test that default policy name is derived from repo path."""
        policy = generate_policy(sample_scan_result)
        
        # Should use last part of repo path
        assert policy["policy_name"].startswith("forge_")
    
    def test_strict_mode_reduces_rate_limits(self, sample_scan_result):
        """Test that strict mode reduces rate limits."""
        policy_normal = generate_policy(sample_scan_result, strict_mode=False)
        policy_strict = generate_policy(sample_scan_result, strict_mode=True)
        
        assert policy_strict["rate_limits"]["requests_per_minute"] < \
               policy_normal["rate_limits"]["requests_per_minute"]
        assert policy_strict["rate_limits"]["requests_per_minute"] == 30
    
    def test_custom_base_rpm(self, sample_scan_result):
        """Test that custom base RPM is used."""
        policy = generate_policy(sample_scan_result, base_rpm=120)
        
        # Should use custom RPM (unless LLM04 detected)
        if "LLM04" not in sample_scan_result.by_owasp():
            assert policy["rate_limits"]["requests_per_minute"] == 120


class TestRuleDeduplication:
    """Test rule deduplication logic."""
    
    def test_deduplicate_removes_duplicates(self):
        """Test that duplicate rules are removed."""
        rules = [
            {"name": "rule1", "action": "DENY"},
            {"name": "rule2", "action": "ALLOW"},
            {"name": "rule1", "action": "DENY"},  # Duplicate
            {"name": "rule3", "action": "LOG"},
        ]
        
        deduplicated = _deduplicate_rules(rules)
        
        assert len(deduplicated) == 3
        rule_names = [r["name"] for r in deduplicated]
        assert rule_names == ["rule1", "rule2", "rule3"]
    
    def test_deduplicate_preserves_order(self):
        """Test that deduplication preserves first occurrence order."""
        rules = [
            {"name": "rule_a", "priority": 100},
            {"name": "rule_b", "priority": 90},
            {"name": "rule_a", "priority": 80},  # Duplicate with different priority
        ]
        
        deduplicated = _deduplicate_rules(rules)
        
        assert len(deduplicated) == 2
        assert deduplicated[0]["name"] == "rule_a"
        assert deduplicated[0]["priority"] == 100  # First occurrence preserved
        assert deduplicated[1]["name"] == "rule_b"


class TestYAMLSerialization:
    """Test YAML serialization."""
    
    def test_policy_to_yaml_produces_valid_yaml(self, sample_scan_result):
        """Test that policy_to_yaml produces valid YAML."""
        policy = generate_policy(sample_scan_result)
        yaml_str = policy_to_yaml(policy)
        
        # Should be valid YAML
        parsed = yaml.safe_load(yaml_str)
        assert parsed is not None
        assert isinstance(parsed, dict)
    
    def test_yaml_preserves_structure(self, sample_scan_result):
        """Test that YAML serialization preserves policy structure."""
        policy = generate_policy(sample_scan_result)
        yaml_str = policy_to_yaml(policy)
        parsed = yaml.safe_load(yaml_str)
        
        # Verify all top-level keys preserved
        for key in policy.keys():
            assert key in parsed
        
        # Verify nested structures preserved
        assert len(parsed["ingress_rules"]) == len(policy["ingress_rules"])
        assert len(parsed["egress_rules"]) == len(policy["egress_rules"])
    
    def test_yaml_handles_unicode(self):
        """Test that YAML serialization handles Unicode characters."""
        policy = {
            "policy_name": "test_policy",
            "description": "Test with émojis 🔒 and spëcial çhars",
            "rules": []
        }
        
        yaml_str = policy_to_yaml(policy)
        parsed = yaml.safe_load(yaml_str)
        
        assert parsed["description"] == policy["description"]


class TestRuleTemplates:
    """Test rule template definitions."""
    
    def test_owasp_ingress_rules_structure(self):
        """Test that OWASP_INGRESS_RULES has correct structure."""
        assert isinstance(OWASP_INGRESS_RULES, dict)
        
        for owasp_id, rules in OWASP_INGRESS_RULES.items():
            assert owasp_id.startswith("LLM")
            assert isinstance(rules, list)
            
            for rule in rules:
                assert "name" in rule
                assert "description" in rule
                assert "priority" in rule
                assert "action" in rule
                assert "conditions" in rule
                assert rule["action"] in ["DENY", "ALLOW", "LOG", "HUMAN_REVIEW", "RATE_LIMIT"]
    
    def test_egress_rules_base_structure(self):
        """Test that EGRESS_RULES_BASE has correct structure."""
        assert isinstance(EGRESS_RULES_BASE, list)
        assert len(EGRESS_RULES_BASE) > 0
        
        for rule in EGRESS_RULES_BASE:
            assert "name" in rule
            assert "description" in rule
            assert "priority" in rule
            assert "action" in rule
            assert "conditions" in rule
    
    def test_rule_priorities_valid(self):
        """Test that all rule priorities are valid integers."""
        for rules in OWASP_INGRESS_RULES.values():
            for rule in rules:
                assert isinstance(rule["priority"], int)
                assert 0 <= rule["priority"] <= 100
        
        for rule in EGRESS_RULES_BASE:
            assert isinstance(rule["priority"], int)
            assert 0 <= rule["priority"] <= 100


class TestPolicyCompleteness:
    """Test that generated policies are complete and valid."""
    
    def test_policy_has_all_required_fields(self, sample_scan_result):
        """Test that policy has all required fields for Lobster Trap."""
        policy = generate_policy(sample_scan_result)
        
        required_fields = [
            "version",
            "policy_name",
            "generated_by",
            "generated_at",
            "source_repo",
            "owasp_findings",
            "default_action",
            "ingress_rules",
            "egress_rules",
            "rate_limits",
            "network",
            "filesystem",
        ]
        
        for field in required_fields:
            assert field in policy, f"Missing required field: {field}"
    
    def test_policy_always_includes_baseline_protection(self):
        """Test that policy always includes baseline LLM01 protection."""
        # Even with no findings, should include baseline
        scan = ScanResult(
            repo_path="/test",
            scan_time_ms=100.0,
            total_files_scanned=1,
            total_lines_scanned=50,
            call_sites=[],
            governance_gaps=[]
        )
        
        policy = generate_policy(scan)
        
        # Should still have prompt injection protection
        rule_names = [r["name"] for r in policy["ingress_rules"]]
        assert "forge_block_prompt_injection" in rule_names
    
    def test_policy_always_includes_high_risk_review(self, sample_scan_result):
        """Test that policy always includes high-risk review rule."""
        policy = generate_policy(sample_scan_result)
        
        rule_names = [r["name"] for r in policy["ingress_rules"]]
        assert "forge_review_high_risk" in rule_names
