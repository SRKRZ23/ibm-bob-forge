"""
FORGE Policy Generator — converts scan findings into SOUF AI YAML policies.

For each OWASP category found, generates:
- Targeted ingress rules (input sanitisation)
- Targeted egress rules (output filtering)
- Rate limit config
- Audit log rules

Output is a valid SOUF AI / Lobster Trap policy YAML ready for import.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

import yaml

from scanner.repo_scanner import ScanResult, LLMCallSite


# ── Policy rule templates per OWASP category ──────────────────────────────────

OWASP_INGRESS_RULES: dict[str, list[dict]] = {
    "LLM01": [
        {
            "name": "forge_block_prompt_injection",
            "description": "FORGE: Block prompt injection (LLM01) — detected in repo scan",
            "priority": 100,
            "action": "DENY",
            "deny_message": "[FORGE/SOUF-AI] Blocked: prompt injection detected by FORGE governance.",
            "conditions": [
                {"field": "contains_injection_patterns", "match_type": "boolean", "value": True}
            ],
        },
        {
            "name": "forge_review_role_override",
            "description": "FORGE: Flag role-override / system-prompt manipulation (LLM01)",
            "priority": 95,
            "action": "HUMAN_REVIEW",
            "conditions": [
                {"field": "contains_role_impersonation", "match_type": "boolean", "value": True}
            ],
        },
    ],
    "LLM02": [
        {
            "name": "forge_log_llm_output_requests",
            "description": "FORGE: Log all LLM output requests for audit trail (LLM02)",
            "priority": 40,
            "action": "LOG",
            "conditions": [
                {"field": "intent_category", "match_type": "exact", "value": "general"}
            ],
        },
    ],
    "LLM04": [
        {
            "name": "forge_rate_limit_high_risk",
            "description": "FORGE: Rate-limit high-risk requests to prevent model DoS (LLM04)",
            "priority": 60,
            "action": "RATE_LIMIT",
            "conditions": [
                {"field": "risk_score", "match_type": "threshold", "value": 0.5}
            ],
        },
    ],
    "LLM05": [
        {
            "name": "forge_block_supply_chain_paths",
            "description": "FORGE: Block access to supply-chain-related paths (LLM05)",
            "priority": 88,
            "action": "DENY",
            "deny_message": "[FORGE/SOUF-AI] Blocked: supply chain path access denied.",
            "conditions": [
                {"field": "contains_sensitive_paths", "match_type": "boolean", "value": True}
            ],
        },
    ],
    "LLM06": [
        {
            "name": "forge_block_credential_access",
            "description": "FORGE: Block prompt requests for credentials/PII (LLM06)",
            "priority": 92,
            "action": "DENY",
            "deny_message": "[FORGE/SOUF-AI] Blocked: credential/PII request detected.",
            "conditions": [
                {"field": "contains_pii_request", "match_type": "boolean", "value": True}
            ],
        },
    ],
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
    "LLM08": [
        {
            "name": "forge_review_agentic_tool_calls",
            "description": "FORGE: Human review for agentic tool calls (LLM08 — excessive agency)",
            "priority": 75,
            "action": "HUMAN_REVIEW",
            "conditions": [
                {"field": "contains_system_commands", "match_type": "boolean", "value": True},
                {"field": "risk_score", "match_type": "threshold", "value": 0.4},
            ],
        },
        {
            "name": "forge_block_dangerous_agentic_commands",
            "description": "FORGE: Block dangerous agentic system commands (LLM08)",
            "priority": 85,
            "action": "DENY",
            "deny_message": "[FORGE/SOUF-AI] Blocked: dangerous agentic command detected.",
            "conditions": [
                {"field": "contains_system_commands", "match_type": "boolean", "value": True},
                {"field": "risk_score", "match_type": "threshold", "value": 0.7},
            ],
        },
    ],
}

EGRESS_RULES_BASE: list[dict] = [
    {
        "name": "forge_block_credential_leak",
        "description": "FORGE: Block output containing credentials",
        "priority": 100,
        "action": "DENY",
        "deny_message": "[FORGE/SOUF-AI] Output blocked: credentials detected in model response.",
        "conditions": [
            {"field": "contains_credentials", "match_type": "boolean", "value": True}
        ],
    },
    {
        "name": "forge_block_pii_output",
        "description": "FORGE: Block output containing PII",
        "priority": 90,
        "action": "DENY",
        "deny_message": "[FORGE/SOUF-AI] Output blocked: PII detected in model response.",
        "conditions": [
            {"field": "contains_pii", "match_type": "boolean", "value": True}
        ],
    },
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


def _deduplicate_rules(rules: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for r in rules:
        if r["name"] not in seen:
            seen.add(r["name"])
            out.append(r)
    return out


def generate_policy(
    scan: ScanResult,
    policy_name: Optional[str] = None,
    base_rpm: int = 60,
    strict_mode: bool = False,
) -> dict:
    """
    Generate a SOUF AI YAML policy dict from a ScanResult.
    """
    owasp_found = set(scan.by_owasp().keys())
    name = policy_name or f"forge_{scan.repo_path.split('/')[-1]}"

    ingress_rules: list[dict] = []
    for owasp_id in sorted(owasp_found):
        if owasp_id in OWASP_INGRESS_RULES:
            ingress_rules.extend(OWASP_INGRESS_RULES[owasp_id])

    # Always include baseline injection block
    if "LLM01" not in owasp_found:
        ingress_rules.extend(OWASP_INGRESS_RULES["LLM01"])

    # High-risk review rule
    ingress_rules.append({
        "name": "forge_review_high_risk",
        "description": "FORGE: Human review for high risk-score prompts",
        "priority": 70,
        "action": "HUMAN_REVIEW",
        "conditions": [
            {"field": "risk_score", "match_type": "threshold", "value": 0.6}
        ],
    })

    ingress_rules = _deduplicate_rules(ingress_rules)
    egress_rules = list(EGRESS_RULES_BASE)

    # Stricter rate limits if DoS risk detected
    rpm = 30 if "LLM04" in owasp_found or strict_mode else base_rpm

    policy = {
        "version": "1.0",
        "policy_name": name,
        "generated_by": "FORGE v1.0",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source_repo": scan.repo_path,
        "owasp_findings": sorted(owasp_found),
        "default_action": "ALLOW",
        "ingress_rules": ingress_rules,
        "egress_rules": egress_rules,
        "rate_limits": {
            "requests_per_minute": rpm,
            "requests_per_hour": rpm * 30,
            "burst_threshold": max(5, rpm // 4),
        },
        "network": {
            "egress_policy": "allowlist",
            "allowed_domains": ["api.openai.com", "api.anthropic.com"],
            "denied_domains": ["*.onion", "pastebin.com"],
        },
        "filesystem": {
            "denied_paths": ["/etc/**", "/root/**", "**/.ssh/**", "**/.env", "**/*secret*", "**/*password*"],
            "allowed_read_paths": ["/tmp/agent_workspace/**"],
            "allowed_write_paths": ["/tmp/agent_workspace/**"],
        },
    }
    return policy


def policy_to_yaml(policy: dict) -> str:
    return yaml.dump(policy, default_flow_style=False, sort_keys=False, allow_unicode=True)
