"""
FORGE — IBM Bob-powered LLM governance policy generator.

Full pipeline:
  1. Scan repository for LLM call sites + OWASP vulnerability patterns
  2. Generate SOUF AI / Lobster Trap policy YAML tailored to the repo
  3. Log every action in BobShell (tamper-evident audit trail)
  4. Verify generated policy imports into Lobster Trap

Usage (CLI):
    python -m forge scan --repo /path/to/repo --out policy.yaml
    python -m forge verify --policy policy.yaml
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from scanner.repo_scanner import scan_repo, ScanResult
from generator.policy_generator import generate_policy, policy_to_yaml
from audit.bobshell import BobShell

logger = logging.getLogger(__name__)


@dataclass
class ForgeResult:
    repo_path: str
    scan: ScanResult
    policy: dict
    policy_yaml: str
    bobshell: dict
    total_time_ms: float


def run_forge(
    repo_path: str,
    policy_name: Optional[str] = None,
    strict_mode: bool = False,
    out_dir: Optional[str] = None,
) -> ForgeResult:
    """
    Full FORGE pipeline: scan → generate policy → log to BobShell.
    """
    bob = BobShell()
    t0 = time.perf_counter()

    # Step 1: Scan
    logger.info("FORGE: scanning %s", repo_path)
    bob.log("forge_scan_start", {"repo": repo_path, "strict": strict_mode}, "started")
    scan = scan_repo(repo_path)
    bob.log("forge_scan_complete", {
        "repo": repo_path,
        "files": scan.total_files_scanned,
        "findings": scan.total_findings,
    }, scan.summary())

    # Step 2: Generate policy
    logger.info("FORGE: generating policy (%d findings)", scan.total_findings)
    policy = generate_policy(scan, policy_name=policy_name, strict_mode=strict_mode)
    yaml_str = policy_to_yaml(policy)
    bob.log("forge_policy_generated", {
        "policy_name": policy["policy_name"],
        "owasp_findings": policy["owasp_findings"],
        "ingress_rules": len(policy["ingress_rules"]),
        "egress_rules": len(policy["egress_rules"]),
    }, {"yaml_hash": _sha256_short(yaml_str), "yaml_bytes": len(yaml_str)})

    # Step 3: Write outputs
    if out_dir:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        policy_file = out / f"{policy['policy_name']}.yaml"
        policy_file.write_text(yaml_str)
        bob.log("forge_policy_written", {"path": str(policy_file)}, str(policy_file))

        bobshell_file = out / f"{policy['policy_name']}_bobshell.jsonl"
        bob.write_jsonl(bobshell_file)
        logger.info("FORGE: wrote policy → %s", policy_file)
        logger.info("FORGE: wrote BobShell → %s", bobshell_file)

    total_ms = (time.perf_counter() - t0) * 1000
    return ForgeResult(
        repo_path=repo_path,
        scan=scan,
        policy=policy,
        policy_yaml=yaml_str,
        bobshell=bob.export(),
        total_time_ms=total_ms,
    )


def _sha256_short(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()[:16]
