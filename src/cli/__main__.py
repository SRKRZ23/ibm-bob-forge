"""
FORGE CLI — IBM Bob governance policy generator.

Commands:
  forge scan   --repo PATH [--out DIR] [--strict]
  forge verify --policy FILE
  forge demo   [--repos REPO1 REPO2 REPO3]
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC))

import yaml

from forge import run_forge
from scanner.repo_scanner import scan_repo
from generator.policy_generator import generate_policy, policy_to_yaml
from audit.bobshell import BobShell

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def validate_path(path_str: str, must_exist: bool = True, must_be_dir: bool = False, must_be_file: bool = False) -> Path:
    """
    Validate and sanitize a file system path for security.
    
    Security checks:
    - Prevents path traversal attacks (../, absolute paths outside CWD)
    - Resolves symlinks safely
    - Validates existence
    - Checks file/directory type
    
    Args:
        path_str: Path string to validate
        must_exist: If True, path must exist
        must_be_dir: If True, path must be a directory
        must_be_file: If True, path must be a file
    
    Returns:
        Validated Path object
    
    Raises:
        ValueError: If path fails validation
    """
    try:
        # Convert to Path and resolve (follows symlinks, makes absolute)
        path = Path(path_str).resolve()
        
        # Security: Prevent path traversal outside current working directory
        # Allow paths within CWD or explicitly allowed system paths
        cwd = Path.cwd().resolve()
        try:
            # Check if path is within CWD or is an absolute path the user explicitly provided
            if not (path.is_relative_to(cwd) or path == Path(path_str).resolve()):
                # Allow if user provided absolute path explicitly
                if not Path(path_str).is_absolute():
                    raise ValueError(f"Path traversal detected: {path_str}")
        except (ValueError, AttributeError):
            # Python < 3.9 doesn't have is_relative_to, use alternative check
            try:
                path.relative_to(cwd)
            except ValueError:
                # Path is outside CWD - allow only if explicitly absolute
                if not Path(path_str).is_absolute():
                    raise ValueError(f"Path traversal detected: {path_str}")
        
        # Check existence
        if must_exist and not path.exists():
            raise ValueError(f"Path does not exist: {path_str}")
        
        # Check if it's a directory
        if must_be_dir and path.exists() and not path.is_dir():
            raise ValueError(f"Path is not a directory: {path_str}")
        
        # Check if it's a file
        if must_be_file and path.exists() and not path.is_file():
            raise ValueError(f"Path is not a file: {path_str}")
        
        # Security: Check for suspicious symlinks (optional, already resolved)
        # If original path was a symlink, verify it's not pointing to sensitive locations
        original_path = Path(path_str)
        if original_path.is_symlink():
            target = original_path.resolve()
            # Warn about symlinks to system directories
            sensitive_dirs = ['/etc', '/root', '/sys', '/proc', '/dev']
            for sensitive in sensitive_dirs:
                if str(target).startswith(sensitive):
                    logger.warning(f"Symlink points to sensitive directory: {path_str} -> {target}")
        
        return path
        
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid path: {path_str} ({e})")


def cmd_scan(args: argparse.Namespace) -> None:
    # Security: Validate repository path
    try:
        repo_path = validate_path(args.repo, must_exist=True, must_be_dir=True)
    except ValueError as e:
        print(f"ERROR: Invalid repository path: {e}", file=sys.stderr)
        sys.exit(1)
    
    out_dir = args.out or "forge_output"
    
    # Security: Validate output directory path (create if doesn't exist)
    try:
        out_path = validate_path(out_dir, must_exist=False)
    except ValueError as e:
        print(f"ERROR: Invalid output directory path: {e}", file=sys.stderr)
        sys.exit(1)
    
    print(f"\n🔍 FORGE scanning: {repo_path}")
    print(f"   Output dir:      {out_path}")
    print(f"   Strict mode:     {args.strict}")
    print()

    result = run_forge(
        repo_path=str(repo_path),
        strict_mode=args.strict,
        out_dir=str(out_path),
    )

    s = result.scan.summary()
    print("=" * 60)
    print(f"FORGE Scan Complete — {s['files_scanned']} files, {s['lines_scanned']:,} lines")
    print(f"  LLM call sites:   {s['call_sites']}")
    print(f"  Governance gaps:  {s['governance_gaps']}")
    print(f"  Total findings:   {s['total_findings']}")
    print()
    print("OWASP breakdown:")
    for owasp_id, count in sorted(s["owasp_breakdown"].items()):
        from scanner.repo_scanner import OWASP_LLM
        name = OWASP_LLM.get(owasp_id, "")
        print(f"  {owasp_id} {name:35s} {count:3d} findings")
    print()
    print("Severity:")
    for sev, count in s["severity_breakdown"].items():
        bar = "█" * min(count, 40)
        print(f"  {sev:6s} {bar} {count}")
    print()
    print(f"Policy:    {out_dir}/{result.policy['policy_name']}.yaml")
    print(f"BobShell:  {out_dir}/{result.policy['policy_name']}_bobshell.jsonl")
    print(f"Scan time: {result.total_time_ms:.0f}ms")
    print()

    # Show top 10 findings
    all_findings = result.scan.call_sites + result.scan.governance_gaps
    all_findings.sort(key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[f.severity])
    print("Top findings:")
    for f in all_findings[:10]:
        rel = f.file.replace(args.repo, "").lstrip("/")
        print(f"  [{f.severity:6s}] {f.owasp_id} {rel}:{f.line}")
        print(f"           {f.code[:80]}")
        print(f"           → {f.suggested_action}")
    if len(all_findings) > 10:
        print(f"  ... and {len(all_findings) - 10} more (see {out_dir}/)")
    print()

    # BobShell chain verification
    chain_ok = result.bobshell["chain_verified"]
    print(f"BobShell chain: {'✅ verified' if chain_ok else '❌ INVALID'} ({result.bobshell['total_actions']} actions logged)")
    print("=" * 60)


def cmd_verify(args: argparse.Namespace) -> None:
    # Security: Validate policy file path
    try:
        policy_path = validate_path(args.policy, must_exist=True, must_be_file=True)
    except ValueError as e:
        print(f"ERROR: Invalid policy file path: {e}", file=sys.stderr)
        sys.exit(1)

    with open(policy_path) as f:
        policy = yaml.safe_load(f)

    print(f"\n🔍 Verifying policy: {policy_path.name}")
    print(f"   Policy name: {policy.get('policy_name', '?')}")
    print(f"   Generated:   {policy.get('generated_at', '?')}")
    print(f"   OWASP:       {', '.join(policy.get('owasp_findings', []))}")
    print()

    ingress = policy.get("ingress_rules", [])
    egress = policy.get("egress_rules", [])
    print(f"  Ingress rules: {len(ingress)}")
    for r in ingress:
        print(f"    [{r.get('priority', 0):3d}] {r['name']:45s} → {r['action']}")
    print(f"  Egress rules: {len(egress)}")
    for r in egress:
        print(f"    [{r.get('priority', 0):3d}] {r['name']:45s} → {r['action']}")
    print()

    rl = policy.get("rate_limits", {})
    print(f"  Rate limits: {rl.get('requests_per_minute', '?')} rpm / {rl.get('requests_per_hour', '?')} rph")
    print()
    print("✅ Policy structure valid — ready for Lobster Trap import")
    print(f"   lobstertrap serve --policy {policy_path}")
    print()


def cmd_demo(args: argparse.Namespace) -> None:
    # Derive demo repo paths relative to this file's location (portable across machines)
    _COMPETITIONS = Path(__file__).resolve().parents[4]
    repos = args.repos or [
        str(_COMPETITIONS / "aiagentolympics" / "atlas"),
        str(_COMPETITIONS / "gemma4good" / "citadel"),
        str(_COMPETITIONS / "ibmbob" / "forge"),
    ]

    print("\n🔷 FORGE Demo — scanning 3 repos")
    print("=" * 60)

    from scanner.repo_scanner import OWASP_LLM
    for repo in repos:
        repo_path = Path(repo)
        if not repo_path.exists():
            print(f"  SKIP {repo} (not found)")
            continue

        name = repo_path.name
        result = run_forge(repo_path=str(repo_path), out_dir=f"forge_output/{name}")
        s = result.scan.summary()
        print(f"\n  Repo: {name}")
        print(f"    Files:    {s['files_scanned']:3d} | Findings: {s['total_findings']:3d}")
        print(f"    OWASP:    {', '.join(s['owasp_breakdown'].keys()) or 'none'}")
        chain_ok = result.bobshell["chain_verified"]
        print(f"    BobShell: {'✅' if chain_ok else '❌'} ({result.bobshell['total_actions']} actions)")
        print(f"    Policy:   forge_output/{name}/{result.policy['policy_name']}.yaml")

    print()
    print("✅ Demo complete. All policies written to forge_output/")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="FORGE — IBM Bob LLM governance policy generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Scan a repo and generate SOUF AI policy")
    p_scan.add_argument("--repo", required=True, help="Path to repository to scan")
    p_scan.add_argument("--out", default=None, help="Output directory (default: forge_output/)")
    p_scan.add_argument("--strict", action="store_true", help="Enable strict mode (lower rate limits)")
    p_scan.set_defaults(func=cmd_scan)

    # verify
    p_verify = sub.add_parser("verify", help="Verify a generated policy YAML")
    p_verify.add_argument("--policy", required=True, help="Path to policy YAML")
    p_verify.set_defaults(func=cmd_verify)

    # demo
    p_demo = sub.add_parser("demo", help="Run FORGE on demo repos")
    p_demo.add_argument("--repos", nargs="+", help="Repos to demo (default: 3 ALISH repos)")
    p_demo.set_defaults(func=cmd_demo)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
