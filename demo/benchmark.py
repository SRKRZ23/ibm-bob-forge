#!/usr/bin/env python3
"""
FORGE Benchmark Script
Measures performance metrics for FORGE scanning and policy generation
"""

import time
import json
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scanner.repo_scanner import scan_repo
from generator.policy_generator import generate_policy, policy_to_yaml
from audit.bobshell import BobShell


def benchmark_forge(repo_path: str) -> dict:
    """
    Benchmark FORGE on a repository.
    
    Returns:
        dict: Benchmark results with timing and metrics
    """
    print("=" * 60)
    print("FORGE Benchmark")
    print("=" * 60)
    print(f"Repository: {repo_path}")
    print()
    
    results = {
        "repo_path": repo_path,
        "timings": {},
        "metrics": {},
        "success": True,
        "errors": []
    }
    
    # Benchmark: Repository Scanning
    print("[1/4] Benchmarking repository scan...")
    scan_start = time.time()
    
    try:
        scan_result = scan_repo(repo_path=repo_path)
        scan_duration = time.time() - scan_start
        
        results["timings"]["scan_seconds"] = round(scan_duration, 3)
        results["metrics"]["files_scanned"] = scan_result.total_files_scanned
        results["metrics"]["lines_scanned"] = scan_result.total_lines_scanned
        results["metrics"]["llm_calls_found"] = len(scan_result.call_sites)
        results["metrics"]["total_findings"] = len(scan_result.call_sites) + len(scan_result.governance_gaps)
        
        # Get all findings
        all_findings = scan_result.call_sites + scan_result.governance_gaps
        
        # Count OWASP categories
        owasp_cats = set()
        for finding in all_findings:
            if hasattr(finding, 'owasp_id'):
                owasp_cats.add(finding.owasp_id)
        results["metrics"]["owasp_categories"] = len(owasp_cats)
        
        # Breakdown by severity
        high = sum(1 for f in all_findings if f.severity == "HIGH")
        medium = sum(1 for f in all_findings if f.severity == "MEDIUM")
        low = sum(1 for f in all_findings if f.severity == "LOW")
        
        results["metrics"]["high_severity"] = high
        results["metrics"]["medium_severity"] = medium
        results["metrics"]["low_severity"] = low
        
        print(f"  ✓ Scan completed in {scan_duration:.3f}s")
        print(f"    Files: {scan_result.total_files_scanned}")
        print(f"    Lines: {scan_result.total_lines_scanned}")
        print(f"    Findings: {len(all_findings)}")
        
    except Exception as e:
        results["success"] = False
        results["errors"].append(f"Scan failed: {str(e)}")
        print(f"  ✗ Scan failed: {e}")
        return results
    
    # Benchmark: Policy Generation
    print("\n[2/4] Benchmarking policy generation...")
    policy_start = time.time()
    
    try:
        policy_dict = generate_policy(scan_result)
        policy_yaml = policy_to_yaml(policy_dict)
        policy_duration = time.time() - policy_start

        results["timings"]["policy_generation_seconds"] = round(policy_duration, 3)
        results["metrics"]["policy_size_bytes"] = len(policy_yaml)
        results["metrics"]["policy_lines"] = policy_yaml.count('\n')

        # Count policy rules across ingress_rules + egress_rules sections of the dict
        ingress_count = len(policy_dict.get("ingress_rules", []))
        egress_count = len(policy_dict.get("egress_rules", []))
        results["metrics"]["policy_rules"] = ingress_count + egress_count
        results["metrics"]["ingress_rules"] = ingress_count
        results["metrics"]["egress_rules"] = egress_count

        ingress_rules = ingress_count + egress_count  # for downstream printing
        
        print(f"  ✓ Policy generated in {policy_duration:.3f}s")
        print(f"    Size: {len(policy_yaml)} bytes")
        print(f"    Rules: {ingress_rules}")
        
    except Exception as e:
        results["success"] = False
        results["errors"].append(f"Policy generation failed: {str(e)}")
        print(f"  ✗ Policy generation failed: {e}")
        return results
    
    # Benchmark: BobShell Audit Logging
    print("\n[3/4] Benchmarking BobShell audit logging...")
    audit_start = time.time()
    
    try:
        bob = BobShell()
        
        # Log multiple actions
        bob.log("forge_scan_start", {"repo": repo_path}, {"status": "started"})
        bob.log("forge_scan_complete", {
            "files": scan_result.total_files_scanned,
            "findings": len(all_findings)
        }, {"status": "completed"})
        bob.log("forge_policy_generated", {
            "size": len(policy_yaml),
            "rules": ingress_rules
        }, {"status": "generated"})
        bob.log("forge_benchmark_complete", {}, {"status": "complete"})
        
        audit_duration = time.time() - audit_start
        
        results["timings"]["audit_logging_seconds"] = round(audit_duration, 3)
        results["metrics"]["audit_entries"] = len(bob)
        
        # Verify chain
        chain_valid = bob.verify()
        results["metrics"]["audit_chain_valid"] = chain_valid
        
        print(f"  ✓ Audit logging completed in {audit_duration:.3f}s")
        print(f"    Entries: {len(bob)}")
        print(f"    Chain valid: {chain_valid}")
        
    except Exception as e:
        results["success"] = False
        results["errors"].append(f"Audit logging failed: {str(e)}")
        print(f"  ✗ Audit logging failed: {e}")
        return results
    
    # Calculate total time
    total_duration = scan_duration + policy_duration + audit_duration
    results["timings"]["total_seconds"] = round(total_duration, 3)
    
    # Calculate throughput metrics
    if scan_duration > 0:
        results["metrics"]["files_per_second"] = round(
            scan_result.total_files_scanned / scan_duration, 2
        )
        results["metrics"]["lines_per_second"] = round(
            scan_result.total_lines_scanned / scan_duration, 2
        )
    
    print("\n[4/4] Benchmark complete!")
    
    return results


def print_benchmark_report(results: dict):
    """Print formatted benchmark report."""
    print("\n" + "=" * 60)
    print("BENCHMARK REPORT")
    print("=" * 60)
    
    if not results["success"]:
        print("\n❌ BENCHMARK FAILED")
        for error in results["errors"]:
            print(f"  - {error}")
        return
    
    print("\n📊 PERFORMANCE METRICS")
    print("-" * 60)
    print(f"Total time:           {results['timings']['total_seconds']:.3f}s")
    print(f"  Scan:               {results['timings']['scan_seconds']:.3f}s")
    print(f"  Policy generation:  {results['timings']['policy_generation_seconds']:.3f}s")
    print(f"  Audit logging:      {results['timings']['audit_logging_seconds']:.3f}s")
    
    print("\n📈 THROUGHPUT")
    print("-" * 60)
    print(f"Files per second:     {results['metrics'].get('files_per_second', 0):.2f}")
    print(f"Lines per second:     {results['metrics'].get('lines_per_second', 0):.2f}")
    
    print("\n🔍 SCAN RESULTS")
    print("-" * 60)
    print(f"Files scanned:        {results['metrics']['files_scanned']}")
    print(f"Lines scanned:        {results['metrics']['lines_scanned']}")
    print(f"LLM calls found:      {results['metrics']['llm_calls_found']}")
    print(f"Total findings:       {results['metrics']['total_findings']}")
    print(f"  HIGH severity:      {results['metrics']['high_severity']}")
    print(f"  MEDIUM severity:    {results['metrics']['medium_severity']}")
    print(f"  LOW severity:       {results['metrics']['low_severity']}")
    print(f"OWASP categories:     {results['metrics']['owasp_categories']}")
    
    print("\n📝 POLICY GENERATION")
    print("-" * 60)
    print(f"Policy size:          {results['metrics']['policy_size_bytes']} bytes")
    print(f"Policy lines:         {results['metrics']['policy_lines']}")
    print(f"Policy rules:         {results['metrics']['policy_rules']}")
    
    print("\n🔐 AUDIT TRAIL")
    print("-" * 60)
    print(f"Audit entries:        {results['metrics']['audit_entries']}")
    print(f"Chain integrity:      {'✓ VALID' if results['metrics']['audit_chain_valid'] else '✗ INVALID'}")
    
    print("\n" + "=" * 60)
    print("✅ BENCHMARK COMPLETED SUCCESSFULLY")
    print("=" * 60)


def save_benchmark_results(results: dict, output_path: str):
    """Save benchmark results to JSON file."""
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n💾 Results saved to: {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python benchmark.py <repo_path> [output_json]")
        print("\nExample:")
        print("  python benchmark.py demo/sample_vulnerable_repo")
        print("  python benchmark.py demo/sample_vulnerable_repo demo/benchmark_results.json")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not os.path.exists(repo_path):
        print(f"❌ Error: Repository not found: {repo_path}")
        sys.exit(1)
    
    # Run benchmark
    results = benchmark_forge(repo_path)
    
    # Print report
    print_benchmark_report(results)
    
    # Save results if output path provided
    if output_path:
        save_benchmark_results(results, output_path)
    
    # Exit with appropriate code
    sys.exit(0 if results["success"] else 1)
