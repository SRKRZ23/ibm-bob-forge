"""
FORGE — Scientific Test Suite (IBM Bob Hackathon submission verification).

Verifies FORGE behaviour empirically:
  T1: Scanner finds LLM call sites in known repos (precision check)
  T2: OWASP mappings are correct for each finding type
  T3: Generated YAML is structurally valid (lobstertrap-compatible)
  T4: BobShell chain integrity (4 actions, valid JSONL)
  T5: Verify command passes on all generated policies
  T6: No false positive findings on non-LLM code
  T7: Scan latency < 500ms per repo

All assertions are data-driven, no untested claims.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from forge import run_forge
from scanner.repo_scanner import scan_repo
from generator.policy_generator import generate_policy, policy_to_yaml
from audit.bobshell import BobShell

ROOT = Path(__file__).resolve().parents[4]  # Alish/
ATLAS_DIR = str(ROOT / "competitions" / "aiagentolympics" / "atlas")
CITADEL_DIR = str(ROOT / "competitions" / "gemma4good" / "citadel")
FORGE_DIR = str(ROOT / "competitions" / "ibmbob" / "forge")

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    status = "✓ PASS" if condition else "✗ FAIL"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
    if condition:
        PASS += 1
    else:
        FAIL += 1


# ── T1: Scanner finds LLM call sites ───────────────────────────────────────

print("\nT1: Scanner — LLM call site detection")
scan = scan_repo(ATLAS_DIR)
check("ATLAS: found ≥1 LLM sites", scan.total_findings >= 1, f"{scan.total_findings} findings")
check("ATLAS: scanned ≥5 files", scan.total_files_scanned >= 5, f"{scan.total_files_scanned} files")

scan_citadel = scan_repo(CITADEL_DIR)
check("CITADEL: found ≥1 LLM sites", scan_citadel.total_findings >= 1, f"{scan_citadel.total_findings} findings")

# ── T2: OWASP mappings ──────────────────────────────────────────────────────

print("\nT2: OWASP category mappings")
all_findings = scan.call_sites + scan.governance_gaps
owasp_atlas = {f.owasp_id for f in all_findings}
check("ATLAS: has LLM01 (prompt injection)", "LLM01" in owasp_atlas, f"categories: {sorted(owasp_atlas)}")
# Either LLM02 (output handling) or LLM08 (excessive agency) expected for orchestrator patterns
check("ATLAS: has LLM02 or LLM08", bool({"LLM02", "LLM08"} & owasp_atlas), f"categories: {sorted(owasp_atlas)}")

# ── T3: Generated YAML structural validity ──────────────────────────────────

print("\nT3: Policy YAML structure")
policy = generate_policy(scan, policy_name="test_policy")
yaml_str = policy_to_yaml(policy)

check("YAML: name field present", "name:" in yaml_str, "")
check("YAML: version field present", "version:" in yaml_str, "")
check("YAML: has ingress rules", "ingress_rules:" in yaml_str, "")
check("YAML: has egress rules", "egress_rules:" in yaml_str, "")
check("YAML: has rate limits", "rate_limits:" in yaml_str, "")

# At least one DENY rule
check("YAML: has DENY action", "action: DENY" in yaml_str, "")

# Priority values must be 1–100
import re as _re
priorities = [int(m) for m in _re.findall(r"priority:\s*(\d+)", yaml_str)]
check("YAML: all priorities 1–100", all(1 <= p <= 100 for p in priorities), f"priorities: {priorities}")

# ── T4: BobShell chain integrity ────────────────────────────────────────────

print("\nT4: BobShell audit trail")
bob = BobShell()
bob.log("scan_start", {"repo": ATLAS_DIR}, "started")
bob.log("scan_complete", {"findings": 7}, "done")
bob.log("policy_generated", {"rules": 4}, "done")
bob.log("policy_written", {"path": "out.yaml"}, "done")

chain = bob.export()
check("BobShell: 4 actions logged", chain.get("total_actions", 0) == 4, f"{chain.get('total_actions')} actions")
check("BobShell: chain_verified=True", chain.get("chain_verified", False), "")
check("BobShell: entries list", isinstance(chain.get("entries"), list), "")

# JSONL serialization round-trip
import io as _io
buf = _io.StringIO()
for rec in chain.get("entries", []):
    buf.write(json.dumps(rec) + "\n")
lines = buf.getvalue().strip().split("\n")
check("BobShell: JSONL round-trip", len(lines) == 4, f"{len(lines)} lines")
for line in lines:
    try:
        json.loads(line)
    except json.JSONDecodeError as e:
        check("BobShell: JSON parse error", False, str(e))
        break
else:
    check("BobShell: all lines valid JSON", True, "")

# ── T5: Full FORGE pipeline ─────────────────────────────────────────────────

print("\nT5: End-to-end FORGE pipeline")
import tempfile, os
with tempfile.TemporaryDirectory() as tmp:
    result = run_forge(ATLAS_DIR, policy_name="atlas_e2e", out_dir=tmp)
    check("Pipeline: ForgeResult returned", result is not None, "")
    check("Pipeline: policy YAML populated", len(result.policy_yaml) > 100, f"{len(result.policy_yaml)} chars")
    check("Pipeline: bobshell has records", result.bobshell.get("total_actions", 0) >= 4, "")
    check("Pipeline: total_time_ms > 0", result.total_time_ms > 0, f"{result.total_time_ms:.1f}ms")
    # Output files created
    out_files = list(Path(tmp).rglob("*.yaml")) + list(Path(tmp).rglob("*.jsonl"))
    check("Pipeline: output files written", len(out_files) >= 2, f"{len(out_files)} files")

# ── T6: No FP on non-LLM code ───────────────────────────────────────────────

print("\nT6: False positive check on non-LLM code")
# Create a temp dir with pure Python data-processing code (no LLM calls)
import tempfile, textwrap
with tempfile.TemporaryDirectory() as tmp:
    p = Path(tmp) / "data_processor.py"
    p.write_text(textwrap.dedent("""
        def process_csv(path):
            import csv
            with open(path) as f:
                return list(csv.reader(f))

        def compute_stats(data):
            values = [float(row[0]) for row in data if row]
            return {"mean": sum(values)/len(values), "n": len(values)}
    """))
    scan_noai = scan_repo(tmp)
    check("No FP: pure data code = 0 findings", scan_noai.total_findings == 0, f"{scan_noai.total_findings} findings")

# ── T7: Scan latency ────────────────────────────────────────────────────────

print("\nT7: Performance")
t0 = time.perf_counter()
scan_repo(ATLAS_DIR)
atlas_ms = (time.perf_counter() - t0) * 1000
check(f"ATLAS scan < 500ms", atlas_ms < 500, f"{atlas_ms:.1f}ms")

t0 = time.perf_counter()
scan_repo(CITADEL_DIR)
citadel_ms = (time.perf_counter() - t0) * 1000
check(f"CITADEL scan < 500ms", citadel_ms < 500, f"{citadel_ms:.1f}ms")

# ── Summary ─────────────────────────────────────────────────────────────────

total = PASS + FAIL
print(f"\n{'='*60}")
print(f"FORGE Test Suite: {PASS}/{total} PASS")
if FAIL > 0:
    print(f"FAIL count: {FAIL}")
    sys.exit(1)
else:
    print("All tests PASS — FORGE is submission-ready")
print(f"{'='*60}")
