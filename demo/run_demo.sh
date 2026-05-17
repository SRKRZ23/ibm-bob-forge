#!/bin/bash
#
# FORGE End-to-End Demo Script
# Demonstrates complete workflow: scan → policy generation → audit verification
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
FORGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_DIR="$FORGE_ROOT/demo"
SAMPLE_REPO="$DEMO_DIR/sample_vulnerable_repo"
OUTPUT_DIR="$DEMO_DIR/output"
REPORT_FILE="$DEMO_DIR/demo_report.txt"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         FORGE End-to-End Demo                             ║${NC}"
echo -e "${BLUE}║  LLM Security Policy Generator with IBM Bob Audit         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Clean previous output
echo -e "${YELLOW}[1/6] Cleaning previous demo output...${NC}"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
echo -e "${GREEN}✓ Output directory ready: $OUTPUT_DIR${NC}"
echo ""

# Show sample repository
echo -e "${YELLOW}[2/6] Sample vulnerable repository:${NC}"
echo "  Location: $SAMPLE_REPO"
echo "  Files:"
ls -1 "$SAMPLE_REPO" | sed 's/^/    - /'
echo ""

# Run FORGE scan
echo -e "${YELLOW}[3/6] Running FORGE security scan...${NC}"
cd "$FORGE_ROOT"

python -m src.cli scan \
    --repo "$SAMPLE_REPO" \
    --out "$OUTPUT_DIR" \
    2>&1 | tee "$OUTPUT_DIR/scan.log"

SCAN_EXIT_CODE=${PIPESTATUS[0]}

if [ $SCAN_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}✗ Scan failed with exit code $SCAN_EXIT_CODE${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Scan completed successfully${NC}"
echo ""

# Parse scan results
echo -e "${YELLOW}[4/6] Parsing scan results...${NC}"

POLICY_FILE=$(find "$OUTPUT_DIR" -name "*.yaml" -type f | head -n 1)
AUDIT_FILE=$(find "$OUTPUT_DIR" -name "*_bobshell.jsonl" -type f | head -n 1)

if [ -z "$POLICY_FILE" ]; then
    echo -e "${RED}✗ No policy file generated${NC}"
    exit 1
fi

if [ -z "$AUDIT_FILE" ]; then
    echo -e "${RED}✗ No audit log generated${NC}"
    exit 1
fi

echo "  Policy file: $(basename "$POLICY_FILE")"
echo "  Audit log:   $(basename "$AUDIT_FILE")"
echo ""

# Extract findings from scan log
FILES_SCANNED=$(grep -oP "(?<=— )\d+(?= files)" "$OUTPUT_DIR/scan.log" || echo "0")
TOTAL_FINDINGS=$(grep -oP "(?<=Total findings:   )\d+" "$OUTPUT_DIR/scan.log" || echo "0")
HIGH_FINDINGS=$(grep -oP "(?<=HIGH   ).*" "$OUTPUT_DIR/scan.log" | grep -oP "\d+" || echo "0")
MEDIUM_FINDINGS=$(grep -oP "(?<=MEDIUM ).*" "$OUTPUT_DIR/scan.log" | grep -oP "\d+" || echo "0")

# Extract OWASP categories
OWASP_CATEGORIES=$(grep -oP "(?<=OWASP breakdown:).*?(?=Severity:)" "$OUTPUT_DIR/scan.log" | grep -oP "LLM\d+" | sort -u | tr '\n' ', ' | sed 's/,$//')

echo -e "${BLUE}Scan Results:${NC}"
echo "  Files scanned:    $FILES_SCANNED"
echo "  Total findings:   $TOTAL_FINDINGS"
echo "  HIGH severity:    $HIGH_FINDINGS"
echo "  MEDIUM severity:  $MEDIUM_FINDINGS"
echo "  OWASP categories: $OWASP_CATEGORIES"
echo ""

# Count policy rules
echo -e "${YELLOW}[5/6] Analyzing generated policy...${NC}"

INGRESS_RULES=$(grep -c "^  - name:" "$POLICY_FILE" | head -1 || echo "0")
RATE_LIMITS=$(grep -c "requests_per_minute:" "$POLICY_FILE" || echo "0")

echo -e "${BLUE}Policy Analysis:${NC}"
echo "  Policy rules:     $INGRESS_RULES"
echo "  Rate limiting:    $([ "$RATE_LIMITS" -gt 0 ] && echo "✓ Enabled" || echo "✗ Disabled")"
echo ""

# Verify BobShell audit log
echo -e "${YELLOW}[6/6] Verifying BobShell audit chain...${NC}"

python3 << EOF
import json
import sys

try:
    with open("$AUDIT_FILE", 'r') as f:
        entries = [json.loads(line) for line in f]
    
    if len(entries) < 2:
        print("${RED}✗ Audit log incomplete (< 2 entries)${NC}")
        sys.exit(1)
    
    # Verify chain integrity
    for i in range(1, len(entries)):
        if entries[i]['prev_hash'] != entries[i-1]['entry_hash']:
            print("${RED}✗ Audit chain broken at entry", i, "${NC}")
            sys.exit(1)
    
    print("${GREEN}✓ BobShell audit chain verified${NC}")
    print(f"  Total entries: {len(entries)}")
    print(f"  Session ID:    {entries[0]['bob_session_id']}")
    
    # Show actions
    print("  Actions logged:")
    for entry in entries:
        print(f"    [{entry['seq']}] {entry['action']}")
    
    sys.exit(0)
    
except Exception as e:
    print(f"${RED}✗ Audit verification failed: {e}${NC}")
    sys.exit(1)
EOF

AUDIT_EXIT_CODE=$?

echo ""

# Generate final report
echo -e "${YELLOW}Generating demo report...${NC}"

cat > "$REPORT_FILE" << EOF
╔════════════════════════════════════════════════════════════╗
║              FORGE Demo Report                             ║
║         $(date '+%Y-%m-%d %H:%M:%S %Z')                           ║
╚════════════════════════════════════════════════════════════╝

SCAN RESULTS
────────────────────────────────────────────────────────────
Repository:       $SAMPLE_REPO
Files scanned:    $FILES_SCANNED
Total findings:   $TOTAL_FINDINGS
  HIGH severity:  $HIGH_FINDINGS
  MEDIUM severity: $MEDIUM_FINDINGS

OWASP COVERAGE
────────────────────────────────────────────────────────────
Categories detected: $OWASP_CATEGORIES

GENERATED POLICY
────────────────────────────────────────────────────────────
Policy file:      $(basename "$POLICY_FILE")
Policy rules:     $INGRESS_RULES
Rate limiting:    $([ "$RATE_LIMITS" -gt 0 ] && echo "Enabled" || echo "Disabled")

AUDIT TRAIL
────────────────────────────────────────────────────────────
Audit log:        $(basename "$AUDIT_FILE")
Chain integrity:  $([ $AUDIT_EXIT_CODE -eq 0 ] && echo "✓ VERIFIED" || echo "✗ FAILED")

DEMO STATUS
────────────────────────────────────────────────────────────
Overall:          $([ $AUDIT_EXIT_CODE -eq 0 ] && echo "✓ SUCCESS" || echo "✗ FAILED")

All demo artifacts saved to: $OUTPUT_DIR
EOF

cat "$REPORT_FILE"

# Summary
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
if [ $AUDIT_EXIT_CODE -eq 0 ]; then
    echo -e "${BLUE}║${GREEN}  ✓ DEMO COMPLETED SUCCESSFULLY                            ${BLUE}║${NC}"
else
    echo -e "${BLUE}║${RED}  ✗ DEMO FAILED                                             ${BLUE}║${NC}"
fi
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Demo artifacts:"
echo "  - Scan log:    $OUTPUT_DIR/scan.log"
echo "  - Policy:      $POLICY_FILE"
echo "  - Audit log:   $AUDIT_FILE"
echo "  - Report:      $REPORT_FILE"
echo ""
echo "Next steps:"
echo "  1. Review policy: cat $POLICY_FILE"
echo "  2. Deploy to Lobster Trap: lobstertrap serve --policy $POLICY_FILE"
echo "  3. See documentation: docs/USAGE.md"
echo ""

exit $AUDIT_EXIT_CODE
