#!/bin/bash
#
# FORGE Pre-commit Hook
# Runs FORGE security scan before each commit
#
# Installation:
#   cp pre-commit-hook.sh /path/to/your/repo/.git/hooks/pre-commit
#   chmod +x /path/to/your/repo/.git/hooks/pre-commit
#
# Bypass (if needed):
#   git commit --no-verify

set -e

echo "🔍 Running FORGE security scan..."

# Configuration
FORGE_DIR="/path/to/forge"  # Update this path
OUTPUT_DIR="/tmp/forge-scan-$(date +%s)"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Run FORGE scan
python -m "$FORGE_DIR/src/cli" scan \
    --repo . \
    --out "$OUTPUT_DIR" \
    2>&1 | tee "$OUTPUT_DIR/scan.log"

# Check for HIGH severity findings
if [ -f "$OUTPUT_DIR"/*.yaml ]; then
    HIGH_COUNT=$(grep -c "severity: HIGH" "$OUTPUT_DIR"/*.yaml 2>/dev/null || echo "0")
    MEDIUM_COUNT=$(grep -c "severity: MEDIUM" "$OUTPUT_DIR"/*.yaml 2>/dev/null || echo "0")
    
    echo ""
    echo "============================================================"
    echo "FORGE Scan Results:"
    echo "  HIGH severity:   $HIGH_COUNT"
    echo "  MEDIUM severity: $MEDIUM_COUNT"
    echo "============================================================"
    
    if [ "$HIGH_COUNT" -gt "0" ]; then
        echo ""
        echo "❌ COMMIT BLOCKED: $HIGH_COUNT HIGH severity vulnerabilities found!"
        echo ""
        echo "Please fix the HIGH severity issues before committing."
        echo "See: $OUTPUT_DIR/*.yaml for details"
        echo ""
        echo "To bypass this check (not recommended):"
        echo "  git commit --no-verify"
        echo ""
        exit 1
    fi
    
    echo ""
    echo "✅ Security scan passed. Proceeding with commit."
    echo ""
else
    echo "⚠️  Warning: No policy file generated. Scan may have failed."
    echo "Check: $OUTPUT_DIR/scan.log"
    exit 1
fi

# Cleanup (optional - comment out to keep results)
# rm -rf "$OUTPUT_DIR"

exit 0
