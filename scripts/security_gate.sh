#!/usr/bin/env bash
set -euo pipefail

# KEYOPS SECURITY RELEASE GATE RUNNER
# Fail-closed execution of all verification stages.

echo "================================================================================"
echo "🛡️  KEYOPS COMPREHENSIVE SECURITY RELEASE GATE"
echo "================================================================================"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUNNER="uv run"
if ! command -v uv &> /dev/null; then
    if command -v /opt/homebrew/bin/uv &> /dev/null; then
        RUNNER="/opt/homebrew/bin/uv run"
    else
        RUNNER="python3"
    fi
fi

FAILED_GATES=0

run_gate() {
    local gate_name="$1"
    local command="$2"
    echo -n "[RUNNING] $gate_name ... "
    if eval "$command" > /dev/null 2>&1; then
        echo -e "\033[0;32m[PASS]\033[0m"
    else
        echo -e "\033[0;31m[FAIL]\033[0m"
        FAILED_GATES=$((FAILED_GATES + 1))
    fi
}

echo ""
echo "1. Core Compilation & Syntax Gates:"
run_gate "Python Compileall (app tests)" "$RUNNER python -m compileall app tests"

echo ""
echo "2. System Usability & Diagnostics Gates:"
run_gate "Doctor Environment & Chromium Launch Check" "$RUNNER python -m app.cli.doctor"

echo ""
echo "3. Automated Test Suites Gates:"
run_gate "Unit Tests (tests/unit)" "$RUNNER pytest -q tests/unit"
run_gate "Security Invariants & Adversarial Tests (tests/security)" "$RUNNER pytest -q tests/security"
run_gate "Integration & Real Playwright Attacks (tests/integration)" "$RUNNER pytest -q tests/integration"
run_gate "Complete Pytest Suite" "$RUNNER pytest -q"

echo ""
echo "4. Static Security & Dependency Gates:"
run_gate "Static Security & Token Isolation Scan" "$RUNNER python scripts/static_security_scan.py"
run_gate "Dependency Vulnerability Audit (pip-audit)" "$RUNNER pip-audit"

echo ""
echo "================================================================================"
if [ "$FAILED_GATES" -eq 0 ]; then
    echo -e "\033[0;32m✓ ALL SECURITY GATES PASSED — SYSTEM IS RELEASE READY\033[0m"
    echo "================================================================================"
    exit 0
else
    echo -e "\033[0;31m✗ $FAILED_GATES SECURITY GATE(S) FAILED — SYSTEM IS NOT RELEASE READY\033[0m"
    echo "================================================================================"
    exit 1
fi
