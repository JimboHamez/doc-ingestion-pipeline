#!/usr/bin/env bash

# Static-analysis / security scan for the doc-ingestion-pipeline scripts.
#
# Runs bandit, semgrep, mypy and pip-audit against the three pipeline stages'
# Python (pre-conversion-scan/, doc-to-markdown/, doc-security-scan/) and
# audits the declared dependency set in requirements.txt.
#
# Tools are installed into a local .venv so they don't collide with
# system-managed packages (e.g. a Debian-provided jsonschema).
#
# Usage:
#   ./scan.sh                 # scan the three stages' scripts/ dirs
#   ./scan.sh path/to/dir     # scan a different target directory instead

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

# Default targets: the Python for each pipeline stage. Override with $1.
if [ -n "$1" ]; then
    if [ ! -d "$1" ]; then
        echo "Error: target directory not found: $1"
        exit 1
    fi
    TARGETS=("$1")
else
    TARGETS=(
        "$SCRIPT_DIR/pre-conversion-scan/scripts"
        "$SCRIPT_DIR/doc-to-markdown/scripts"
        "$SCRIPT_DIR/doc-security-scan/scripts"
    )
fi
echo "Scan targets: ${TARGETS[*]}"

echo "=== 1. Setting up Virtual Environment ==="
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment in $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
fi
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "=== 2. Ensuring Python Tools are Installed ==="
pip install --quiet --upgrade pip

TOOLS=(bandit semgrep mypy pip-audit)
for tool in "${TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo "$tool not found. Installing..."
        pip install --quiet "$tool"
    else
        echo "$tool is already installed."
    fi
done

echo "=== 3. Running Scanners ==="

# 1. Bandit: recurse the targets for common security issues.
echo "--> Running Bandit..."
bandit -r "${TARGETS[@]}" || echo "Bandit found issues."

# 2. Semgrep: auto ruleset against the targets.
echo "--> Running Semgrep..."
semgrep scan --config auto --quiet "${TARGETS[@]}" || echo "Semgrep found issues."

# 3. Mypy: static type checking. --ignore-missing-imports because the runtime
#    deps (markitdown, fitz/PyMuPDF, pytesseract, oletools, pikepdf, ...) ship
#    no type stubs; we care about our own code type-checking, not theirs.
echo "--> Running Mypy..."
mypy --ignore-missing-imports "${TARGETS[@]}" || echo "Mypy found type errors."

# 4. Pip-audit: audit the declared dependency set for known-vulnerable packages.
echo "--> Running Pip-audit..."
pip-audit -r "$SCRIPT_DIR/requirements.txt" || echo "Pip-audit found vulnerable packages."

echo "=== 4. Cleaning Up ==="
deactivate

echo "Done!"
