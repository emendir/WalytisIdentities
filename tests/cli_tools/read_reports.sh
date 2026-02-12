#!/bin/bash

set -euo pipefail # Exit if any command fails

# the absolute path of this script's directory
SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source "$SCRIPT_DIR/config.sh"


if [ -z "$PYTEST_DIR" ];then
    echo "PYTEST_DIR is not defined in config.h or environment."
fi
if [ -z "$PYTEST_REPORTS_DIR" ];then
    echo "PYTEST_REPORTS_DIR is not defined in config.h or environment."
fi

cd "$PYTEST_DIR"

# -----------------------------
# Defaults
# -----------------------------
DEFAULT_PATTERNS=("WARNING" "ERROR" "Test FAILED")

# Find last alphabetically sorted tests/reports/report-* directory
DEFAULT_REPORT_DIR=$(
  ls -d $PYTEST_REPORTS_DIR/report-* 2>/dev/null | sort | tail -n 1
  ) || ( echo "Failed to find report directories." >&2 && exit 1 )


DEFAULT_LOG_GLOB="${DEFAULT_REPORT_DIR}/test_*/*.log"

# -----------------------------
# Parse arguments
# -----------------------------
# Usage:
#   group_logs.sh [log_glob] [pattern1 pattern2 ...]
#
# Examples:
#   group_logs.sh
#   group_logs.sh "tests/reports/report-42/*.log"
#   group_logs.sh "tests/reports/report-42/*.log" WARNING ERROR FATAL

LOG_GLOB="${1:-$DEFAULT_LOG_GLOB}"
if [[ -z "${LOG_GLOB}" ]]; then
  echo "No log directories found" >&2
  exit 1
else
    echo "Reading log files:"
    echo "$LOG_GLOB"
    echo ""
    ls $LOG_GLOB
fi

if [[ $# -ge 2 ]]; then
  shift
  PATTERNS=("$@")
else
  PATTERNS=("${DEFAULT_PATTERNS[@]}")
fi

echo "
Looking for:
${PATTERNS[@]}
"
# Build grep pattern (OR-ed)
GREP_PATTERN=$(printf "|%s" "${PATTERNS[@]}")
GREP_PATTERN="${GREP_PATTERN:1}"

# -----------------------------
# Main loop
# -----------------------------
shopt -s nullglob
FILES=($LOG_GLOB)

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "No log files matched: $LOG_GLOB" >&2
  exit 1
fi

echo ""

for f in "${FILES[@]}"; do
  if grep -Eq "$GREP_PATTERN" "$f"; then
    printf '━%.0s' $(seq 1 "$(tput cols)")
    echo ""
    echo "$f"
    printf '─%.0s' $(seq 1 "$(tput cols)")
    echo ""
    grep -E "$GREP_PATTERN" "$f"
    echo
  fi
done
