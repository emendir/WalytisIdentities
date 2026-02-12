#!/bin/bash
SCRIPT_PATH=$BASH_SOURCE[0]
# Detect if the script is being executed instead of sourced
(return 0 2>/dev/null) && sourced=1 || sourced=0
if [ "$sourced" -eq 0 ]; then
    # the absolute path of this script's directory
    echo "Error: This script must be sourced, not executed." >&2

    echo "Run:" >&2
    echo "source $(realpath $SCRIPT_PATH)" >&2
    exit 1
fi

SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

PYTEST_DIR=$(dirname "$SCRIPT_DIR")
export PYTEST_DIR
export PYTEST_REPORTS_DIR="$PYTEST_DIR/reports"
