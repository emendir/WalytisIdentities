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

for dir in "$PYTEST_REPORTS_DIR"/report-*/test*; do
    failed_test_reports=$(grep -l "Test FAILED" "$dir"/*.log 2>/dev/null) || true

    if [ -n "$failed_test_reports" ]; then 
        echo $failed_test_reports

        for file in "$dir"/*.log;do
            errors_found=0
            if grep WARNING "$file" 2>/dev/null 1>&2; then errors_found=1; fi
            if grep ERROR "$file" 2>/dev/null 1>&2; then errors_found=1; fi

            if [ "$errors_found" -eq 1 ]; then
                echo "$file"
            fi
        done

        echo # blank line
    fi
done
