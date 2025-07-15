#!/bin/bash

set -e # exit on error

# the directory of this script
SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# the root directory of this project
PROJ_DIR=$(realpath $SCRIPT_DIR/../..)
cd $PROJ_DIR

# copy all paths listed in ./python_packages.txt to ./python_packages/
# paths are relative to $PROJ_DIR
PYTHON_PACKAGES_DIR="$SCRIPT_DIR/python_packages/"
PACKAGES_LIST="$SCRIPT_DIR/python_packages.txt"
if ! [ -e $PYTHON_PACKAGES_DIR ];then
    mkdir -p $PYTHON_PACKAGES_DIR
fi
if [[ -f "$PACKAGES_LIST" ]]; then
    while IFS= read -r line; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^# ]] && continue

        rsync -XAvaL "$line" "$PYTHON_PACKAGES_DIR"
    done < "$PACKAGES_LIST"
fi



docker build -t local/walid_prereqs -f tests/walid_docker/walid_prereqs.dockerfile .

## Run with:
# docker run -it --privileged local/walid_prereqs
