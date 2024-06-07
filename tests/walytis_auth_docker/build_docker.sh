#!/bin/bash
# Get the directory of this script
work_dir="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# change to root directory of the Brenthy repo
cd $work_dir/../..

cp -r ../../MultiCrypt tests/walytis_auth_docker/MultiCrypt/



docker build -t local/walytis_auth -f tests/walytis_auth_docker/dockerfile .

## Run with:
# docker run -it --privileged local/walytis_auth