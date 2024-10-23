#!/bin/bash
# Get the directory of this script
work_dir="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# change to root directory of the Brenthy repo
cd $work_dir/../..

rsync -XAva ../../MultiCrypt tests/priblocks_docker/python_packages/
rsync -XAva ../../Brenthy/blockchains/Walytis_Beta tests/priblocks_docker/python_packages/


docker build -t local/walytis_auth_testing -f tests/walytis_auth_docker/walytis_auth_testing.dockerfile .

## Run with:
# docker run -it --privileged local/walytis_auth_testing