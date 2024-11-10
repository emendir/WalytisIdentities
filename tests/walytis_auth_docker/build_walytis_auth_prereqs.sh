#!/bin/bash
# Get the directory of this script
work_dir="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# change to root directory of the Brenthy repo
cd $work_dir/../..

rsync -XAva ../../IPFS-Monitoring tests/walytis_auth_docker/
rsync -XAva ../../MultiCrypt tests/walytis_auth_docker/python_packages/
rsync -XAva ../../Brenthy/Brenthy/blockchains/Walytis_Beta tests/walytis_auth_docker/python_packages/

docker build -t local/walytis_auth_prereqs -f tests/walytis_auth_docker/walytis_auth_prereqs.dockerfile .

## Run with:
# docker run -it --privileged local/walytis_auth_prereqs