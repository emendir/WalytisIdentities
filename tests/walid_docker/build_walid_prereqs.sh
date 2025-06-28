#!/bin/bash
# Get the directory of this script
work_dir="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# change to root directory of the Brenthy repo
cd $work_dir/../..

rsync -XAva ../../IPFS-Monitoring tests/walid_docker/
rsync -XAva ../../MultiCrypt tests/walid_docker/python_packages/
rsync -XAva ../../Brenthy/Brenthy/blockchains/Walytis_Beta tests/walid_docker/python_packages/
rsync -XALva ../../Brenthy/Deployment/walytis_beta_embedded tests/walid_docker/python_packages/

docker build -t local/walid_prereqs -f tests/walid_docker/walid_prereqs.dockerfile .

## Run with:
# docker run -it --privileged local/walid_prereqs