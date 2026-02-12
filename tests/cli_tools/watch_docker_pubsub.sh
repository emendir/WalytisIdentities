#!/bin/bash
CONTAINER_ID=${CONTAINER_ID:-$(docker ps -q -f 'ancestor=local/walid_testing' | head -n 1)}
watch bash -c "'docker exec $CONTAINER_ID /opt/walytis_identities/tests/cli_tools/check_ipfs_pubsub_peers.sh'"
