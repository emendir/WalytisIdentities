TEST_CMD='python test_key_renewal.py --html=reports/report-$(date +%Y_%m_%d-%H_%M_%S)/report.html --timeout 150'
# TEST_CMD='python run_all_tests.py'

set -euo pipefail # Exit if any command fails

export TESTS_REBUILD_DOCKER=0

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

# rm -rf $PYTEST_REPORTS_DIR || true

walid_docker/build_walid_testing.sh



EMBEDDED=0
if [ $EMBEDDED -eq 1 ];then
    export WALYTIS_BETA_API_TYPE=WALYTIS_BETA_DIRECT_API
    export IPFS_TK_MODE=EMBEDDED
    sudo systemctl stop ipfs brenthy
else
    "$SCRIPT_DIR/limit_ipfs.sh"
fi

while true; do
    # # break if any test failures are identitified
    # grep -RI WARNING ./reports/report-*/test*/ 2>/dev/null && break
    # grep -RI ERROR ./reports/report-*/test*/ 2>/dev/null && break
    # grep -RI "Test Failed" ./reports/report-*/test*/ 2>/dev/null && break

    sudo systemctl stop brenthy 
    sudo rm -rf /opt/Brenthy/BlockchainData/Walytis_Beta/Qm* || true 
    sudo systemctl restart ipfs brenthy
    sudo systemctl restart docker
    # wait until ipfs is online again
    until ipfs swarm peers 2>/dev/null 1>&2;do sleep 1;done

    bash -c "$TEST_CMD" || true
    sleep 10
done
