from walytis_identities.log import LOG_TIMESTAMP_FORMAT
import pytest
from walid_docker.walid_docker import (
    WalytisIdentitiesDocker,
    delete_containers,
)
from emtest import (
    get_pytest_report_dirs,
)
from emtest.log_utils import collect_logs
import shutil
from datetime import datetime
from pathlib import Path
import os
from datetime import datetime, UTC
from walytis_identities.log import console_handler
from walytis_identities.key_objects import Key
import logging

from brenthy_docker.utils import get_logs_and_delete_dockers  # noqa

DOCKER_LOG_FILES = [
    "/opt/Brenthy/Brenthy.log",
    "/opt/Brenthy/Brenthy_Walytis.log",
    "/opt/log/Walytis_Beta/Walytis_Beta.log",
    "/opt/log/WalytisIdentities/WalytisIdentities.log",
    "/opt/log/WalytisOffchain/WalytisOffchain.log",
    "/opt/log/WalytisMutability/WalytisMutability.log",
    "/opt/log/IPFS_TK/IPFS_TK.log",
    "/opt/log/WalId_Tests/Tests-WalId.log",
    "/opt/log/IpfsPeersLogger/ipfs_peers_logger.log",
]
HOST_LOG_FILES = [
    "/opt/Brenthy/Brenthy.log",
    "/opt/Brenthy/Brenthy_Walytis.log",
    "/opt/log/Walytis_Beta/Walytis_Beta.log",
    "/opt/log/WalytisIdentities/WalytisIdentities.log",
    "/opt/log/WalytisOffchain/WalytisOffchain.log",
    "/opt/log/WalytisMutability/WalytisMutability.log",
    "/opt/log/IPFS_TK/IPFS_TK.log",
    "/opt/log/WalId_Tests/Tests-WalId.log",
    "/opt/log/IpfsPeersLogger/ipfs_peers_logger.log",
]
console_handler.setLevel(logging.DEBUG)

CRYPTO_FAMILY = "EC-secp256k1"
KEY = Key(
    family=CRYPTO_FAMILY,
    public_key=b"\x04\xa6#\x1a\xcf\xa7\xbe\xa8\xbf\xd9\x7fd\xa7\xab\xba\xeb{Wj\xe2\x8fH\x08*J\xda\xebS\x94\x06\xc9\x02\x8c9>\xf45\xd3=Zg\x92M\x84\xb3\xc2\xf2\xf4\xe6\xa8\xf9i\x82\xdb\xd8\x82_\xcaIT\x14\x9cA\xd3\xe1",
    private_key=b"\xd9\xd1\\D\x80\xd7\x1a\xe6E\x0bt\xdf\xd0z\x88\xeaQ\xe8\x04\x91\x11\xaf\\%wC\x83~\x0eGP\xd8",
    creation_time=datetime(2024, 11, 6, 19, 17, 45, 713000, tzinfo=UTC),
)

dm_config_dir = "/tmp/wali_test_dmws_synchronisation"

# used for creation, first loading test, and invitation creation
PROFILE_CREATE_TIMEOUT_S = 20
PROFILE_JOIN_TIMEOUT_S = 60
CORRESP_JOIN_TIMEOUT_S = 60


def cleanup_logs():
    for log_file in HOST_LOG_FILES:
        if os.path.exists(log_file):
            print("Removing log file", log_file)
            os.remove(log_file)
        else:
            print("Log file not found", log_file)


def collect_all_test_logs(
    test_name: str,
    docker_containers: list[WalytisIdentitiesDocker],
    test_report_dirs: list[str],
    test_start_time: datetime,
):
    """Gather logs from host and docker containers.

    WARNING: deletes the given docker containers.
    Copies logs to all report directories registered in pytest.
    """
    report_dirs = [os.path.join(d, test_name) for d in test_report_dirs]
    # get logs from, then delete containers
    get_logs_and_delete_dockers(
        docker_containers,
        DOCKER_LOG_FILES,
        report_dirs,
    )
    collect_logs(
        HOST_LOG_FILES,
        report_dirs,
        test_start_time,
        LOG_TIMESTAMP_FORMAT,
        " ",
        "host-",
    )
