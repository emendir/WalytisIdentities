from walytis_identities.log import LOG_TIMESTAMP_FORMAT
import pytest
from walid_docker.walid_docker import (
    WalytisIdentitiesDocker,
    delete_containers,
)
from emtest import (
    await_thread_cleanup,
    env_vars,
    polite_wait,
    ensure_dir_exists,
    get_pytest_report_dirs,
)
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
    "/opt/log/WalId_Tests/WalIdTests.log",
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
    "/opt/log/WalId_Tests/WalIdTests.log",
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


def copy_logs_from_starttime(
    logfile_path: str | Path,
    target_path: str | Path,
    pytest_start_time: datetime,
    timestamp_format: str,
    timestamp_next_char: str,
) -> Path:
    """
    Copy log lines from `logfile_path` starting at the first line whose
    timestamp is >= `pytest_start_time`, then copy all remaining lines
    verbatim into a new logfile at `target_path`.
    """
    logfile_path = Path(logfile_path)
    target_path = Path(target_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    copying = False

    with (
        logfile_path.open("r", encoding="utf-8") as src,
        target_path.open("w", encoding="utf-8") as dst,
    ):
        for line in src:
            if not copying:
                # Try to parse timestamp only until we find the first match
                try:
                    timestamp_str = line.split(timestamp_next_char)[0]
                    timestamp = datetime.strptime(
                        timestamp_str,
                        timestamp_format,
                    )
                except (ValueError, IndexError):
                    continue

                if timestamp >= pytest_start_time:
                    copying = True
                    dst.write(line)
            else:
                # After the cut point, copy everything verbatim
                dst.write(line)
    if not copying:
        print("Didn't find timestamp!")
        print(logfile_path)
    return target_path


def collect_all_test_logs(
    test_name,
    docker_containers: list[WalytisIdentitiesDocker],
    pytest_data: pytest.Config,
    test_start_time: datetime,
):
    """Gather logs from host and docker containers.


    WARNING: deletes the given docker containers.
    Copies logs to all report directories registered in pytest.
    """
    # get logs from, then delete containers
    get_logs_and_delete_dockers(
        docker_containers,
        DOCKER_LOG_FILES,
        [
            os.path.join(d, test_name)
            for d in get_pytest_report_dirs(pytest_data)
        ],
    )

    for report_dir in get_pytest_report_dirs(pytest_data):
        target_dir = ensure_dir_exists(os.path.join(report_dir, test_name))

        for log_file in HOST_LOG_FILES:
            if not os.path.exists(log_file):
                print(f"Log file not found: {log_file}")
                continue
            target_path = os.path.join(
                target_dir, f"host-{os.path.basename(log_file)}"
            )
            copy_logs_from_starttime(
                log_file,
                target_path,
                test_start_time,
                LOG_TIMESTAMP_FORMAT,
                " ",
            )
