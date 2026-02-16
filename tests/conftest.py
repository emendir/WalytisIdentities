"""Script for configuring tests.

Runs automatically when pytest runs a test before loading the test module.
"""

from time import sleep
import threading
import time
from ipfs_remote import IpfsRemote
from ipfs_node import IpfsNode
from datetime import datetime
import logging
import os
import sys

import pytest
from emtest import (
    add_path_to_python,
    are_we_in_docker,
    assert_is_loaded_from_source,
    configure_pytest_reporter,
    set_env_var,
)

from emtest import (
    get_pytest_report_dirs,
)
from emtest.log_utils import get_app_log_dir

PRINT_ERRORS = (
    True  # whether or not to print error messages after failed tests
)
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJ_DIR = os.path.dirname(TESTS_DIR)
SRC_DIR = os.path.join(PROJ_DIR, "src")

os.chdir(TESTS_DIR)

# add source code paths to python's search paths
add_path_to_python(SRC_DIR)


logger_tests = logging.getLogger("Tests-WalId")
logger_tests.setLevel(logging.DEBUG)
logger_pytest = logging.getLogger("Pytest")
logger_pytest.setLevel(logging.DEBUG)


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    """Make changes to pytest's behaviour."""
    configure_pytest_reporter(
        config, print_errors=PRINT_ERRORS, logger=logger_pytest
    )
    terminal = config.pluginmanager.get_plugin("terminalreporter")
    if terminal:
        terminal.write_line(f"Python {sys.version.split(' ')[0]}")


def pytest_sessionfinish(
    session: pytest.Session,
    exitstatus: pytest.ExitCode,
) -> None:
    """Clean up after pytest has finished."""
    os._exit(int(exitstatus))  # force close terminating dangling threads


@pytest.fixture(scope="module")
def test_name(request: pytest.FixtureRequest):
    module = request.module
    module_name = module.__name__
    print(module_name)
    return module_name


@pytest.fixture(scope="session")
def test_report_dirs(
    pytestconfig: pytest.Config,
):
    return get_pytest_report_dirs(pytestconfig)


@pytest.fixture(scope="module", autouse=True)
def test_module_start_time(
    pytestconfig: pytest.Config,
):
    return datetime.now()


if True:
    # Walytis Config: use Brenthy by default if not otherwise specified by env var
    if are_we_in_docker():
        os.environ["USE_IPFS_NODE"] = "false"
        os.environ["WALYTIS_BETA_API_TYPE"] = "WALYTIS_BETA_BRENTHY_API"
    set_env_var(
        "WALYTIS_BETA_API_TYPE", "WALYTIS_BETA_BRENTHY_API", override=False
    )

    # set_env_var(
    #     "WALYTIS_BETA_LOG_PATH",
    #     os.path.join(os.getcwd(), "Walytis.log"),
    #     override=True,
    # )
    print("IPFS_TK_MODE", os.environ.get("IPFS_TK_MODE"))
    set_env_var("WALY_LOG_DIR", "/opt/log", override=False)
    import walytis_beta_api
    import walytis_beta_embedded
    from brenthy_tools_beta import BrenthyNotRunningError, brenthy_api
    from walytis_beta_tools._experimental.ipfs_interface import ipfs

    def assert_brenthy_online(timeout: int = 2) -> None:
        """Check if Brenthy is reachable, raising an error if not."""
        brenthy_api.get_brenthy_version(timeout=timeout)

    # walytis_beta_tools.log.logger_blockchain_model.setLevel(logging.DEBUG)
    # walytis_beta_tools.log.file_handler.setLevel(logging.DEBUG)
    USING_BRENTHY = (
        walytis_beta_api.walytis_beta_interface.get_walytis_beta_api_type()
        == walytis_beta_api.walytis_beta_interface.WalytisBetaApiTypes.WALYTIS_BETA_BRENTHY_API
    )
    if USING_BRENTHY:
        while True:
            try:
                assert_brenthy_online()
                break
            except BrenthyNotRunningError as e:
                print(e)
                print("Retrying to connect to brenthy...")
    else:
        walytis_beta_embedded.set_appdata_dir("./.blockchains")
        walytis_beta_embedded.run_blockchains()
    walytis_beta_embedded.set_appdata_dir("./.blockchains")
    print("IPFS Peer ID:", ipfs.peer_id)

    import walytis_identities

    if not are_we_in_docker():
        assert_is_loaded_from_source(SRC_DIR, walytis_identities)

    from walytis_identities.log import (
        file_handler,
        console_handler,
        formatter,
    )

    plain_console_handler = logging.StreamHandler()
    plain_console_handler.setLevel(logging.DEBUG)

    file_handler_tests = logging.handlers.RotatingFileHandler(
        os.path.join(
            get_app_log_dir("WalId_Tests", "Waly"), "Tests-WalId.log"
        ),
        maxBytes=4 * 1024 * 1024,
        backupCount=4,
    )
    file_handler_tests.setLevel(logging.DEBUG)
    file_handler_tests.setFormatter(formatter)
    logger_tests.addHandler(file_handler_tests)
    logger_tests.addHandler(plain_console_handler)

    logger_pytest.addHandler(plain_console_handler)
    logger_pytest.addHandler(file_handler_tests)

    file_handler.setLevel(logging.DEBUG)
    console_handler.setLevel(logging.DEBUG)

    # add logging for IPFS-Toolkit
    from ipfs_tk_transmission.log import logger_transm, logger_conv

    file_handler_ipfs = logging.handlers.RotatingFileHandler(
        os.path.join(get_app_log_dir("IPFS_TK", "Waly"), "IPFS_TK.log"),
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
    )
    file_handler_ipfs.setLevel(logging.DEBUG)
    file_handler_ipfs.setFormatter(formatter)

    logger_transm.addHandler(file_handler_ipfs)
    logger_conv.addHandler(file_handler_ipfs)
    logger_conv.setLevel(logging.DEBUG)
    logger_transm.setLevel(logging.DEBUG)

    disabled_loggers = ["urllib3.connectionpool"]
    for logger_name in disabled_loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.WARNING)


def cleanup_walytis_ipfs():
    if not USING_BRENTHY:
        print("Terminating Walytis...")
        walytis_beta_embedded.terminate()

    if isinstance(ipfs, IpfsNode):
        ipfs.terminate()
    else:
        # remove connections to old docker containers
        ipfs.peers.disconnect(ipfs.peers.list_peers())
