"""Script for configuring tests.

Runs automatically when pytest runs a test before loading the test module.
"""

import logging
import os

import pytest
from emtest import (
    add_path_to_python,
    are_we_in_docker,
    assert_is_loaded_from_source,
    configure_pytest_reporter,
    set_env_var,
)
from loguru import logger

PRINT_ERRORS = (
    True  # whether or not to print error messages after failed tests
)

WORKDIR = os.path.dirname(os.path.abspath(__file__))
PROJ_DIR = os.path.dirname(WORKDIR)
SRC_DIR = os.path.join(PROJ_DIR, "src")

os.chdir(WORKDIR)

# add source code paths to python's search paths
add_path_to_python(SRC_DIR)


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    """Make changes to pytest's behaviour."""
    configure_pytest_reporter(config, print_errors=PRINT_ERRORS)


if True:
    # Walytis Config: use Brenthy by default if not otherwise specified by env var
    if are_we_in_docker():
        os.environ["USE_IPFS_NODE"] = "false"
        os.environ["WALYTIS_BETA_API_TYPE"] = "WALYTIS_BETA_BRENTHY_API"
    set_env_var(
        "WALYTIS_BETA_API_TYPE", "WALYTIS_BETA_BRENTHY_API", override=False
    )

    set_env_var(
        "WALYTIS_BETA_LOG_PATH",
        os.path.join(os.getcwd(), "Walytis.log"),
        override=True,
    )
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
    logger.info(f"USING BRENTHY: {USING_BRENTHY}")
    if USING_BRENTHY:
        while True:
            try:
                assert_brenthy_online()
                break
            except BrenthyNotRunningError as e:
                logger.error(e)
                logger.info("Retrying to connect to brenthy...")
    else:
        walytis_beta_embedded.set_appdata_dir("./.blockchains")
        walytis_beta_embedded.run_blockchains()
    walytis_beta_embedded.set_appdata_dir("./.blockchains")
    print("IPFS Peer ID:", ipfs.peer_id)

    import walytis_identities

    if not are_we_in_docker():
        assert_is_loaded_from_source(SRC_DIR, walytis_identities)
    walytis_identities.log.console_handler.setLevel(logging.DEBUG)
