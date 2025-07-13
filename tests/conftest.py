"""Script for configuring tests.

Runs automatically when pytest runs a test before loading the test module.
"""
from emtest import assert_is_loaded_from_source
from emtest import set_env_var
from loguru import logger
from walytis_beta_tools._experimental.config import (
    WalytisTestModes,
    get_walytis_test_mode,
)
import os

import pytest
from emtest import (
    add_path_to_python,
    are_we_in_docker,
    configure_pytest_reporter,
)

PRINT_ERRORS = True  # whether or not to print error messages after failed tests

# add source code paths to python's search paths
PROJ_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(
    PROJ_DIR, "src"
)

add_path_to_python(SRC_DIR)


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    """Make changes to pytest's behaviour."""
    configure_pytest_reporter(config, print_errors=PRINT_ERRORS)

import logging
if True:
    # Walytis Config: use Brenthy by default if not otherwise specified by env var
    if are_we_in_docker():
        os.environ["USE_IPFS_NODE"] = "false"
        os.environ["WALYTIS_BETA_API_TYPE"] = "WALYTIS_BETA_BRENTHY_API"
    set_env_var("WALYTIS_BETA_API_TYPE",
                "WALYTIS_BETA_BRENTHY_API", override=False)

    set_env_var("WALYTIS_BETA_LOG_PATH", os.path.join(os.getcwd(), "Walytis.log"), override=True)
    from walytis_beta_tools._experimental.ipfs_interface import ipfs
    import walytis_beta_embedded
    import walytis_beta_api
    from brenthy_tools_beta import BrenthyNotRunningError
    import walytis_beta_tools
    # walytis_beta_tools.log.logger_blockchain_model.setLevel(logging.DEBUG)
    # walytis_beta_tools.log.file_handler.setLevel(logging.DEBUG)
    USING_BRENTHY = walytis_beta_api.walytis_beta_interface.get_walytis_beta_api_type(
    ) == walytis_beta_api.walytis_beta_interface.WalytisBetaApiTypes.WALYTIS_BETA_BRENTHY_API
    logger.info(f"USING BRENTHY: {USING_BRENTHY}")
    if USING_BRENTHY:
        while True:
            try:
                walytis_beta_api.list_blockchain_names()
                break
            except BrenthyNotRunningError as e:
                logger.error(e)
                logger.info("Retrying to connect to brenthy...")
    else:
        walytis_beta_embedded.set_appdata_dir("./.blockchains")
        walytis_beta_embedded.run_blockchains()
    print("IPFS Peer ID:", ipfs.peer_id)
    import walytis_identities
    if not are_we_in_docker():
        assert_is_loaded_from_source(SRC_DIR, walytis_identities)
    walytis_identities.log.console_handler.setLevel(logging.DEBUG)
    walytis_beta_embedded.set_appdata_dir("./.blockchains")
    