import _auto_run_with_pytest  # noqa
import _testing_utils
from walytis_beta_api._experimental import generic_blockchain_testing
from time import sleep
import _testing_utils
from walytis_beta_api._experimental.generic_blockchain_testing import test_generic_blockchain
from walytis_beta_api import Blockchain
import os
import pytest
import shutil
from walytis_identities.did_manager import DidManager
from walytis_identities.did_objects import Key
from walytis_identities.group_did_manager import GroupDidManager
from walytis_identities.key_store import KeyStore
import tempfile
from datetime import datetime
import walytis_beta_api as waly
import os
import shutil
import tempfile

import walytis_identities
import pytest
import walytis_beta_api as walytis_api
from _testing_utils import mark, test_threads_cleanup
from walytis_identities.did_objects import Key
from walytis_identities import did_manager_with_supers
from walytis_identities.did_manager_with_supers import DidManagerWithSupers, GroupDidManager
# walytis_api.log.PRINT_DEBUG = False

_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.dirname(os.path.dirname(__file__)), module=did_manager_with_supers
)
_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.join(os.path.dirname(__file__), "..", ".."), module=walytis_identities
)


@pytest.fixture(scope="module", autouse=True)
def setup_and_teardown() -> None:
    """Wrap around tests, running preparations and cleaning up afterwards.

    A module-level fixture that runs once for all tests in this file.
    """
    # Setup: code here runs before tests that uses this fixture
    print(f"\nRunning tests for {__name__}\n")
    prepare()

    yield  # This separates setup from teardown

    # Teardown: code here runs after the tests
    print(f"\nFinished tests for {__name__}\n")
    cleanup()
def prepare() -> None:
    """Setup resources in preparation for tests."""
    # declare 'global' variables
    pytest.profile_config_dir = tempfile.mkdtemp()
    pytest.key_store_path = os.path.join(
        pytest.profile_config_dir, "master_keystore.json")

    # the cryptographic family to use for the tests
    pytest.CRYPTO_FAMILY = "EC-secp256k1"
    pytest.KEY = Key.create(pytest.CRYPTO_FAMILY)

    config_dir = pytest.profile_config_dir
    key = pytest.KEY

    device_keystore_path = os.path.join(config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(
        config_dir, "profile_keystore.json")

    pytest.device_did_keystore = KeyStore(device_keystore_path, key)
    pytest.profile_did_keystore = KeyStore(profile_keystore_path, key)
    pytest.device_did_manager = DidManager.create(pytest.device_did_keystore)
    pytest.dmws_did_manager = GroupDidManager.create(
        pytest.profile_did_keystore, pytest.device_did_manager
    )
    pytest.dmws_did_manager.terminate()
    pytest.group_did_manager = GroupDidManager(
        pytest.profile_did_keystore,
        pytest.device_did_manager,
        auto_load_missed_blocks=False
    )
    dmws = DidManagerWithSupers(
        did_manager=pytest.group_did_manager,
    )

    pytest.dmws = dmws
    pytest.super = pytest.dmws.create_super()
    sleep(1)
    pytest.dmws.terminate()


def cleanup() -> None:
    """Clean up resources used during tests."""
    if pytest.dmws:
        pytest.dmws.delete()

    shutil.rmtree(pytest.profile_config_dir)


def test_profile():
    print("Running test for DidManagerWithSupers...")
    pytest.group_did_manager = GroupDidManager(
        pytest.profile_did_keystore,
        pytest.device_did_manager,
        auto_load_missed_blocks=False
    )
    dmws = test_generic_blockchain(
        DidManagerWithSupers,
        did_manager=pytest.group_did_manager
    )
    dmws.terminate()


def test_super():
    print("Running test for Super...")
    super = test_generic_blockchain(
        GroupDidManager,
        group_key_store=pytest.super.key_store,
        member=pytest.super.member_did_manager.key_store
    )
    super.terminate()
from emtest import await_thread_cleanup
def test_threads_cleanup() -> None:
    """Test that no threads are left running."""
    cleanup()
    assert await_thread_cleanup(timeout=5)


def run_tests():
    print("Running test for DidManagerWithSupers Generic Blockchain features...")
    prepare()
    test_profile()
    test_super()
    pytest.group_did_manager.terminate()
    pytest.super.terminate()
    pytest.dmws.terminate()
    cleanup()


if __name__ == "__main__":
    _testing_utils.PYTEST = False
    _testing_utils.BREAKPOINTS = False
    run_tests()
    _testing_utils.terminate()
    