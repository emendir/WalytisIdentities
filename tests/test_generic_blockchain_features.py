import _auto_run_with_pytest  # noqa
import _testing_utils
from _testing_utils import test_threads_cleanup
import os
import shutil
import tempfile

import pytest
from walytis_identities.did_manager import DidManager
from walytis_identities.did_objects import Key
from walytis_identities.group_did_manager import GroupDidManager
from walytis_identities.key_store import KeyStore
from walytis_beta_api._experimental import generic_blockchain_testing
from walytis_beta_api._experimental.generic_blockchain_testing import (
    test_generic_blockchain,
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
    pytest.person_config_dir = tempfile.mkdtemp()
    pytest.person_config_dir2 = tempfile.mkdtemp()
    pytest.key_store_path = os.path.join(
        pytest.person_config_dir, "master_keystore.json")
    # the cryptographic family to use for the tests
    pytest.CRYPTO_FAMILY = "EC-secp256k1"
    pytest.KEY = Key.create(pytest.CRYPTO_FAMILY)
    device_keystore_path = os.path.join(
        pytest.person_config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(
        pytest.person_config_dir, "profile_keystore.json")
    pytest.device_did_keystore = KeyStore(device_keystore_path, pytest.KEY)
    pytest.profile_did_keystore = KeyStore(profile_keystore_path, pytest.KEY)
    pytest.member_1 = DidManager.create(pytest.device_did_keystore)
    pytest.group_1 = GroupDidManager.create(
        pytest.profile_did_keystore, pytest.member_1
    )
    pytest.group_1.terminate()


def cleanup() -> None:
    """Clean up resources used during tests."""
    print("Cleaning up...")
    if pytest.group_1:
        pytest.group_1.delete()
    if pytest.member_1:
        pytest.member_1.delete()
    print("Cleaned up!")

    shutil.rmtree(pytest.person_config_dir)
    shutil.rmtree(pytest.person_config_dir2)


def test_member():
    print("\nRunning Generic Blockchain feature tests for DidManager...")
    test_generic_blockchain(DidManager, key_store=pytest.device_did_keystore)


def test_group():
    print("\nRunning Generic Blockchain feature tests for GroupDidManager...")
    test_generic_blockchain(
        GroupDidManager, group_key_store=pytest.profile_did_keystore, member=pytest.member_1)
from emtest import await_thread_cleanup
def test_threads_cleanup() -> None:
    """Test that no threads are left running."""
    cleanup()
    assert await_thread_cleanup(timeout=5)


def run_tests():
    prepare()
    test_member()
    test_group()
    cleanup()
    test_threads_cleanup()



if __name__ == "__main__":
    _testing_utils.PYTEST = False
    _testing_utils.BREAKPOINTS = False
    run_tests()
    _testing_utils.terminate()
    