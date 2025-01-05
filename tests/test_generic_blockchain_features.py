from walytis_beta_api._experimental import generic_blockchain_testing
import _testing_utils
from walytis_beta_api._experimental.generic_blockchain_testing import test_generic_blockchain
from walytis_beta_api import Blockchain
from mutablockchain import MutaBlockchain
import os
import pytest
import shutil
from walidentity.did_manager import DidManager
from walidentity.did_objects import Key
from walidentity.group_did_manager import GroupDidManager
from walidentity.key_store import KeyStore
import tempfile


def test_preparations() -> None:
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


def test_cleanup() -> None:
    """Clean up resources used during tests."""
    if pytest.group_1:
        pytest.group_1.delete()
    if pytest.member_1:
        pytest.member_1.delete()

    shutil.rmtree(pytest.person_config_dir)
    shutil.rmtree(pytest.person_config_dir2)


def test_member():
    test_generic_blockchain(DidManager, key_store=pytest.device_did_keystore)


def test_group():
    test_generic_blockchain(
        GroupDidManager, group_key_store=pytest.profile_did_keystore, member=pytest.member_1)


def run_tests():
    test_preparations()
    test_member()
    test_group()
    test_cleanup()


if __name__ == "__main__":
    generic_blockchain_testing.PYTEST = False
    run_tests()
