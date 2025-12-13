import os
import shutil
import tempfile

import _auto_run_with_pytest  # noqa
from emtest import await_thread_cleanup
from conftest import cleanup_walytis_ipfs
from walytis_beta_api._experimental import generic_blockchain_testing

from walytis_identities.did_manager import DidManager
from walytis_identities.key_objects import Key
from walytis_identities.group_did_manager import GroupDidManager
from walytis_identities.key_store import KeyStore


class SharedData:
    member_1: DidManager
    group_1: GroupDidManager


shared_data = SharedData()


def test_preparations():
    """Setup resources in preparation for tests."""
    # declare 'global' variables
    shared_data.person_config_dir = tempfile.mkdtemp()
    shared_data.person_config_dir2 = tempfile.mkdtemp()
    shared_data.key_store_path = os.path.join(
        shared_data.person_config_dir, "master_keystore.json"
    )
    # the cryptographic family to use for the tests
    shared_data.CRYPTO_FAMILY = "EC-secp256k1"
    shared_data.KEY = Key.create(shared_data.CRYPTO_FAMILY)
    device_keystore_path = os.path.join(
        shared_data.person_config_dir, "device_keystore.json"
    )
    profile_keystore_path = os.path.join(
        shared_data.person_config_dir, "profile_keystore.json"
    )
    shared_data.device_did_keystore = KeyStore(
        device_keystore_path, shared_data.KEY
    )
    shared_data.profile_did_keystore = KeyStore(
        profile_keystore_path, shared_data.KEY
    )
    shared_data.member_1 = DidManager.create(shared_data.device_did_keystore)
    shared_data.group_1 = GroupDidManager.create(
        shared_data.profile_did_keystore, shared_data.member_1
    )
    shared_data.group_1.terminate()


def cleanup() -> None:
    """Clean up resources used during tests."""
    print("Cleaning up...")
    if shared_data.group_1:
        shared_data.group_1.delete()
    if shared_data.member_1:
        shared_data.member_1.delete()
    print("Cleaned up!")

    if os.path.exists(shared_data.person_config_dir):
        shutil.rmtree(shared_data.person_config_dir)
    if os.path.exists(shared_data.person_config_dir2):
        shutil.rmtree(shared_data.person_config_dir2)
    cleanup_walytis_ipfs()


def test_member():
    print("\nRunning Generic Blockchain feature tests for DidManager...")
    blockchain = generic_blockchain_testing.run_generic_blockchain_test(
        DidManager, key_store=shared_data.device_did_keystore
    )
    blockchain.terminate()


def test_group():
    print("\nRunning Generic Blockchain feature tests for GroupDidManager...")
    blockchain = generic_blockchain_testing.run_generic_blockchain_test(
        GroupDidManager,
        group_key_store=shared_data.profile_did_keystore,
        member=shared_data.member_1,
    )
    blockchain.terminate()


def test_threads_cleanup() -> None:
    """Test that no threads are left running."""
    cleanup()
    assert await_thread_cleanup(timeout=10)
