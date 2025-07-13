import os
import shutil
import tempfile

import _auto_run_with_pytest  # noqa
from emtest import await_thread_cleanup
from walytis_beta_api._experimental import generic_blockchain_testing

from walytis_identities.did_manager import DidManager
from walytis_identities.did_objects import Key
from walytis_identities.group_did_manager import GroupDidManager
from walytis_identities.key_store import KeyStore


class SharedData:
    def __init__(self):
        """Setup resources in preparation for tests."""
        # declare 'global' variables
        self.person_config_dir = tempfile.mkdtemp()
        self.person_config_dir2 = tempfile.mkdtemp()
        self.key_store_path = os.path.join(
            self.person_config_dir, "master_keystore.json")
        # the cryptographic family to use for the tests
        self.CRYPTO_FAMILY = "EC-secp256k1"
        self.KEY = Key.create(self.CRYPTO_FAMILY)
        device_keystore_path = os.path.join(
            self.person_config_dir, "device_keystore.json")
        profile_keystore_path = os.path.join(
            self.person_config_dir, "profile_keystore.json")
        self.device_did_keystore = KeyStore(device_keystore_path, self.KEY)
        self.profile_did_keystore = KeyStore(profile_keystore_path, self.KEY)
        self.member_1 = DidManager.create(self.device_did_keystore)
        self.group_1 = GroupDidManager.create(
            self.profile_did_keystore, self.member_1
        )
        self.group_1.terminate()


shared_data = SharedData()


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


def test_member():
    print("\nRunning Generic Blockchain feature tests for DidManager...")
    blockchain = generic_blockchain_testing.run_generic_blockchain_test(

        DidManager, key_store=shared_data.device_did_keystore
    )
    blockchain.terminate()


def test_group():
    print("\nRunning Generic Blockchain feature tests for GroupDidManager...")
    blockchain = generic_blockchain_testing.run_generic_blockchain_test(
        GroupDidManager, group_key_store=shared_data.profile_did_keystore, 
        member=shared_data.member_1
    )
    blockchain.terminate()


def test_threads_cleanup() -> None:
    """Test that no threads are left running."""
    cleanup()
    assert await_thread_cleanup(timeout=5)

