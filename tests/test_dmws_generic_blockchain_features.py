import os
import shutil
import tempfile
from time import sleep

import _auto_run_with_pytest  # noqa
from emtest import await_thread_cleanup
from walytis_beta_api._experimental import generic_blockchain_testing

from walytis_identities.did_manager import DidManager
from walytis_identities.did_manager_with_supers import (
    DidManagerWithSupers,
    GroupDidManager,
)
from walytis_identities.did_objects import Key
from walytis_identities.group_did_manager import GroupDidManager
from walytis_identities.key_store import KeyStore

# walytis_api.log.PRINT_DEBUG = False


class SharedData():
    def __init__(self):
        """Setup resources in preparation for tests."""
        # declare 'global' variables
        self.profile_config_dir = tempfile.mkdtemp()
        self.key_store_path = os.path.join(
            self.profile_config_dir, "master_keystore.json")

        # the cryptographic family to use for the tests
        self.CRYPTO_FAMILY = "EC-secp256k1"
        self.KEY = Key.create(self.CRYPTO_FAMILY)

        config_dir = self.profile_config_dir
        key = self.KEY

        device_keystore_path = os.path.join(config_dir, "device_keystore.json")
        profile_keystore_path = os.path.join(
            config_dir, "profile_keystore.json")

        self.device_did_keystore = KeyStore(device_keystore_path, key)
        self.profile_did_keystore = KeyStore(profile_keystore_path, key)
        self.device_did_manager = DidManager.create(self.device_did_keystore)
        self.dmws_did_manager = GroupDidManager.create(
            self.profile_did_keystore, self.device_did_manager
        )
        self.dmws_did_manager.terminate()
        self.group_did_manager = GroupDidManager(
            self.profile_did_keystore,
            self.device_did_manager,
            auto_load_missed_blocks=False
        )
        dmws = DidManagerWithSupers(
            did_manager=self.group_did_manager,
        )

        self.dmws = dmws
        self.super = self.dmws.create_super()
        sleep(1)
        self.dmws.terminate()

shared_data = SharedData()

def test_profile():
    print("Running test for DidManagerWithSupers...")
    shared_data.group_did_manager = GroupDidManager(
        shared_data.profile_did_keystore,
        shared_data.device_did_manager,
        auto_load_missed_blocks=False
    )
    dmws = generic_blockchain_testing.run_generic_blockchain_test(
        DidManagerWithSupers,
        did_manager=shared_data.group_did_manager
    )
    dmws.terminate()


def test_super():
    print("Running test for Super...")
    super = generic_blockchain_testing.run_generic_blockchain_test(
        GroupDidManager,
        group_key_store=shared_data.super.key_store,
        member=shared_data.super.member_did_manager.key_store
    )
    super.terminate()


def test_threads_cleanup() -> None:
    """Test that no threads are left running."""
    if shared_data.dmws:
        shared_data.dmws.delete()
    if os.path.exists(shared_data.profile_config_dir):
        shutil.rmtree(shared_data.profile_config_dir)
    if shared_data.group_did_manager:
        shared_data.group_did_manager.terminate()
    if shared_data.super:
        shared_data.super.terminate()
    if shared_data.dmws:
        shared_data.dmws.terminate()
    assert await_thread_cleanup(timeout=10)

