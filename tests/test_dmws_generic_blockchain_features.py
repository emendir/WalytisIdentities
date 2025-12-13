import os
import shutil
import tempfile
from time import sleep

import _auto_run_with_pytest  # noqa
from conftest import cleanup_walytis_ipfs
from emtest import await_thread_cleanup
from walytis_beta_api._experimental import generic_blockchain_testing

from walytis_identities.did_manager import DidManager
from walytis_identities.did_manager_with_supers import (
    DidManagerWithSupers,
    GroupDidManager,
)
from walytis_identities.key_objects import Key
from walytis_identities.group_did_manager import GroupDidManager
from walytis_identities.key_store import KeyStore

# walytis_api.log.PRINT_DEBUG = False


class SharedData:
    profile_config_dir: str
    key_store_path: str
    CRYPTO_FAMILY: str
    KEY: str
    device_did_keystore: KeyStore
    profile_did_keystore: KeyStore
    device_did_manager: DidManager
    dmws_did_manager: GroupDidManager
    group_did_manager: GroupDidManager
    dmws: DidManagerWithSupers
    super: GroupDidManager


shared_data = SharedData()


def test_preparations():
    """Setup resources in preparation for tests."""
    # declare 'global' variables
    shared_data.profile_config_dir = tempfile.mkdtemp()
    shared_data.key_store_path = os.path.join(
        shared_data.profile_config_dir, "master_keystore.json"
    )

    # the cryptographic family to use for the tests
    shared_data.CRYPTO_FAMILY = "EC-secp256k1"
    shared_data.KEY = Key.create(shared_data.CRYPTO_FAMILY)

    config_dir = shared_data.profile_config_dir
    key = shared_data.KEY

    device_keystore_path = os.path.join(config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(config_dir, "profile_keystore.json")

    shared_data.device_did_keystore = KeyStore(device_keystore_path, key)
    shared_data.profile_did_keystore = KeyStore(profile_keystore_path, key)

    shared_data.device_did_manager = DidManager.create(
        shared_data.device_did_keystore
    )
    dmws_did_manager = GroupDidManager.create(
        shared_data.profile_did_keystore, shared_data.device_did_manager
    )
    dmws_did_manager.terminate()
    shared_data.group_did_manager = GroupDidManager(
        shared_data.profile_did_keystore,
        shared_data.device_did_manager,
        auto_load_missed_blocks=False,
    )
    shared_data.dmws = DidManagerWithSupers(
        did_manager=shared_data.group_did_manager,
    )

    shared_data.super = shared_data.dmws.create_super()
    sleep(1)
    shared_data.dmws.terminate()


def test_profile():
    print("Running test for DidManagerWithSupers...")
    dmws = generic_blockchain_testing.run_generic_blockchain_test(
        DidManagerWithSupers, did_manager=shared_data.group_did_manager
    )
    dmws.terminate()


def test_super():
    print("Running test for Super...")
    super = generic_blockchain_testing.run_generic_blockchain_test(
        GroupDidManager,
        group_key_store=shared_data.super.key_store,
        member=shared_data.super.member_did_manager.key_store,
    )
    super.terminate()


def test_threads_cleanup() -> None:
    """Test that no threads are left running."""
    cleanup_walytis_ipfs()
    try:
        if shared_data.super:
            shared_data.super.terminate()
            shared_data.super.delete()
    except:
        pass

    try:
        if shared_data.dmws:
            shared_data.dmws.terminate()
            shared_data.dmws.delete()
    except:
        pass

    try:
        if shared_data.group_did_manager:
            shared_data.group_did_manager.terminate()
            shared_data.group_did_manager.delete()
    except:
        pass

    try:
        if shared_data.device_did_manager:
            shared_data.device_did_manager.terminate()
            shared_data.device_did_manager.delete()
    except:
        pass
    if os.path.exists(shared_data.profile_config_dir):
        shutil.rmtree(shared_data.profile_config_dir)
    assert await_thread_cleanup(timeout=10)
