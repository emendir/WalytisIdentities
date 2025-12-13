from emtest import await_thread_cleanup
import _auto_run_with_pytest  # noqa
from conftest import cleanup_walytis_ipfs
from walytis_identities.key_store import KeyStore
from walytis_identities.did_manager import DidManager
import walytis_beta_api as waly
import os
import shutil
import pytest
from walytis_identities.did_manager_with_supers import (
    DidManagerWithSupers,
    GroupDidManager,
)

# walytis_api.log.PRINT_DEBUG = False
from testing_utils import KEY, dm_config_dir


class SharedData:
    pass


shared_data = SharedData()


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


def prepare():
    if os.path.exists(dm_config_dir):
        shutil.rmtree(dm_config_dir)
    os.makedirs(dm_config_dir)
    shared_data.super = None
    shared_data.dm = None
    shared_data.key_store_path = os.path.join(dm_config_dir, "keystore.json")


def cleanup():
    try:
        if shared_data.super:
            shared_data.super.delete()
    except:
        pass
    try:
        if shared_data.dm:
            shared_data.dm.delete()
    except:
        pass
    if os.path.exists(dm_config_dir):
        shutil.rmtree(dm_config_dir)
    cleanup_walytis_ipfs()


def test_create_dm():
    config_dir = dm_config_dir
    key = KEY

    device_keystore_path = os.path.join(config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(config_dir, "profile_keystore.json")

    device_did_keystore = KeyStore(device_keystore_path, key)
    profile_did_keystore = KeyStore(profile_keystore_path, key)
    device_did_manager = DidManager.create(device_did_keystore)
    profile_did_manager = GroupDidManager.create(
        profile_did_keystore, device_did_manager
    )
    profile_did_manager.terminate()
    group_did_manager = GroupDidManager(
        profile_did_keystore, device_did_manager, auto_load_missed_blocks=False
    )
    dmws = DidManagerWithSupers(
        did_manager=group_did_manager,
    )
    shared_data.dm = dmws
    existing_blockchain_ids = waly.list_blockchain_ids()

    assert (
        shared_data.dm.blockchain.blockchain_id in existing_blockchain_ids
    ), "Created DidManagerWithSupers."


def test_create_super():
    dm = shared_data.dm
    shared_data.super = dm.create_super()

    assert isinstance(shared_data.super, GroupDidManager), "Created super."

    assert shared_data.super == dm.get_super(shared_data.super.did), (
        "  -> get_super()"
    )

    assert (
        shared_data.super.did in dm.get_active_supers()
        and shared_data.super.did not in dm.get_archived_supers()
    ), "  -> get_active_supers() & get_archived_supers()"

    active_ids, archived_ids = dm._read_super_registry()
    assert (
        shared_data.super.did in active_ids
        and shared_data.super.did not in archived_ids
    ), "  -> _read_super_registry()"


def test_archive_super():
    dm = shared_data.dm
    dm.archive_super(shared_data.super.did)

    assert isinstance(shared_data.super, GroupDidManager), "Created super."

    assert (
        shared_data.super.did not in dm.get_active_supers()
        and shared_data.super.did in dm.get_archived_supers()
    ), "  -> get_active_supers() & get_archived_supers()"
    active_ids, archived_ids = dm._read_super_registry()
    assert (
        shared_data.super.did not in active_ids
        and shared_data.super.did in archived_ids
    ), "  -> _read_super_registry()"


def test_reload_dm():
    shared_data.dm.terminate()
    config_dir = dm_config_dir
    key = KEY

    device_keystore_path = os.path.join(config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(config_dir, "profile_keystore.json")

    device_did_keystore = KeyStore(device_keystore_path, key)
    profile_did_keystore = KeyStore(profile_keystore_path, key)
    group_did_manager = GroupDidManager(
        profile_did_keystore,
        device_did_keystore,
        auto_load_missed_blocks=False,
    )
    dmws = DidManagerWithSupers(
        did_manager=group_did_manager,
    )

    shared_data.dm = dmws


def test_delete_dm():
    shared_data.dm.delete()
    existing_blockchain_ids = waly.list_blockchain_ids()

    assert (
        shared_data.dm.blockchain.blockchain_id not in existing_blockchain_ids
    ), "Deleted DidManagerWithSupers."


def test_threads_cleanup() -> None:
    """Test that no threads are left running."""
    cleanup()
    assert await_thread_cleanup(timeout=10)
