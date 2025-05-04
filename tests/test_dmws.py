import _testing_utils
from walytis_identities.key_store import KeyStore
from walytis_identities.did_manager import DidManager
from datetime import datetime
import walytis_beta_embedded._walytis_beta.walytis_beta_api as waly
import os
import shutil
import tempfile

import walytis_identities
import pytest
import walytis_beta_embedded._walytis_beta.walytis_beta_api as walytis_api
from _testing_utils import mark, test_threads_cleanup
from walytis_identities.did_objects import Key
from walytis_identities import did_manager_with_supers
from walytis_identities.did_manager_with_supers import DidManagerWithSupers, GroupDidManager
walytis_api.log.PRINT_DEBUG = False

_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.dirname(os.path.dirname(__file__)), module=did_manager_with_supers
)
_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.join(os.path.dirname(__file__), "..", ".."), module=walytis_identities
)



def test_preparations():
    pytest.super = None
    pytest.dm = None
    pytest.dm_config_dir = tempfile.mkdtemp()
    pytest.key_store_path = os.path.join(
        pytest.dm_config_dir, "keystore.json")

    # the cryptographic family to use for the tests
    pytest.CRYPTO_FAMILY = "EC-secp256k1"
    pytest.KEY = Key(
        family=pytest.CRYPTO_FAMILY,
        public_key=b'\x04\xa6#\x1a\xcf\xa7\xbe\xa8\xbf\xd9\x7fd\xa7\xab\xba\xeb{Wj\xe2\x8fH\x08*J\xda\xebS\x94\x06\xc9\x02\x8c9>\xf45\xd3=Zg\x92M\x84\xb3\xc2\xf2\xf4\xe6\xa8\xf9i\x82\xdb\xd8\x82_\xcaIT\x14\x9cA\xd3\xe1',
        private_key=b'\xd9\xd1\\D\x80\xd7\x1a\xe6E\x0bt\xdf\xd0z\x88\xeaQ\xe8\x04\x91\x11\xaf\\%wC\x83~\x0eGP\xd8',
        creation_time=datetime(2024, 11, 6, 19, 17, 45, 713000)
    )


def test_cleanup():
    if pytest.super:
        pytest.super.delete()
    if pytest.dm:
        pytest.dm.delete()
    shutil.rmtree(pytest.dm_config_dir)


def test_create_dm():
    config_dir = pytest.dm_config_dir
    key = pytest.KEY

    device_keystore_path = os.path.join(config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(
        config_dir, "profile_keystore.json")

    device_did_keystore = KeyStore(device_keystore_path, key)
    profile_did_keystore = KeyStore(profile_keystore_path, key)
    device_did_manager = DidManager.create(device_did_keystore)
    profile_did_manager = GroupDidManager.create(
        profile_did_keystore, device_did_manager
    )
    profile_did_manager.terminate()
    group_did_manager = GroupDidManager(
        profile_did_keystore,
        device_did_manager,
        auto_load_missed_blocks=False
    )
    dmws = DidManagerWithSupers(
        did_manager=group_did_manager,
    )
    pytest.dm = dmws
    existing_blockchain_ids = waly.list_blockchain_ids()
    mark(
        pytest.dm.blockchain.blockchain_id in existing_blockchain_ids,
        "Created DidManagerWithSupers."
    )


def test_reload_dm():
    pytest.dm.terminate()
    test_threads_cleanup()
    config_dir = pytest.dm_config_dir
    key = pytest.KEY

    device_keystore_path = os.path.join(config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(
        config_dir, "profile_keystore.json")

    device_did_keystore = KeyStore(device_keystore_path, key)
    profile_did_keystore = KeyStore(profile_keystore_path, key)
    group_did_manager = GroupDidManager(
        profile_did_keystore,
        device_did_keystore,
        auto_load_missed_blocks=False
    )
    dmws = DidManagerWithSupers(
        did_manager=group_did_manager,
    )

    pytest.dm = dmws


def test_create_super():
    dm = pytest.dm
    pytest.super = dm.create_super()
    mark(
        isinstance(pytest.super, GroupDidManager),
        "Created super."
    )
    mark(
        pytest.super == dm.get_super(pytest.super.did),
        "  -> get_super()"
    )
    mark(
        pytest.super.did in dm.get_active_supers()
        and pytest.super.did not in dm.get_archived_supers(),
        "  -> get_active_supers() & get_archived_supers()"
    )
    active_ids, archived_ids = dm._read_super_registry()
    mark(
        pytest.super.did in active_ids
        and pytest.super.did not in archived_ids,
        "  -> _read_super_registry()"
    )


def test_archive_super():
    dm = pytest.dm
    dm.archive_super(pytest.super.did)
    mark(
        isinstance(pytest.super, GroupDidManager),
        "Created super."
    )
    mark(
        pytest.super.did not in dm.get_active_supers()
        and pytest.super.did in dm.get_archived_supers(),
        "  -> get_active_supers() & get_archived_supers()"
    )
    active_ids, archived_ids = dm._read_super_registry()
    mark(
        pytest.super.did not in active_ids
        and pytest.super.did in archived_ids,
        "  -> _read_super_registry()"
    )


def test_delete_dm():
    pytest.dm.delete()
    existing_blockchain_ids = waly.list_blockchain_ids()
    mark(
        pytest.dm.blockchain.blockchain_id not in existing_blockchain_ids,
        "Deleted DidManagerWithSupers."
    )


def run_tests():
    print("\nRunning tests for DidManagerWithSupers:")
    test_preparations()
    test_create_dm()
    test_create_super()

    test_archive_super()

    test_reload_dm()
    test_delete_dm()
    test_cleanup()
    test_threads_cleanup()


if __name__ == "__main__":
    _testing_utils.PYTEST = False
    _testing_utils.BREAKPOINTS = False
    run_tests()
    _testing_utils.terminate()
    