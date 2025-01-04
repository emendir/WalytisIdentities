from datetime import datetime
import walytis_beta_api as waly
import os
import shutil
import tempfile

import _testing_utils
import walidentity
import pytest
import walytis_beta_api as walytis_api
from _testing_utils import mark, test_threads_cleanup
from walidentity.did_objects import Key
from walidentity import did_manager_with_supers
from walidentity.did_manager_with_supers import DidManagerWithSupers, GroupDidManager
walytis_api.log.PRINT_DEBUG = False

_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.dirname(os.path.dirname(__file__)), module=did_manager_with_supers
)
_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.join(os.path.dirname(__file__), "..", ".."), module=walidentity
)

REBUILD_DOCKER = True

# automatically remove all docker containers after failed tests
DELETE_ALL_BRENTHY_DOCKERS = True


def test_preparations():
    pytest.super = None
    pytest.profile = None
    pytest.profile_config_dir = tempfile.mkdtemp()
    pytest.key_store_path = os.path.join(
        pytest.profile_config_dir, "keystore.json")

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
    if pytest.profile:
        pytest.profile.delete()
    shutil.rmtree(pytest.profile_config_dir)


def test_create_profile():
    pytest.profile = DidManagerWithSupers.create(pytest.profile_config_dir, pytest.KEY)
    existing_blockchain_ids = waly.list_blockchain_ids()
    mark(
        pytest.profile.profile_did_manager.blockchain.blockchain_id in existing_blockchain_ids
        and pytest.profile.profile_did_manager.member_did_manager.blockchain.blockchain_id in existing_blockchain_ids,
        "Created profile."
    )


def test_create_super():
    profile = pytest.profile
    pytest.super = profile.add()
    mark(
        isinstance(pytest.super, GroupDidManager),
        "Created correspondence."
    )
    mark(
        pytest.super == profile.get_from_id( pytest.super.did),
        "  -> get_from_id()"
    )
    mark(
        pytest.super.did in profile.get_active_ids()
        and pytest.super.did not in profile.get_archived_ids(),
        "  -> get_active_ids() & get_archived_ids()"
    )
    active_ids, archived_ids = profile._read_super_registry()
    mark(
        pytest.super.did in active_ids
        and pytest.super.did not in archived_ids,
        "  -> _read_super_registry()"
    )


def test_archive_super():
    profile = pytest.profile
    profile.archive(pytest.super.did)
    mark(
        isinstance(pytest.super, GroupDidManager),
        "Created correspondence."
    )
    mark(
        pytest.super.did not in profile.get_active_ids()
        and pytest.super.did  in profile.get_archived_ids(),
        "  -> get_active_ids() & get_archived_ids()"
    )
    active_ids, archived_ids = profile._read_super_registry()
    mark(
        pytest.super.did not in active_ids
        and pytest.super.did in archived_ids,
        "  -> _read_super_registry()"
    )


def test_delete_profile():
    pytest.profile.delete()
    existing_blockchain_ids = waly.list_blockchain_ids()
    mark(
        pytest.profile.profile_did_manager.blockchain.blockchain_id not in existing_blockchain_ids
        and pytest.profile.profile_did_manager.member_did_manager.blockchain.blockchain_id not in existing_blockchain_ids,
        "Deleted profile."
    )

def run_tests():
    print("\nRunning tests for DidManagerWithSupers:")
    test_preparations()
    test_create_profile()
    test_create_super()
    
    test_archive_super()

    # test_delete_profile()
    # test_cleanup()
    test_threads_cleanup()


if __name__ == "__main__":
    _testing_utils.PYTEST = False
    _testing_utils.BREAKPOINTS = True
    run_tests()

