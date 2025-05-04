import _testing_utils
from walytis_beta_embedded._walytis_beta.walytis_beta_api._experimental import generic_blockchain_testing
from time import sleep
import _testing_utils
from walytis_beta_embedded._walytis_beta.walytis_beta_api._experimental.generic_blockchain_testing import test_generic_blockchain
from walytis_beta_embedded._walytis_beta.walytis_beta_api import Blockchain
import os
import pytest
import shutil
from walytis_identities.did_manager import DidManager
from walytis_identities.did_objects import Key
from walytis_identities.group_did_manager import GroupDidManager
from walytis_identities.key_store import KeyStore
import tempfile
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


def test_preparations() -> None:
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


def test_cleanup() -> None:
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


def run_tests():
    print("Running test for DidManagerWithSupers Generic Blockchain features...")
    test_preparations()
    test_profile()
    test_super()
    pytest.group_did_manager.terminate()
    pytest.super.terminate()
    pytest.dmws.terminate()
    test_cleanup()


if __name__ == "__main__":
    _testing_utils.PYTEST = False
    _testing_utils.BREAKPOINTS = False
    run_tests()
    _testing_utils.terminate()
    