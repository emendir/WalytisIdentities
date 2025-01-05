from walytis_beta_api._experimental import generic_blockchain_testing
from time import sleep
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


def test_preparations() -> None:
    """Setup resources in preparation for tests."""
    # declare 'global' variables
    pytest.profile_config_dir = tempfile.mkdtemp()
    pytest.key_store_path = os.path.join(
        pytest.profile_config_dir, "master_keystore.json")

    # the cryptographic family to use for the tests
    pytest.CRYPTO_FAMILY = "EC-secp256k1"
    pytest.KEY = Key.create(pytest.CRYPTO_FAMILY)

    pytest.profile = DidManagerWithSupers.create(
        pytest.profile_config_dir, pytest.KEY)
    pytest.super = pytest.profile.create_super()
    sleep(1)
    pytest.profile.terminate()


def test_cleanup() -> None:
    """Clean up resources used during tests."""
    if pytest.profile:
        pytest.profile.delete()

    shutil.rmtree(pytest.profile_config_dir)


def test_profile():
    print("Running test for DidManagerWithSupers...")
    test_generic_blockchain(
        DidManagerWithSupers,
        group_key_store=pytest.profile.key_store,
        member=pytest.profile.member_did_manager.key_store
    )


def test_super():
    print("Running test for Super...")
    test_generic_blockchain(
        GroupDidManager,
        group_key_store=pytest.super.key_store,
        member=pytest.super.member_did_manager.key_store
    )


def run_tests():
    test_preparations()
    test_profile()
    test_super()
    test_cleanup()


if __name__ == "__main__":
    generic_blockchain_testing.PYTEST = False
    run_tests()
