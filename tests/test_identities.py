import os
import shutil
import sys
import tempfile

import pytest
import walytis_beta_api
from multi_crypt import Crypt
import testing_utils
from testing_utils import mark

if True:
    # for Hydrogen
    if False:
        __file__ = "./test_identities.py"
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.join(
        os.path.abspath(os.path.dirname(os.path.dirname(__file__))), "src"
    ))

    from identity.identity import IdentityAccess

testing_utils.BREAKPOINTS = True


def pytest_configure():
    """Setup resources in preparation for tests."""
    # declare 'global' variables
    pytest.person_config_dir = tempfile.mkdtemp()
    pytest.person_config_dir2 = tempfile.mkdtemp()
    pytest.key_store_path = os.path.join(
        pytest.person_config_dir, "master_keystore.json")

    # the cryptographic family to use for the tests
    pytest.CRYPTO_FAMILY = "EC-secp256k1"
    pytest.CRYPT = Crypt.new(pytest.CRYPTO_FAMILY)


def pytest_unconfigure():
    """Clean up resources used during tests."""
    shutil.rmtree(pytest.person_config_dir)
    shutil.rmtree(pytest.person_config_dir2)


def test_create_person_identity():
    pytest.p_id_access = IdentityAccess.create(
        pytest.person_config_dir,
        pytest.CRYPT,
    )

    members = pytest.p_id_access.get_members()
    mark(
        isinstance(pytest.p_id_access, IdentityAccess)
        and len(members) == 1
        and pytest.p_id_access.device_did_manager.get_did() in members[0]["did"],
        "Create IdentityAccess"
    )
    pytest.p_id_access.terminate()


def test_load_person_identity():
    p_id_access = IdentityAccess.load_from_appdata(
        pytest.person_config_dir,
        pytest.CRYPT
    )
    device_did = pytest.p_id_access.device_did_manager.get_did()
    person_did = pytest.p_id_access.person_did_manager.get_did()
    members = p_id_access.get_members()
    mark(
        p_id_access.device_did_manager.get_did() == device_did
        and p_id_access.person_did_manager.get_did() == person_did
        and len(members) == 1
        and p_id_access.device_did_manager.get_did() in members[0]["did"],
        "Load IdentityAccess"
    )
    # p_id_access.terminate()
    pytest.p_id_access = p_id_access


def test_delete_person_identity():
    person_blockchain = pytest.p_id_access.person_did_manager.blockchain.blockchain_id
    device_blockchain = pytest.p_id_access.device_did_manager.blockchain.blockchain_id
    pytest.p_id_access.delete()

    # ensure the blockchains of both the person and the device identities
    # have been deleted
    mark(
        person_blockchain not in walytis_beta_api.list_blockchain_ids() and
        device_blockchain not in walytis_beta_api.list_blockchain_ids(),
        "Delete IdentityAccess"
    )


def run_tests():
    print("\nRunning tests for Identities:")
    testing_utils.PYTEST = False
    pytest_configure()  # run test preparations

    # run tests
    test_create_person_identity()
    test_load_person_identity()
    test_delete_person_identity()
    pytest_unconfigure()  # run test cleanup


if __name__ == "__main__":
    run_tests()
