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
    sys.path.insert(0, os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))
    # from management import friends_management
    # from management import identity_management
    # from identity.identity import IdentityAccess
    from identity.identity import DeviceIdentityAccess, PersonIdentityAccess

testing_utils.BREAKPOINTS = True


def pytest_configure():
    """Setup resources in preparation for tests."""
    # declare 'global' variables
    pytest.d_id_access = None
    pytest.tempdir = tempfile.mkdtemp()
    pytest.key_store_path = os.path.join(
        pytest.tempdir, "master_keystore.json")

    # the cryptographic family to use for the tests
    pytest.CRYPTO_FAMILY = "EC-secp256k1"
    pytest.CRYPT = Crypt.new(pytest.CRYPTO_FAMILY)


def pytest_unconfigure():
    """Clean up resources used during tests."""
    shutil.rmtree(pytest.tempdir)


def test_create_device_identity():
    pytest.d_id_access = DeviceIdentityAccess.create(
        pytest.tempdir, pytest.CRYPT)
    mark(
        isinstance(pytest.d_id_access, DeviceIdentityAccess),
        "Create DeviceIdentityAccess")


def test_create_person_identity():
    pytest.p_id_access = PersonIdentityAccess.create(
        pytest.d_id_access,
        pytest.tempdir,
        pytest.CRYPT,
    )
    members = pytest.p_id_access.get_members()
    mark(
        isinstance(pytest.p_id_access, PersonIdentityAccess)
        and len(members) == 1
        and pytest.d_id_access.get_did() in members[0]["did"],
        "Create PersonIdentityAccess"
    )


def test_load_identities():
    d_id_access = DeviceIdentityAccess.load_from_appdata(
        pytest.tempdir,
        pytest.CRYPT
    )
    mark(
        d_id_access.get_did() == pytest.d_id_access.get_did(),
        "Load DeviceIdentityAccess"
    )
    p_id_access = PersonIdentityAccess.load_from_appdata(
        pytest.d_id_access,
        pytest.tempdir,
        pytest.CRYPT
    )
    members = p_id_access.get_members()
    mark(
        d_id_access.get_did() == pytest.d_id_access.get_did()
        and p_id_access.get_did() == pytest.p_id_access.get_did()
        and len(members) == 1
        and d_id_access.get_did() in members[0]["did"],
        "Load PersonIdentityAccess"
    )


def test_delete_person_identity():
    person_blockchain = pytest.p_id_access.get_blockchain_id()
    device_blockchain = pytest.d_id_access.get_blockchain_id()
    pytest.p_id_access.delete()

    # ensure the blockchains of both the person and the device identities
    # have been deleted
    mark(
        person_blockchain not in walytis_beta_api.list_blockchain_ids() and
        device_blockchain not in walytis_beta_api.list_blockchain_ids(),
        "Delete PersonIdentityAccess"
    )


def run_tests():
    testing_utils.PYTEST = False
    pytest_configure()  # run test preparations

    # run tests
    test_create_device_identity()
    test_create_person_identity()
    test_load_identities()
    test_delete_person_identity()
    pytest_unconfigure()  # run test cleanup


run_tests()
