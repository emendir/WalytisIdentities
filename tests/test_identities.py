import walytis_beta_api
import walytis_beta_api as walytis_api
from termcolor import colored as coloured
import pytest
import sys
import os
import shutil
import tempfile
from multi_crypt import Crypt
if True:
    # for Hydrogen
    if False:
        __file__ = "./test_identities.py"
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    # from management import friends_management
    # from management import identity_management
    # from identity.identity import IdentityAccess
    from identity.did_manager import DidManager
    from identity.did_objects import Key
    from identity.identity import PersonIdentityAccess, DeviceIdentityAccess

BREAKPOINTS = True
PYTEST = True  # whether or not this script is being run by pytest


def pytest_configure():
    """Setup resources in preparation for tests."""
    # declare 'global' variables
    pytest.device_identity_access = None
    pytest.tempdir = tempfile.mkdtemp()
    pytest.keystore_path = os.path.join(pytest.tempdir, "keystore.json")

    pytest.CRYPTO_FAMILY = "EC-secp256k1"  # the cryptographic family to use for the tests
    pytest.CRYPT = Crypt.new(pytest.CRYPTO_FAMILY)


def pytest_unconfigure():
    """Clean up resources used during tests."""
    shutil.rmtree(pytest.tempdir)


def test_create_device_identity():
    pytest.device_identity_access = DeviceIdentityAccess.create()
    mark(isinstance(pytest.device_identity_access, DeviceIdentityAccess), "Create DeviceIdentityAccess")


def test_create_person_identity():
    pytest.person_identity_access = PersonIdentityAccess.create(pytest.device_identity_access)
    mark(isinstance(pytest.person_identity_access, PersonIdentityAccess), "Create DeviceIdentityAccess")


def test_delete_person_identity():
    person_blockchain = pytest.person_identity_access.did_manager.blockchain.blockchain_id
    device_blockchain = pytest.device_identity_access.did_manager.blockchain.blockchain_id
    pytest.person_identity_access.delete()

    # ensure the blockchains of both the person and the device identities
    # have been deleted
    mark(
        person_blockchain not in walytis_beta_api.list_blockchain_ids() and
        device_blockchain not in walytis_beta_api.list_blockchain_ids(),
        "Delete PersonIdentityAccess"
    )


def run_tests():
    global PYTEST
    PYTEST = False
    pytest_configure()  # run test preparations

    # run tests
    test_create_device_identity()
    test_create_person_identity()
    test_delete_person_identity()
    pytest_unconfigure()  # run test cleanup


run_tests()
