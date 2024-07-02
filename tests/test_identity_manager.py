import os
import shutil
import sys

import pytest
import testing_utils
import walytis_beta_api
from multi_crypt import Crypt
from testing_utils import mark

if True:
    sys.path.insert(0, os.path.join(
        os.path.abspath(os.path.dirname(os.path.dirname(__file__))), "src"
    ))
    from identity.identity import IdentityAccess
    from management import friends_management, identity_management
import tempfile

BREAKPOINTS = True
PYTEST = True  # whether or not this script is being run by pytest


def pytest_configure():
    """Setup resources in preparation for tests."""
    # declare 'global' variables
    pytest.d_id_access = None
    pytest.person1_config_dir = tempfile.mkdtemp()
    pytest.person2_config_dir = tempfile.mkdtemp()
    pytest.contacts_manager = None
    pytest.me2 = None
    pytest.tempdir = tempfile.mkdtemp()
    # the cryptographic family to use for the tests
    pytest.CRYPTO_FAMILY = "EC-secp256k1"
    pytest.CRYPT = Crypt.new(pytest.CRYPTO_FAMILY)


def pytest_unconfigure():
    """Clean up resources used during tests."""
    shutil.rmtree(pytest.person1_config_dir)
    shutil.rmtree(pytest.person2_config_dir)
    shutil.rmtree(pytest.tempdir)


def test_create_identity():
    print("Creating identity...")
    pytest.me1 = identity_management.create_person_identity(
        pytest.person1_config_dir, pytest.CRYPT
    )

    mark(isinstance(pytest.me1, IdentityAccess), "identity creation")
    members = pytest.me1.get_members()
    mark(
        len(members) == 1 and members[0]["did"] == pytest.me1.member_did_manager.get_did(),
        "person identity has member identity"
    )


def test_create_contacts_manager():
    print("Creating contacts manager...")
    cm_filepath = os.path.join(pytest.tempdir, "contacts_manager.json")
    pytest.contacts_manager = friends_management.ContactsManager(cm_filepath)
    mark(True, "create contacts manager")


def test_befriend():
    print("Creating identity...")
    pytest.me2 = identity_management.create_person_identity(
        pytest.person1_config_dir, pytest.CRYPT
    )
    print("Befriending...")
    pytest.contacts_manager.befriend(pytest.me2)
    mark(pytest.me2 in pytest.contacts_manager.get_friends(), "befriend")


def test_deletion():
    print("Deleting contacts...")
    pytest.me1.delete()
    pytest.contacts_manager.forget(pytest.me2)
    me2_blockchain_id = pytest.me2.person_did_manager.blockchain.blockchain_id
    mark(
        pytest.me2 not in pytest.contacts_manager.get_friends()
        and me2_blockchain_id not in walytis_beta_api.list_blockchain_ids(),
        "forget"
    )


def run_tests():
    print("\nRunning tests for IdentityManager:")
    testing_utils.PYTEST = False

    pytest_configure()
    test_create_identity()
    test_create_contacts_manager()
    test_befriend()
    test_deletion()
    pytest_unconfigure()


if __name__ == "__main__":
    run_tests()
