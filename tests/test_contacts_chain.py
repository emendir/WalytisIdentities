import os
import shutil
import tempfile

import _testing_utils
import private_blocks
import pytest
import walidentity
import walytis_beta_embedded._walytis_beta.walytis_beta_api
from _testing_utils import mark, test_threads_cleanup
from multi_crypt import Crypt
from walidentity.group_did_manager import GroupDidManager
from waly_contacts import (
    ContactsChain,
    identity_management,
)
from walidentity.did_objects import Key
_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.dirname(os.path.dirname(__file__)), module=walidentity
)
_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.join(os.path.dirname(__file__), "..", ".."), module=private_blocks
)


def pytest_configure():
    """Setup resources in preparation for tests."""
    # declare 'global' variables
    pytest.person1_config_dir = tempfile.mkdtemp()
    pytest.person2_config_dir = tempfile.mkdtemp()
    pytest.contacts_chain = None
    pytest.me2 = None
    pytest.tempdir = tempfile.mkdtemp()
    # the cryptographic family to use for the tests
    pytest.CRYPTO_FAMILY = "EC-secp256k1"
    pytest.CRYPT = Key.create(pytest.CRYPTO_FAMILY)


def pytest_unconfigure():
    """Clean up resources used during tests."""
    try:
        pytest.me1.delete()
    except:
        pass
    try:
        pytest.me2.delete()
    except:
        pass
    try:
        pytest.contacts_chain.delete()
    except:
        pass
    shutil.rmtree(pytest.person1_config_dir)
    shutil.rmtree(pytest.person2_config_dir)
    shutil.rmtree(pytest.tempdir)


def test_create_identity():
    print("Creating identity...")
    pytest.me1 = identity_management.create_person_identity(
        pytest.person1_config_dir, pytest.CRYPT
    )

    members = pytest.me1.get_members()
    mark(
        isinstance(pytest.me1, GroupDidManager) and
        len(members) == 1 and members[0].did == pytest.me1.member_did_manager.did,
        "Created identity"
    )


def test_create_contacts_manager():
    print("Creating contacts manager...")

    pytest.contacts_chain = ContactsChain(pytest.me1)

    mark(
        pytest.contacts_chain.blockchain.base_blockchain.blockchain_id ==
        pytest.me1.blockchain.blockchain_id,
        "create contacts manager"
    )


def test_add_contact():
    print("Creating identity...")
    pytest.me1.terminate()
    pytest.me2 = identity_management.create_person_identity(
        pytest.person2_config_dir, pytest.CRYPT
    )
    print("Befriending...")
    pytest.contacts_chain.add_contact(pytest.me2.did)
    mark(pytest.me2.did in pytest.contacts_chain.get_contacts(), "add contact")


def test_remove_contact():
    print("Deleting contacts...")
    pytest.contacts_chain.remove_contact(pytest.me2.did)
    me2_blockchain_id = pytest.me2.blockchain.blockchain_id
    mark(
        pytest.me2.did not in pytest.contacts_chain.get_contacts(),
        "remove contact"
    )


def run_tests():
    print("\nRunning tests for ContactsChain:")
    _testing_utils.PYTEST = False

    pytest_configure()
    test_create_identity()
    test_create_contacts_manager()
    test_add_contact()
    test_remove_contact()
    pytest_unconfigure()
    test_threads_cleanup()


if __name__ == "__main__":
    _testing_utils.PYTEST = False
    _testing_utils.BREAKPOINTS = True
    run_tests()
    _testing_utils.terminate()
    
