import os
import shutil
import tempfile

import _testing_utils
import walidentity
import pytest
import walytis_beta_api
from _testing_utils import mark
from walidentity.group_did_manager import GroupDidManager
from walidentity.key_store import CodePackage
from multi_crypt import Crypt
from walidentity import key_store
from walidentity import did_manager
from walidentity.did_objects import Key


import os
from walidentity.key_store import KeyStore
from walidentity.did_manager import DidManager
from walidentity.did_objects import Key

_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.dirname(os.path.dirname(__file__)), module=walidentity
)
_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.dirname(os.path.dirname(__file__)), module=key_store
)
_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.dirname(os.path.dirname(__file__)), module=did_manager
)


_testing_utils.BREAKPOINTS = True


def pytest_configure():
    """Setup resources in preparation for tests."""
    # declare 'global' variables
    pytest.person_config_dir = tempfile.mkdtemp()
    pytest.person_config_dir2 = tempfile.mkdtemp()
    pytest.key_store_path = os.path.join(
        pytest.person_config_dir, "master_keystore.json")

    # the cryptographic family to use for the tests
    pytest.CRYPTO_FAMILY = "EC-secp256k1"
    pytest.KEY = Key.create(pytest.CRYPTO_FAMILY)


def pytest_unconfigure():
    """Clean up resources used during tests."""
    shutil.rmtree(pytest.person_config_dir)
    shutil.rmtree(pytest.person_config_dir2)


def test_create_person_identity():
    device_keystore_path = os.path.join(pytest.person_config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(pytest.person_config_dir, "profile_keystore.json")

    device_did_keystore = KeyStore(device_keystore_path, pytest.KEY)
    profile_did_keystore = KeyStore(profile_keystore_path, pytest.KEY)
    pytest.member_1 = DidManager.create(device_did_keystore)
    pytest.group_1 = GroupDidManager.create(
        profile_did_keystore, pytest.member_1
    )
    
    


    members = pytest.group_1.get_members()
    mark(
        isinstance(pytest.group_1, GroupDidManager)
        and len(members) == 1
        and pytest.group_1.member_did_manager.did in members[0]["did"],
        "Create GroupDidManager"
    )
    pytest.group_1.terminate()


def test_load_person_identity():
    device_keystore_path = os.path.join(pytest.person_config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(pytest.person_config_dir, "profile_keystore.json")

    device_did_keystore = KeyStore(device_keystore_path, pytest.KEY)
    profile_did_keystore = KeyStore(profile_keystore_path, pytest.KEY)
    group_1 = GroupDidManager(
        profile_did_keystore,
        device_did_keystore
    )
    member_did = pytest.group_1.member_did_manager.did
    person_did = pytest.group_1.did
    members = group_1.get_members()
    mark(
        group_1.member_did_manager.did == member_did
        and group_1.did == person_did
        and len(members) == 1
        and group_1.member_did_manager.did in members[0]["did"],
        "Load GroupDidManager"
    )
    # group_1.terminate()
    pytest.group_1 = group_1


PLAIN_TEXT = "Hello there!".encode()


def test_encryption():
    cipher_1 = pytest.group_1.encrypt(PLAIN_TEXT)
    pytest.group_1.renew_control_key()
    cipher_2 = pytest.group_1.encrypt(PLAIN_TEXT)

    mark(
        (
            CodePackage.deserialise_bytes(cipher_1).public_key !=
            CodePackage.deserialise_bytes(cipher_2).public_key
            and pytest.group_1.decrypt(cipher_1) == PLAIN_TEXT
            and pytest.group_1.decrypt(cipher_2) == PLAIN_TEXT
        ),
        "Encryption across key renewal works"
    )


def test_signing():
    signature_1 = pytest.group_1.sign(PLAIN_TEXT)
    pytest.group_1.renew_control_key()
    signature_2 = pytest.group_1.sign(PLAIN_TEXT)

    mark(
        (
            CodePackage.deserialise_bytes(signature_1).public_key !=
            CodePackage.deserialise_bytes(signature_2).public_key
            and pytest.group_1.verify_signature(signature_1, PLAIN_TEXT)
            and pytest.group_1.verify_signature(signature_2, PLAIN_TEXT)
        ),
        "Signature verification across key renewal works"
    )


def test_delete_person_identity():
    group_blockchain = pytest.group_1.blockchain.blockchain_id
    member_blockchain = pytest.group_1.member_did_manager.blockchain.blockchain_id
    pytest.group_1.delete()

    # ensure the blockchains of both the person and the member identities
    # have been deleted
    mark(
        group_blockchain not in walytis_beta_api.list_blockchain_ids() and
        member_blockchain not in walytis_beta_api.list_blockchain_ids(),
        "Delete GroupDidManager"
    )


def run_tests():
    print("\nRunning tests for Identities:")
    _testing_utils.PYTEST = False
    pytest_configure()  # run test preparations

    # run tests
    test_create_person_identity()
    test_load_person_identity()
    test_encryption()
    test_signing()
    test_delete_person_identity()
    pytest_unconfigure()  # run test cleanup


if __name__ == "__main__":
    run_tests()
