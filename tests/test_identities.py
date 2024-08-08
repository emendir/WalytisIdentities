import os
import shutil
import tempfile

import _testing_utils
import walidentity
import pytest
import walytis_beta_api
from _testing_utils import mark
from walidentity.identity_access import IdentityAccess
from walidentity.key_store import CodePackage
from multi_crypt import Crypt

_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.dirname(os.path.dirname(__file__)), module=walidentity
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
        and pytest.p_id_access.member_did_manager.did in members[0]["did"],
        "Create IdentityAccess"
    )
    pytest.p_id_access.terminate()


def test_load_person_identity():
    p_id_access = IdentityAccess.load_from_appdata(
        pytest.person_config_dir,
        pytest.CRYPT
    )
    member_did = pytest.p_id_access.member_did_manager.did
    person_did = pytest.p_id_access.did
    members = p_id_access.get_members()
    mark(
        p_id_access.member_did_manager.did == member_did
        and p_id_access.did == person_did
        and len(members) == 1
        and p_id_access.member_did_manager.did in members[0]["did"],
        "Load IdentityAccess"
    )
    # p_id_access.terminate()
    pytest.p_id_access = p_id_access


PLAIN_TEXT = "Hello there!".encode()


def test_encryption():
    cipher_1 = pytest.p_id_access.encrypt(PLAIN_TEXT)
    pytest.p_id_access.person_did_manager.renew_control_key()
    cipher_2 = pytest.p_id_access.encrypt(PLAIN_TEXT)

    mark(
        (
            CodePackage.deserialise_bytes(cipher_1).public_key !=
            CodePackage.deserialise_bytes(cipher_2).public_key
            and pytest.p_id_access.decrypt(cipher_1) == PLAIN_TEXT
            and pytest.p_id_access.decrypt(cipher_2) == PLAIN_TEXT
        ),
        "Encryption across key renewal works"
    )


def test_signing():
    signature_1 = pytest.p_id_access.sign(PLAIN_TEXT)
    pytest.p_id_access.person_did_manager.renew_control_key()
    signature_2 = pytest.p_id_access.sign(PLAIN_TEXT)

    mark(
        (
            CodePackage.deserialise_bytes(signature_1).public_key !=
            CodePackage.deserialise_bytes(signature_2).public_key
            and pytest.p_id_access.verify_signature(signature_1, PLAIN_TEXT)
            and pytest.p_id_access.verify_signature(signature_2, PLAIN_TEXT)
        ),
        "Signature verification across key renewal works"
    )


def test_delete_person_identity():
    person_blockchain = pytest.p_id_access.person_did_manager.blockchain.blockchain_id
    member_blockchain = pytest.p_id_access.member_did_manager.blockchain.blockchain_id
    pytest.p_id_access.delete()

    # ensure the blockchains of both the person and the member identities
    # have been deleted
    mark(
        person_blockchain not in walytis_beta_api.list_blockchain_ids() and
        member_blockchain not in walytis_beta_api.list_blockchain_ids(),
        "Delete IdentityAccess"
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
