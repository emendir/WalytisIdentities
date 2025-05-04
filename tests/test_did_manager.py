import os
import shutil
import tempfile

import _testing_utils
import walytis_identities
import pytest
import walytis_beta_embedded._walytis_beta.walytis_beta_api as walytis_api
from _testing_utils import mark
from walytis_identities.did_manager import DidManager
from walytis_identities.did_objects import Key
from walytis_identities.key_store import CodePackage, KeyStore

_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.dirname(os.path.dirname(__file__)), module=walytis_identities
)


def pytest_configure():
    pytest.tempdir = tempfile.mkdtemp()
    pytest.key_store_path = os.path.join(pytest.tempdir, "keystore.json")

    # the cryptographic family to use for the tests
    pytest.CRYPTO_FAMILY = "EC-secp256k1"
    pytest.CRYPT = Key.create(pytest.CRYPTO_FAMILY)


def pytest_unconfigure():
    """Clean up resources used during tests."""
    shutil.rmtree(pytest.tempdir)


def test_create_did_manager():
    pytest.keystore = KeyStore(pytest.key_store_path, pytest.CRYPT)
    pytest.did_manager = DidManager.create(pytest.keystore)
    blockchain_id = pytest.did_manager.blockchain.blockchain_id

    mark(
        isinstance(pytest.did_manager, DidManager)
        and blockchain_id in walytis_api.list_blockchain_ids(),
        "Create DidManager"
    )


def test_delete_did_manager():
    blockchain_id = pytest.did_manager.blockchain.blockchain_id
    pytest.did_manager.delete()
    mark(
        blockchain_id not in walytis_api.list_blockchain_ids(),
        "Delete DidManager"
    )


def test_renew_control_key():
    old_control_key = pytest.did_manager.get_control_key()

    pytest.did_manager.renew_control_key()

    pytest.new_control_key = pytest.did_manager.get_control_key()
    mark(
        (
            isinstance(old_control_key, Key)
            and isinstance(pytest.new_control_key, Key)
            and old_control_key.public_key != pytest.new_control_key.public_key
        ),
        "Control Key Update"
    )


def test_update_did_doc():
    pytest.did_doc = {
        "id": pytest.did_manager.did,
        "verificationMethod": [
            pytest.new_control_key.generate_key_spec(
                pytest.did_manager.did)
        ]
    }
    pytest.did_manager.update_did_doc(pytest.did_doc)
    mark(pytest.did_manager.did_doc == pytest.did_doc, "Update DID Doc")


def test_reload_did_manager():
    did_manager_copy = DidManager(
        pytest.keystore
    )

    mark((
        did_manager_copy.get_control_key().public_key == pytest.new_control_key.public_key
        and did_manager_copy.did_doc == pytest.did_doc
    ),
        "Reload DID Manager"
    )
    did_manager_copy.terminate()


PLAIN_TEXT = "Hello there!".encode()


def test_encryption():
    cipher_1 = pytest.did_manager.encrypt(PLAIN_TEXT)
    pytest.did_manager.renew_control_key()
    cipher_2 = pytest.did_manager.encrypt(PLAIN_TEXT)

    mark(
        (
            CodePackage.deserialise_bytes(cipher_1).public_key !=
            CodePackage.deserialise_bytes(cipher_2).public_key
            and pytest.did_manager.decrypt(cipher_1) == PLAIN_TEXT
            and pytest.did_manager.decrypt(cipher_2) == PLAIN_TEXT
        ),
        "Encryption across key renewal works"
    )


def test_signing():
    signature_1 = pytest.did_manager.sign(PLAIN_TEXT)
    pytest.did_manager.renew_control_key()
    signature_2 = pytest.did_manager.sign(PLAIN_TEXT)

    mark(
        (
            CodePackage.deserialise_bytes(signature_1).public_key !=
            CodePackage.deserialise_bytes(signature_2).public_key
            and pytest.did_manager.verify_signature(signature_1, PLAIN_TEXT)
            and pytest.did_manager.verify_signature(signature_2, PLAIN_TEXT)
        ),
        "Signature verification across key renewal works"
    )


def run_tests():
    print("\nRunning tests for DidManager:")
    _testing_utils.PYTEST = False
    pytest_configure()  # run test preparations

    # run tests
    test_create_did_manager()
    test_renew_control_key()
    test_update_did_doc()
    test_reload_did_manager()
    test_encryption()
    test_signing()
    test_delete_did_manager()
    pytest_unconfigure()  # run test cleanup


if __name__ == "__main__":
    _testing_utils.PYTEST = False
    _testing_utils.BREAKPOINTS = False
    run_tests()
    _testing_utils.terminate()
    
