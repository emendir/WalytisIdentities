from emtest import await_thread_cleanup
import _auto_run_with_pytest  # noqa
from conftest import cleanup_walytis_ipfs
import os
import shutil
import tempfile

import pytest
import walytis_beta_api as walytis_api
from walytis_identities.did_manager import DidManager
from walytis_identities.key_objects import Key, KeyGroup
from walytis_identities.key_store import CodePackage, KeyStore


class SharedData:
    pass


shared_data = SharedData()


@pytest.fixture(scope="module", autouse=True)
def setup_and_teardown() -> None:
    """Wrap around tests, running preparations and cleaning up afterwards.

    A module-level fixture that runs once for all tests in this file.
    """
    # Setup: code here runs before tests that uses this fixture
    print(f"\nRunning tests for {__name__}\n")
    prepare()

    yield  # This separates setup from teardown

    # Teardown: code here runs after the tests
    print(f"\nFinished tests for {__name__}\n")
    cleanup()


def prepare():
    shared_data.tempdir = tempfile.mkdtemp()
    shared_data.key_store_path = os.path.join(
        shared_data.tempdir, "keystore.json"
    )

    # the cryptographic family to use for the tests
    shared_data.CRYPTO_FAMILY = "EC-secp256k1"
    shared_data.CRYPT = Key.create(shared_data.CRYPTO_FAMILY)


def cleanup():
    """Clean up resources used during tests."""
    if os.path.exists(shared_data.tempdir):
        shutil.rmtree(shared_data.tempdir)
    cleanup_walytis_ipfs()


def test_create_did_manager():
    shared_data.keystore = KeyStore(
        shared_data.key_store_path, shared_data.CRYPT
    )
    shared_data.did_manager = DidManager.create(shared_data.keystore)
    blockchain_id = shared_data.did_manager.blockchain.blockchain_id

    assert (
        isinstance(shared_data.did_manager, DidManager)
        and blockchain_id in walytis_api.list_blockchain_ids()
    ), "Create DidManager"


def test_renew_control_key():
    old_control_keys = shared_data.did_manager.get_control_keys()
    print(type(old_control_keys))

    shared_data.did_manager.renew_control_key()

    shared_data.new_control_keys = shared_data.did_manager.get_control_keys()

    assert isinstance(old_control_keys, KeyGroup)
    assert isinstance(shared_data.new_control_keys, KeyGroup)
    assert old_control_keys.get_id() != shared_data.new_control_keys.get_id()


def test_update_did_doc():
    shared_data.did_doc = {
        "id": shared_data.did_manager.did,
        "verificationMethod": shared_data.new_control_keys.generate_key_specs(
            shared_data.did_manager.did
        ),
    }
    shared_data.did_manager.update_did_doc(shared_data.did_doc)
    assert shared_data.did_manager.did_doc == shared_data.did_doc, (
        "Update DID Doc"
    )


def test_reload_did_manager():
    did_manager_copy = DidManager(shared_data.keystore)

    assert (
        did_manager_copy.get_control_keys().get_id()
        == shared_data.new_control_keys.get_id()
    )
    assert did_manager_copy.did_doc == shared_data.did_doc
    did_manager_copy.terminate()


PLAIN_TEXT = "Hello there!".encode()


def test_encryption():
    cipher_1 = shared_data.did_manager.encrypt(PLAIN_TEXT)
    shared_data.did_manager.renew_control_key()
    cipher_2 = shared_data.did_manager.encrypt(PLAIN_TEXT)

    assert (
        CodePackage.deserialise_bytes(cipher_1).key.get_id()
        != CodePackage.deserialise_bytes(cipher_2).key.get_id()
        and shared_data.did_manager.decrypt(cipher_1) == PLAIN_TEXT
        and shared_data.did_manager.decrypt(cipher_2) == PLAIN_TEXT
    ), "Encryption across key renewal works"


def test_signing():
    signature_1 = shared_data.did_manager.sign(PLAIN_TEXT)
    shared_data.did_manager.renew_control_key()
    signature_2 = shared_data.did_manager.sign(PLAIN_TEXT)

    assert (
        CodePackage.deserialise_bytes(signature_1).key.get_id()
        != CodePackage.deserialise_bytes(signature_2).key.get_id()
        and shared_data.did_manager.verify_signature(signature_1, PLAIN_TEXT)
        and shared_data.did_manager.verify_signature(signature_2, PLAIN_TEXT)
    ), "Signature verification across key renewal works"


def test_delete_did_manager():
    blockchain_id = shared_data.did_manager.blockchain.blockchain_id

    shared_data.did_manager.delete()

    assert blockchain_id not in walytis_api.list_blockchain_ids(), (
        "Delete DidManager"
    )

    def test_threads_cleanup() -> None:
        """Test that no threads are left running."""

    cleanup()
    assert await_thread_cleanup(timeout=10)
