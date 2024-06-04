import testing_utils
import os
import shutil
import sys
import tempfile
from multi_crypt import Crypt
import pytest
import walytis_beta_api as walytis_api
from testing_utils import mark

if True:
    sys.path.insert(0, os.path.abspath(
        os.path.dirname(os.path.dirname(__file__))))

    from identity.did_manager import DidManager
    from identity.did_objects import Key
    from identity.key_store import KeyStore


def pytest_configure():
    pytest.tempdir = tempfile.mkdtemp()
    pytest.key_store_path = os.path.join(pytest.tempdir, "keystore.json")

    pytest.CRYPTO_FAMILY = "EC-secp256k1"  # the cryptographic family to use for the tests
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
        "id": pytest.did_manager.get_did(),
        "verificationMethod": [
            pytest.new_control_key.generate_key_spec(
                pytest.did_manager.get_did())
        ]
    }
    pytest.did_manager.update_did_doc(pytest.did_doc)
    mark(pytest.did_manager.get_did_doc() == pytest.did_doc, "Update DID Doc")


def test_update_members_list():
    pytest.members_list = [
        {'did': 'device1'},
        {'did': 'device2'},
    ]
    pytest.did_manager.update_members_list(pytest.members_list)
    mark(
        pytest.did_manager.get_members() == pytest.members_list,
        "Update Members List"
    )


def test_reload_did_manager():
    did_manager_copy = DidManager(
        pytest.did_manager.blockchain.blockchain_id,
        pytest.keystore
    )

    mark((
        did_manager_copy.get_control_key().public_key == pytest.new_control_key.public_key
        and did_manager_copy.get_did_doc() == pytest.did_doc
        and did_manager_copy.get_members() == pytest.members_list
    ),
        "Reload DID Manager"
    )
    did_manager_copy.terminate()


def run_tests():
    print("\nRunning tests for DidManager:")
    testing_utils.PYTEST = False
    pytest_configure()  # run test preparations

    # run tests
    test_create_did_manager()
    test_renew_control_key()
    test_update_did_doc()
    test_update_members_list()
    test_reload_did_manager()
    test_delete_did_manager()

    pytest_unconfigure()  # run test cleanup


if __name__ == "__main__":
    run_tests()
