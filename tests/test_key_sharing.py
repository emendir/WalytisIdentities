import testing_utils
import tempfile
import walytis_beta_api as walytis_api
import pytest
import sys
import os
from testing_utils import mark

from multi_crypt import Crypt
import shutil


if True:
    sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

    from identity.did_objects import Key
    from identity.key_store import KeyStore
    from identity.identity import IdentityAccess
    from identity.did_manager import DidManager


def test_preparations():
    pytest.device_1_config_dir = tempfile.mkdtemp()
    pytest.device_2_config_dir = tempfile.mkdtemp()
    pytest.key_store_path = os.path.join(pytest.device_1_config_dir, "keystore.json")

    pytest.CRYPTO_FAMILY = "EC-secp256k1"  # the cryptographic family to use for the tests
    pytest.CRYPT = Crypt.new(pytest.CRYPTO_FAMILY)


def cleanup():
    shutil.rmtree(pytest.device_1_config_dir)
    shutil.rmtree(pytest.device_2_config_dir)
    pytest.device_1.delete()
    pytest.device_2.device_did_manager.delete()
    pytest.device_2.terminate()


def test_create_identity():
    pytest.device_1 = IdentityAccess.create(
        pytest.device_1_config_dir,
        pytest.CRYPT,
    )
    mark(isinstance(pytest.device_1, IdentityAccess), "Created IdentityAccess")


def test_add_device_identity():
    invitation = pytest.device_1.create_invitation()

    pytest.device_2 = IdentityAccess.join(
        invitation,
        pytest.device_2_config_dir,
        pytest.CRYPT
    )

    pytest.device_1.add_member(pytest.device_2.device_did_manager.get_did())

    members = pytest.device_1.get_members()
    device_2_did = pytest.device_2.device_did_manager.get_did()
    mark(
        {"did": device_2_did} in pytest.device_1.person_did_manager.get_members()
        and {"did": device_2_did} in pytest.device_1.get_members(),
        "Added member"
    )


def run_tests():
    print("\nRunning tests for Key Sharing:")
    test_preparations()

    test_create_identity()
    test_add_device_identity()
    cleanup()


if __name__ == "__main__":
    testing_utils.PYTEST = False
    testing_utils.BREAKPOINTS = True
    run_tests()
