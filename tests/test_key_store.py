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
    # from management import friends_management
    # from management import identity_management
    # from identity.identity import IdentityAccess
    from identity.did_manager import DidManager
    from identity.did_objects import Key
    from identity.key_store import KeyStore


def test_preparations():
    pytest.tempdir = tempfile.mkdtemp()
    pytest.keystore_path = os.path.join(pytest.tempdir, "keystore.json")

    pytest.CRYPTO_FAMILY = "EC-secp256k1"  # the cryptographic family to use for the tests
    pytest.CRYPT = Crypt.new(pytest.CRYPTO_FAMILY)


def test_add_get_key():
    pytest.crypt1 = Crypt.new(pytest.CRYPTO_FAMILY)
    pytest.crypt2 = Crypt.new(pytest.CRYPTO_FAMILY)

    pytest.keystore = KeyStore(pytest.keystore_path, pytest.CRYPT)

    pytest.keystore.add_key("crypt1", pytest.crypt1)
    pytest.keystore.add_key("crypt2", pytest.crypt2)

    c1 = pytest.keystore.get_key("crypt1")
    c2 = pytest.keystore.get_key("crypt2")

    mark(
        c1.public_key == pytest.crypt1.public_key
        and c1.private_key == pytest.crypt1.private_key
        and c1.family == pytest.crypt1.family
        and c2.public_key == pytest.crypt2.public_key
        and c2.private_key == pytest.crypt2.private_key
        and c2.family == pytest.crypt2.family,
        "add and get key"
    )


def test_reopen_keystore():
    pytest.keystore = KeyStore(pytest.keystore_path, pytest.CRYPT)

    c1 = pytest.keystore.get_key("crypt1")
    c2 = pytest.keystore.get_key("crypt2")

    mark(
        c1.public_key == pytest.crypt1.public_key
        and c1.private_key == pytest.crypt1.private_key
        and c1.family == pytest.crypt1.family
        and c2.public_key == pytest.crypt2.public_key
        and c2.private_key == pytest.crypt2.private_key
        and c2.family == pytest.crypt2.family,
        "reopen keystore"
    )


def cleanup():
    shutil.rmtree(pytest.tempdir)


def run_tests():
    test_preparations()
    test_add_get_key()
    test_reopen_keystore()
    cleanup()


if __name__ == "__main__":
    run_tests()
