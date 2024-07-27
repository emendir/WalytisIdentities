import tempfile
import walytis_beta_api as walytis_api
import pytest
import sys
import os
from testing_utils import mark

from multi_crypt import Crypt
import shutil


if True:
    sys.path.insert(0, os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"
    ))

    from identity.did_objects import Key
    from identity.key_store import KeyStore, CodePackage


def test_preparations():
    pytest.tempdir = tempfile.mkdtemp()
    pytest.key_store_path = os.path.join(pytest.tempdir, "keystore.json")

    pytest.CRYPTO_FAMILY = "EC-secp256k1"  # the cryptographic family to use for the tests
    pytest.CRYPT = Crypt.new(pytest.CRYPTO_FAMILY)


def test_key_serialisation():
    key1 = Key.create(pytest.CRYPTO_FAMILY)
    key2 = Key.create(pytest.CRYPTO_FAMILY)
    mark(
        key2.decrypt(bytes.fromhex(key1.serialise(key2)["private_key"])) == key1.private_key,
        "private key encryption in serialisation"
    )


def test_add_get_key():
    pytest.crypt1 = Key.create(pytest.CRYPTO_FAMILY)
    pytest.crypt2 = Key.create(pytest.CRYPTO_FAMILY)

    pytest.keystore = KeyStore(pytest.key_store_path, pytest.CRYPT)

    pytest.keystore.add_key(pytest.crypt1)
    pytest.keystore.add_key(pytest.crypt2)

    c1 = pytest.keystore.get_key(pytest.crypt1.get_key_id())
    c2 = pytest.keystore.get_key(pytest.crypt2.get_key_id())

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
    keystore = KeyStore(pytest.key_store_path, pytest.CRYPT)

    c1 = keystore.get_key(pytest.crypt1.get_key_id())
    c2 = keystore.get_key(pytest.crypt2.get_key_id())

    mark(
        c1.public_key == pytest.crypt1.public_key
        and c1.private_key == pytest.crypt1.private_key
        and c1.family == pytest.crypt1.family
        and c2.public_key == pytest.crypt2.public_key
        and c2.private_key == pytest.crypt2.private_key
        and c2.family == pytest.crypt2.family,
        "reopen keystore"
    )


PLAIN_TEXT = "Hello there!".encode()


def test_encryption_package():
    code_package = pytest.keystore.encrypt(PLAIN_TEXT, pytest.crypt2)
    decrypted = pytest.keystore.decrypt(code_package)
    mark(decrypted == PLAIN_TEXT, "encryption using CodePackage")


def test_signing_package():
    code_package = pytest.keystore.sign(PLAIN_TEXT, pytest.crypt2)
    validity = pytest.keystore.verify_signature(code_package, PLAIN_TEXT)
    mark(validity, "signing using CodePackage")


def test_code_package_serialisation():
    code_package = pytest.keystore.encrypt(PLAIN_TEXT, pytest.crypt2)
    new_code_package = CodePackage.deserialise_bytes(code_package.serialise_bytes())
    decrypted = pytest.keystore.decrypt(new_code_package)
    mark(decrypted == PLAIN_TEXT, "CodePackage serialisation")


def cleanup():
    shutil.rmtree(pytest.tempdir)


def run_tests():
    print("\nRunning tests for KeyStore:")
    test_preparations()
    test_key_serialisation()
    test_add_get_key()
    test_reopen_keystore()
    test_encryption_package()
    test_signing_package()
    test_code_package_serialisation()
    cleanup()


if __name__ == "__main__":
    run_tests()
