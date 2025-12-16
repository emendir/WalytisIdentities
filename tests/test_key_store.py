import os
import shutil
import tempfile

import _auto_run_with_pytest  # noqa
from conftest import cleanup_walytis_ipfs
from emtest import await_thread_cleanup

from walytis_identities.key_objects import Key, KeyGroup
from walytis_identities.key_store import CodePackage, KeyStore


class SharedData:
    def __init__(self):
        self.tempdir = tempfile.mkdtemp()
        self.key_store_path = os.path.join(self.tempdir, "keystore.json")

        # the cryptographic family to use for the tests
        self.CRYPTO_FAMILY = "EC-secp256k1"
        self.KEY = Key.create(self.CRYPTO_FAMILY)


shared_data = SharedData()


def test_key_serialisation():
    key1 = Key.create(shared_data.CRYPTO_FAMILY)
    key2 = Key.create(shared_data.CRYPTO_FAMILY)

    assert (
        key2.decrypt(
            bytes.fromhex(
                key1.serialise_private_encrypted(key2)["private_key"]
            )
        )
        == key1.private_key
    ), "private key encryption in serialisation"


def test_add_get_key():
    shared_data.crypt1 = Key.create(shared_data.CRYPTO_FAMILY)
    shared_data.crypt2 = Key.create(shared_data.CRYPTO_FAMILY)

    shared_data.keystore = KeyStore(
        shared_data.key_store_path, shared_data.KEY
    )

    shared_data.keystore.add_key(shared_data.crypt1)
    shared_data.keystore.add_key(shared_data.crypt2)

    c1 = shared_data.keystore.get_key(shared_data.crypt1.get_id())
    c2 = shared_data.keystore.get_key(shared_data.crypt2.get_id())

    shared_data.keystore.terminate()

    assert (
        c1.public_key == shared_data.crypt1.public_key
        and c1.private_key == shared_data.crypt1.private_key
        and c1.family == shared_data.crypt1.family
        and c2.public_key == shared_data.crypt2.public_key
        and c2.private_key == shared_data.crypt2.private_key
        and c2.family == shared_data.crypt2.family
    ), "add and get key"


def test_reopen_keystore():
    keystore = KeyStore(shared_data.key_store_path, shared_data.KEY)

    c1 = keystore.get_key(shared_data.crypt1.get_id())
    c2 = keystore.get_key(shared_data.crypt2.get_id())

    assert (
        c1.public_key == shared_data.crypt1.public_key
        and c1.private_key == shared_data.crypt1.private_key
        and c1.family == shared_data.crypt1.family
        and c2.public_key == shared_data.crypt2.public_key
        and c2.private_key == shared_data.crypt2.private_key
        and c2.family == shared_data.crypt2.family
    ), "reopen keystore"


def test_keystore_from_keystore():
    """Test that a key store can be loaded passing a keystore instead of a key"""
    # create parent KeyStore
    parent_keystore = KeyStore(shared_data.key_store_path, shared_data.KEY)
    key = parent_keystore.add_key(Key.create(shared_data.CRYPTO_FAMILY))
    assert isinstance(key, Key)

    # create child KeyStore
    tempdir = tempfile.mkdtemp()
    key_store_path = os.path.join(tempdir, "keystore.json")
    child_keystore = KeyStore(key_store_path, key)
    child_key = child_keystore.add_key(Key.create(shared_data.CRYPTO_FAMILY))
    child_keystore.terminate()

    # reload KeyStore
    reloaded_keystore = KeyStore(key_store_path, parent_keystore)
    reloaded_key = reloaded_keystore.get_key(child_key.get_id())
    assert reloaded_key.private_key == child_key.private_key


PLAIN_TEXT = "Hello there!".encode()


def test_encryption_package():
    code_package = shared_data.keystore.encrypt(PLAIN_TEXT, shared_data.crypt2)
    decrypted = shared_data.keystore.decrypt(code_package)
    assert decrypted == PLAIN_TEXT, "encryption using CodePackage"


def test_signing_package():
    code_package = shared_data.keystore.sign(PLAIN_TEXT, shared_data.crypt2)
    validity = shared_data.keystore.verify_signature(code_package, PLAIN_TEXT)
    assert validity, "signing using CodePackage"


def test_code_package_serialisation():
    code_package = shared_data.keystore.encrypt(PLAIN_TEXT, shared_data.crypt2)
    new_code_package = CodePackage.deserialise_bytes(
        code_package.serialise_bytes()
    )
    decrypted = shared_data.keystore.decrypt(new_code_package)
    assert decrypted == PLAIN_TEXT, "CodePackage serialisation"


def test_keygroup():
    keygroup = KeyGroup.create(
        [shared_data.CRYPTO_FAMILY, shared_data.CRYPTO_FAMILY]
    )
    for key in keygroup.keys:
        shared_data.keystore.add_key(key)

    print(keygroup.get_id())
    reloaded_kg = shared_data.keystore.get_keygroup(keygroup.get_id())
    for i, key in enumerate(keygroup.keys):
        assert reloaded_kg.keys[i].get_id() == key.get_id()
        assert reloaded_kg.keys[i].private_key == key.private_key


def test_cleanup() -> None:
    """Test that no threads are left running."""
    cleanup_walytis_ipfs()
    if os.path.exists(shared_data.tempdir):
        shutil.rmtree(shared_data.tempdir)
    assert await_thread_cleanup(timeout=10)
