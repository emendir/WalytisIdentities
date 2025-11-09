import os
import shutil
import tempfile

import _auto_run_with_pytest  # noqa
from emtest import await_thread_cleanup

from walytis_identities.key_objects import Key, KeyGroup
from walytis_identities.key_store import CodePackage, KeyStore
from walytis_identities.utils import generate_random_string

KEY_FAMILIES = [
    "EC-secp256k1",
    "EC-secp256k1",
]


class SharedData:
    def __init__(self):
        self.tempdir = tempfile.mkdtemp()
        self.key_store_path = os.path.join(self.tempdir, "keystore.json")

        # the cryptographic family to use for the tests
        self.CRYPTO_FAMILY = "EC-secp256k1"
        self.KEY = Key.create(self.CRYPTO_FAMILY)
        self.key_group = None


shared_data = SharedData()


def test_create_keygroup():
    shared_data.key_group = KeyGroup.create(KEY_FAMILIES)
    for i, family in enumerate(KEY_FAMILIES):
        assert shared_data.key_group.get_keys()[i].family == family


def test_keygroup_id():
    print(shared_data.key_group.get_keygroup_id())
    shared_data.locked_kg = KeyGroup.from_keygroup_id(
        shared_data.key_group.get_keygroup_id()
    )

    for i, key in enumerate(shared_data.key_group.keys):
        assert key.get_key_id() == shared_data.locked_kg.keys[i].get_key_id()


def test_signing():
    data = generate_random_string(20).encode()
    signature = shared_data.key_group.sign(data)
    print(signature)
    assert shared_data.locked_kg.verify_signature(signature, data)


def test_encryption():
    data = generate_random_string(20).encode()
    cipher = shared_data.locked_kg.encrypt(data)
    assert shared_data.key_group.decrypt(cipher) == data
