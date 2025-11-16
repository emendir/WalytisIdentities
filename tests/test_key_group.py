import os
import tempfile

import _auto_run_with_pytest  # noqa
from conftest import cleanup_walytis_ipfs
from emtest import await_thread_cleanup

from walytis_identities.key_objects import Key, KeyGroup
from walytis_identities.utils import generate_random_string

KEY_FAMILIES = [
    "EC-secp256k1",
    "EC-secp256k1",
]


class SharedData:
    keygroup: KeyGroup
    locked_kg: KeyGroup


shared_data = SharedData()


def test_create_keygroup():
    shared_data.keygroup = KeyGroup.create(KEY_FAMILIES)
    for i, family in enumerate(KEY_FAMILIES):
        assert shared_data.keygroup.get_keys()[i].family == family


def test_id():
    print(shared_data.keygroup.get_id())
    shared_data.locked_kg = KeyGroup.from_id(shared_data.keygroup.get_id())

    for i, key in enumerate(shared_data.keygroup.keys):
        assert key.get_id() == shared_data.locked_kg.keys[i].get_id()


def test_signing():
    data = generate_random_string(20).encode()
    signature = shared_data.keygroup.sign(data)
    print(signature)
    assert shared_data.locked_kg.verify_signature(signature, data)


def test_encryption():
    data = generate_random_string(20).encode()
    cipher = shared_data.locked_kg.encrypt(data)
    assert shared_data.keygroup.decrypt(cipher) == data


def test_serialisation_private():
    serialisation_key = Key.create(KEY_FAMILIES[0])
    data = shared_data.keygroup.serialise_private_encrypted(serialisation_key)
    reloaded = KeyGroup.deserialise_private_encrypted(data, serialisation_key)
    assert reloaded.get_id() == shared_data.keygroup.get_id()
    assert reloaded.is_unlocked()


def test_serialisation():
    data = shared_data.keygroup.serialise_private()
    reloaded = KeyGroup.deserialise_private(
        data,
    )
    assert reloaded.get_id() == shared_data.keygroup.get_id()
    assert reloaded.is_unlocked()


def test_threads_cleanup() -> None:
    """Test that no threads are left running."""
    cleanup_walytis_ipfs()
    assert await_thread_cleanup(timeout=10)
