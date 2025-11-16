import json
import os
import shutil
import tempfile

import _auto_run_with_pytest  # noqa
from conftest import cleanup_walytis_ipfs
import pytest
import walytis_beta_api
from emtest import await_thread_cleanup
from testing_utils import CRYPTO_FAMILY

from walytis_identities.did_manager import DidManager
from walytis_identities.key_objects import Key
from walytis_identities.group_did_manager import GroupDidManager
from walytis_identities.key_store import CodePackage, KeyStore


class SharedData:
    def __init__(self):
        self.member_1: DidManager | None = None
        self.group_1: GroupDidManager | None = None
        self.member: DidManager | None = None
        self.group: GroupDidManager | None = None
        self.person_config_dir = tempfile.mkdtemp()
        self.person_config_dir1 = tempfile.mkdtemp()
        self.key_store_path = os.path.join(
            self.person_config_dir, "master_keystore.json"
        )

        # the cryptographic family to use for the tests
        self.CRYPTO_FAMILY = CRYPTO_FAMILY
        self.KEY = Key.create(self.CRYPTO_FAMILY)


shared_data = SharedData()


def test_create_person_identity() -> None:
    device_keystore_path = os.path.join(
        shared_data.person_config_dir, "device_keystore.json"
    )
    profile_keystore_path = os.path.join(
        shared_data.person_config_dir, "profile_keystore.json"
    )

    device_did_keystore = KeyStore(device_keystore_path, shared_data.KEY)
    profile_did_keystore = KeyStore(profile_keystore_path, shared_data.KEY)
    shared_data.member_1 = DidManager.create(device_did_keystore)
    shared_data.group_1 = GroupDidManager.create(
        profile_did_keystore, shared_data.member_1
    )

    members = shared_data.group_1.get_members()
    shared_data.invitation_code = json.dumps(
        shared_data.group_1.invite_member()
    )

    assert (
        isinstance(shared_data.group_1, GroupDidManager)
        and len(members) == 1
        and shared_data.group_1.member_did_manager.did in members[0].did
    ), "Create GroupDidManager"

    shared_data.group_1.terminate()


def test_load_person_identity() -> None:
    if not shared_data.member_1 or not shared_data.group_1:
        pytest.skip("Aborting test due to previous failures")
    device_keystore_path = os.path.join(
        shared_data.person_config_dir, "device_keystore.json"
    )
    profile_keystore_path = os.path.join(
        shared_data.person_config_dir, "profile_keystore.json"
    )

    device_did_keystore = KeyStore(device_keystore_path, shared_data.KEY)
    profile_did_keystore = KeyStore(profile_keystore_path, shared_data.KEY)
    group_1 = GroupDidManager(profile_did_keystore, device_did_keystore)
    member_did = shared_data.group_1.member_did_manager.did
    person_did = shared_data.group_1.did
    members = group_1.get_members()

    invitations = group_1.member_invitations
    assert (
        group_1.member_did_manager.did == member_did
        and group_1.did == person_did
        and len(members) == 1
        and group_1.member_did_manager.did in members[0].did
        and invitations
        and invitations[0].generate_code().serialise()
        == shared_data.invitation_code
    ), "Load GroupDidManager"

    # group_1.terminate()
    shared_data.group_1 = group_1


PLAIN_TEXT = "Hello there!".encode()


def test_encryption() -> None:
    if not shared_data.member_1 or not shared_data.group_1:
        pytest.skip("Aborting test due to previous failures")
    cipher_1 = shared_data.group_1.encrypt(PLAIN_TEXT)
    shared_data.group_1.renew_control_key()
    cipher_2 = shared_data.group_1.encrypt(PLAIN_TEXT)

    assert (
        CodePackage.deserialise_bytes(cipher_1).key.get_id()
        != CodePackage.deserialise_bytes(cipher_2).key.get_id()
        and shared_data.group_1.decrypt(cipher_1) == PLAIN_TEXT
        and shared_data.group_1.decrypt(cipher_2) == PLAIN_TEXT
    ), "Encryption across key renewal works"


def test_signing() -> None:
    if not shared_data.member_1 or not shared_data.group_1:
        pytest.skip("Aborting test due to previous failures")
    signature_1 = shared_data.group_1.sign(PLAIN_TEXT)
    shared_data.group_1.renew_control_key()
    signature_2 = shared_data.group_1.sign(PLAIN_TEXT)

    assert (
        CodePackage.deserialise_bytes(signature_1).key.get_id()
        != CodePackage.deserialise_bytes(signature_2).key.get_id()
        and shared_data.group_1.verify_signature(signature_1, PLAIN_TEXT)
        and shared_data.group_1.verify_signature(signature_2, PLAIN_TEXT)
    ), "Signature verification across key renewal works"


def test_delete_person_identity() -> None:
    if not shared_data.member_1 or not shared_data.group_1:
        pytest.skip("Aborting test due to previous failures")
    group_blockchain = shared_data.group_1.blockchain.blockchain_id
    member_blockchain = (
        shared_data.group_1.member_did_manager.blockchain.blockchain_id
    )
    shared_data.group_1.delete()

    # ensure the blockchains of both the person and the member identities
    # have been deleted

    assert (
        group_blockchain not in walytis_beta_api.list_blockchain_ids()
        and member_blockchain not in walytis_beta_api.list_blockchain_ids()
    ), "Delete GroupDidManager"


def test_create_member_given_path() -> None:
    """Test DidManager instantiation given a path instead of a Keystore."""
    if not shared_data.member_1 or not shared_data.group_1:
        pytest.skip("Aborting test due to previous failures")
    conf_dir = tempfile.mkdtemp()
    shared_data.member = DidManager.create(conf_dir)
    shared_data.member.terminate()
    key_store_path = os.path.join(
        conf_dir, shared_data.member.blockchain.blockchain_id + ".json"
    )
    key = shared_data.member.key_store.key
    reloaded = DidManager(KeyStore(key_store_path, key))
    reloaded.terminate()

    assert (
        os.path.exists(key_store_path)
        and reloaded.get_control_keys().is_unlocked()
        == shared_data.member.get_control_keys().is_unlocked()
    ), "Created member given a directory."


def test_create_group_given_path() -> None:
    """Test DidManager instantiation given a path instead of a Keystore."""
    if not shared_data.member:
        pytest.skip("Aborting test due to previous failures")
    if not shared_data.member_1 or not shared_data.group_1:
        pytest.skip("Aborting test due to previous failures")
    conf_dir = tempfile.mkdtemp()
    shared_data.group = GroupDidManager.create(conf_dir, shared_data.member)
    shared_data.group.terminate()
    key_store_path = os.path.join(
        conf_dir, shared_data.group.blockchain.blockchain_id + ".json"
    )
    key = shared_data.group.key_store.key

    reloaded = GroupDidManager(
        KeyStore(key_store_path, key), shared_data.member
    )
    reloaded.terminate()

    assert (
        os.path.exists(key_store_path)
        and reloaded.get_control_keys().is_unlocked()
        == shared_data.group.get_control_keys().is_unlocked()
    ), "Created group given a directory."


def cleanup() -> None:
    """Clean up resources used during tests."""
    if os.path.exists(shared_data.person_config_dir):
        shutil.rmtree(shared_data.person_config_dir)
    cleanup_walytis_ipfs()


def test_threads_cleanup() -> None:
    """Test that no threads are left running."""
    cleanup()
    assert await_thread_cleanup(timeout=10)
