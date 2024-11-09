from decorate_all import decorate_all_functions
from strict_typing import strictly_typed
from walidentity.group_did_manager import GroupDidManager
from multi_crypt import Crypt

import os
from walidentity.key_store import KeyStore
from walidentity.did_manager import DidManager
from walidentity.did_objects import Key


def create_person_identity(config_dir: str, key: Key) -> GroupDidManager:
    device_keystore_path = os.path.join(config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(config_dir, "profile_keystore.json")

    device_did_keystore = KeyStore(device_keystore_path, key)
    profile_did_keystore = KeyStore(profile_keystore_path, key)
    device_did_manager = DidManager.create(device_did_keystore)
    group_did_manager = GroupDidManager.create(
        profile_did_keystore,device_did_manager
    )
    return group_did_manager


def update_identity():
    pass


def delete_identity():
    pass


decorate_all_functions(strictly_typed, __name__)
