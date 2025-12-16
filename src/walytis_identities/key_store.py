import json
from multi_crypt import Crypt
import os
from dataclasses import dataclass
from typing import Type, TypeVar

import portalocker

from .key_objects import (
    Key,
    KeyGroup,
    CodePackage,
    generate_key_id,
    decode_keygroup_id,
)
from .utils import (
    bytes_from_string,
    bytes_to_string,
    time_to_string,
    string_to_time,
)
from datetime import datetime


_KeyStore = TypeVar("_KeyStore", bound="KeyStore")


class KeyStore:
    keys: dict[str, Key]  # key_id: Key object

    def __init__(
        self,
        key_store_path: str,
        key: Key | KeyGroup | _KeyStore,
    ):
        assert (
            isinstance(key, Key)
            or isinstance(key, KeyGroup)
            or isinstance(key, KeyStore)
        ), f"INITIALISING: KEY IS {type(key)}"
        self.key_store_path = key_store_path
        self.lock_file_path = key_store_path + ".lock"
        self.keys: dict[str, Key] = {}
        self._custom_metadata = {}
        self.app_lock = portalocker.Lock(self.lock_file_path)
        self._load_appdata(key)
        assert isinstance(self.key, Key) or isinstance(self.key, KeyGroup), (
            f"INITIALISED: KEY IS {type(key)}"
        )

    def _load_appdata(self, _key: Key | _KeyStore):
        if not os.path.exists(os.path.dirname(self.key_store_path)):
            raise FileNotFoundError(
                "The directory of the keystore path doesn't exist:\n"
                f"{os.path.dirname(self.key_store_path)}"
            )
        self.app_lock.acquire(timeout=0.1)

        if not os.path.exists(self.key_store_path):
            self.keys: dict[str, Key] = {}
            if isinstance(_key, KeyStore):
                raise ValueError(
                    "Key must be supplied when creating a new KeyStore."
                )
            self.key = _key
            return
        with open(self.key_store_path, "r") as file:
            data = json.loads(file.read())

        appdata_encryption_public_key = data["appdata_encryption_public_key"]
        if isinstance(_key, KeyStore):
            owner_keystore = _key
            key = owner_keystore.get_generic_key(appdata_encryption_public_key)
        else:
            key = _key
        assert isinstance(key, Key) or isinstance(key, KeyGroup), (
            "_load_appdata: KEY IS NONE"
        )
        self.key = key
        if appdata_encryption_public_key != key.get_id():
            raise ValueError(
                "Wrong cryptographic key for unlocking keystore.\n"
                f"{appdata_encryption_public_key}\n"
                f"{self.key.public_key.hex()}"
            )

        keys = {}
        encrypted_keys = data["keys"]
        for encrypted_key in encrypted_keys:
            key = Key.deserialise_private_encrypted(encrypted_key, self.key)
            keys.update({key.get_id(): key})
        self.keys = keys
        self._custom_metadata = data.get("custom_metadata", {})

    def get_all_keys(self) -> list[Key]:
        return self.keys.values()

    def get_custom_metadata(self):
        return self._custom_metadata

    def set_custom_metadata(self, data: dict):
        self._custom_metadata = data
        self.save_appdata()

    def update_custom_metadata(self, data: dict):
        """Add new/modify existing fieds to/in custom metadata."""
        self._custom_metadata.update(data)
        self.save_appdata()

    def save_appdata(self):
        encrypted_keys = []
        for key_id, key in list(self.keys.items()):
            assert isinstance(self.key, Key) or isinstance(
                self.key, KeyGroup
            ), "SAVING: KEY IS NONE"
            encrypted_serialised_key = key.serialise_private_encrypted(
                self.key, allow_missing_private_key=True
            )
            encrypted_keys.append(encrypted_serialised_key)
        data = {
            "appdata_encryption_public_key": self.key.get_id(),
            "keys": encrypted_keys,
            "custom_metadata": self._custom_metadata,
        }

        with open(self.key_store_path, "w+") as file:
            file.write(json.dumps(data))

    def add_key(self, key: Key | KeyGroup) -> Key | KeyGroup:
        if isinstance(key, KeyGroup):
            return self.add_keygroup(key)

        key_id = key.get_id()
        if key_id not in self.keys:
            self.keys.update({key_id: key})
            self.save_appdata()
        elif key.private_key and not self.keys[key_id].private_key:
            self.keys[key_id].unlock(key.private_key)
            self.save_appdata()
        return key

    def add_keygroup(self, keygroup: KeyGroup) -> KeyGroup:
        for key in keygroup.keys:
            self.add_key(key)
        return keygroup

    def get_key(self, key_id: str) -> Key:
        if "|" in key_id:
            raise Exception("It looks like this key_id belongs to a KeyGroup")
        key = self.keys.get(key_id, None)
        if not key:
            raise UnknownKeyError
        return key

    def get_keygroup(self, keygroup_id: str):
        keys = [
            self.get_key(key_id) for key_id in decode_keygroup_id(keygroup_id)
        ]

        return KeyGroup(keys)

    def get_generic_key(self, key_id: str) -> Key | KeyGroup:
        if "|" in key_id:
            return self.get_keygroup(key_id)
        else:
            return self.get_key(key_id)

    def get_key_from_public(
        self, public_key: str | bytes | bytearray, family: str
    ) -> Key:
        if isinstance(public_key, str):
            public_key = bytes.fromhex(public_key)
        for key in self.keys.values():
            if key.public_key == public_key and key.family == family:
                return key
        raise UnknownKeyError()

    @staticmethod
    def encrypt(
        data: bytes, key: Key, encryption_options: str | None = None
    ) -> CodePackage:
        """Encrypt the provided data using the specified key.

        Args:
            data (bytes): the data to encrypt
            key (Key): the key to use to encrypt the data
            encryption_options (str): specification code for which
                            encryption/decryption protocol should be used
        Returns:
            CodePackage: an object containing the ciphertext, public-key,
                            crypto-family and encryption-options
        """
        return CodePackage.encrypt(
            data=data, key=key, encryption_options=encryption_options
        )

    def decrypt(self, code_package: CodePackage) -> bytes:
        """Decrypt the provided data using the specified private key.

        Args:
            code_package: a CodePackage object containing the ciphertext,
                    public-key, crypto-family and encryption-options
        Returns:
            bytes: the decrypted data
        """
        if code_package.key.is_unlocked():
            key = code_package.key
        else:
            key = self.get_generic_key(code_package.key.get_id())
        return key.decrypt(
            encrypted_data=code_package.code,
            encryption_options=code_package.operation_options,
        )

    @staticmethod
    def sign(
        data: bytes, key: Key, signature_options: str = ""
    ) -> CodePackage:
        """Sign the provided data using the specified key.

        Args:
            data (bytes): the data to sign
            key (Key): the key to use to sign the data
            signature_options (str): specification code for which
                            signing/verification protocol should be used
        Returns:
            CodePackage: an object containing the signature, public-key,
                            crypto-family and signature-options
        """
        signature = key.sign(
            data=data,
            signature_options=signature_options,
        )
        return CodePackage(
            code=signature,
            key=key,
            operation_options=signature_options,
        )

    def verify_signature(self, code_package: CodePackage, data: bytes) -> bool:
        """Decrypt the provided data using the specified private key.

        Args:
            code_package: a CodePackage object containing the ciphertext,
                    public-key, crypto-family and encryption-options
            data: the data to verify the signature against
        Returns:
            bytes: the decrypted data
        """
        return code_package.key.verify_signature(
            signature=code_package.code,
            data=data,
            signature_options=code_package.operation_options,
        )

    @staticmethod
    def get_keystore_pubkey(key_store_path: str) -> str:
        """Given a keystore appdata file, get its encryption key ID."""
        with open(key_store_path, "r") as file:
            data = json.loads(file.read())
        key_id = data["appdata_encryption_public_key"]
        return key_id

    def terminate(self):
        self.app_lock.release()

    def reload(self) -> "KeyStore":
        self._load_appdata(self.key)
        return self

    def clone(self, key_store_path: str, key: Key) -> "KeyStore":
        key_store = KeyStore(key_store_path=key_store_path, key=key)
        for key in self.get_all_keys():
            key_store.add_key(key)
        key_store.set_custom_metadata(self.get_custom_metadata())
        return key_store

    def __del__(self):
        self.terminate()


class UnknownKeyError(Exception):
    """When looking up a key we don't have."""
