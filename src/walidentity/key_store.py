from typing import Type, TypeVar
from typing import Any
from strict_typing import strictly_typed
from decorate_all import decorate_all_functions
from .did_objects import Key
import json
import os
from .utils import bytes_to_string, bytes_from_string
from dataclasses import dataclass

_CodePackage = TypeVar('_CodePackage', bound='CodePackage')


@dataclass
class CodePackage:
    """Package of encrypted data or a signature with crypto-key-metadata."""
    code: bytes
    public_key: bytes
    family: str
    operation_options: str

    @classmethod
    def deserialise(cls: Type[_CodePackage], data: str) -> _CodePackage:
        _data = json.loads(data)
        return cls(
            code=bytes_from_string(_data["code"]),
            public_key=bytes_from_string(_data["public_key"]),
            family=_data["family"],
            operation_options=_data["operation_options"],
        )

    @classmethod
    def deserialise_bytes(cls: Type[_CodePackage], data: bytes) -> _CodePackage:
        _data = data.decode()
        return cls.deserialise(_data)

    def serialise(self) -> str:
        return json.dumps({
            "code": bytes_to_string(self.code),
            "public_key": bytes_to_string(self.public_key),
            "family": self.family,
            "operation_options": self.operation_options
        })

    def serialise_bytes(self) -> bytes:
        return self.serialise().encode()


class KeyStore:
    keys: dict[str, Key]  # key_id: Key object

    def __init__(self, key_store_path: str, key: Key):
        self.key_store_path = key_store_path
        self.key = key
        self.keys: dict[str, Key] = {}
        self._load_appdata()

    def _load_appdata(self):
        if not os.path.exists(os.path.dirname(self.key_store_path)):
            raise FileNotFoundError(
                "The directory of the keystore path doesn't exist.")
        if not os.path.exists(self.key_store_path):
            self.keys: dict[str, Key] = {}
            return
        with open(self.key_store_path, "r") as file:
            data = json.loads(file.read())
        appdata_encryption_public_key = data["appdata_encryption_public_key"]
        encrypted_keys = data["keys"]

        if appdata_encryption_public_key != self.key.public_key.hex():
            raise ValueError(
                "Wrong cryptographic key for unlocking keystore.\n"
                f"{appdata_encryption_public_key}\n"
                f"{self.key.public_key.hex()}"
            )

        keys = {}
        for encrypted_key in encrypted_keys:
            key = Key.deserialise(encrypted_key, self.key)
            keys.update({key.get_key_id(): key})
        self.keys = keys

    def save_appdata(self):
        encrypted_keys = []
        for key_id, key in list(self.keys.items()):
            encrypted_serialised_key = key.serialise(
                self.key, allow_missing_private_key=True
            )
            encrypted_keys.append(encrypted_serialised_key)
        data = {
            "appdata_encryption_public_key": self.key.public_key.hex(),
            "keys": encrypted_keys
        }

        with open(self.key_store_path, "w+") as file:
            file.write(json.dumps(data))

    def add_key(self, key: Key):
        key_id = key.get_key_id()
        if key_id not in self.keys:
            self.keys.update({key_id: key})
            self.save_appdata()
        elif key.private_key and not self.keys[key_id].private_key:
            self.keys[key_id].unlock(key.private_key)
            self.save_appdata()

    def get_key(self, key_id: str) -> Key:
        key = self.keys.get(key_id, None)
        if not key:
            raise UnknownKeyError
        return key

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
        data: bytes,
        key: Key,
        encryption_options: str = ""
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
        cipher = key.encrypt(
            data_to_encrypt=data,
            encryption_options=encryption_options,
        )
        return CodePackage(
            code=cipher,
            public_key=key.public_key,
            family=key.family,
            operation_options=encryption_options
        )

    def decrypt(
        self,
        code_package: CodePackage
    ) -> bytes:
        """Decrypt the provided data using the specified private key.

        Args:
            code_package: a CodePackage object containing the ciphertext,
                    public-key, crypto-family and encryption-options
        Returns:
            bytes: the decrypted data
        """
        key = self.get_key_from_public(code_package.public_key, code_package.family)
        encrypted_data = code_package.code
        return key.decrypt(
            encrypted_data=encrypted_data,
            encryption_options=code_package.operation_options,
        )

    @staticmethod
    def sign(
        data: bytes,
        key: Key,
        signature_options: str = ""
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
            public_key=key.public_key,
            family=key.family,
            operation_options=signature_options
        )

    def verify_signature(
        self,
        code_package: CodePackage,
        data: bytes
    ) -> bool:
        """Decrypt the provided data using the specified private key.

        Args:
            code_package: a CodePackage object containing the ciphertext,
                    public-key, crypto-family and encryption-options
            data: the data to verify the signature against
        Returns:
            bytes: the decrypted data
        """
        key = self.get_key_from_public(code_package.public_key, code_package.family)
        signature = code_package.code
        return key.verify_signature(
            signature=signature,
            data=data,
            signature_options=code_package.operation_options,
        )


class UnknownKeyError(Exception):
    """When looking up a key we don't have."""


decorate_all_functions(strictly_typed, __name__)
