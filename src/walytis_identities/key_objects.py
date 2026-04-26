"""Various objects used to facilitate cryptographic operations."""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Self

from brenthy_tools_beta.utils import (  # type: ignore
    bytes_to_string,
    string_to_bytes,
    string_to_time,
    time_to_string,
)
from multi_crypt import Crypt  # type: ignore

from .log import logger_keys as logger
from .utils import AbstractClassMeta


class GenericKey(ABC, metaclass=AbstractClassMeta):
    """Base class for Key and KeyGroup objects."""

    @classmethod
    @abstractmethod
    def from_id(cls, key_id: str) -> Self:
        """Instantiate given a key ID."""

    @abstractmethod
    def get_id(self) -> str:
        """Get this key's ID."""

    @abstractmethod
    def encrypt(
        self,
        data_to_encrypt: bytes,
        encryption_options: str | None = None,
    ) -> bytes:
        """Encrypt the provided data.

        Args:
            data_to_encrypt (bytes): the data to encrypt
            encryption_options (str): specification code for which
                                encryption/decryption protocol should be used
        Returns:
            bytes: the encrypted data
        """

    @abstractmethod
    def decrypt(
        self,
        encrypted_data: bytes,
        encryption_options: str | None = None,
    ) -> bytes:
        """Decrypt the provided data.

        Args:
            encrypted_data (bytes): the data to decrypt
            encryption_options (str): specification code for which
                                encryption/decryption protocol should be used
        Returns:
            bytes: the decrypted data
        """

    @abstractmethod
    def sign(self, data: bytes, signature_options: str | None = None) -> bytes:
        """Sign the provided data.

        Args:
            data (bytes): the data to sign
            private_key (bytes): the private key to be used for the signing
            signature_options (str): specification code for which
                                signature/verification protocol should be used
        Returns:
            bytes: the signature
        """

    @abstractmethod
    def verify_signature(
        self,
        signature: bytes,
        data: bytes,
        signature_options: str | None = None,
    ) -> bool:
        """Verify the given signature of the given data.

        Args:
            signature (bytes): the signaure to verify
            data (bytes): the data to sign
            public_key (bytes): the public key to verify the signature against
            signature_options (str): specification code for which
                                signature/verification protocol should be used
        Returns:
            bool: whether or not the signature matches the data
        """

    @abstractmethod
    def is_unlocked(self) -> bool:
        """Check whether we have this key's private key."""

    @abstractmethod
    def clone_public(self) -> Self:
        """Create a new key object without the private key."""


@dataclass
class Key(Crypt, GenericKey):
    """Represents a set of cryptographic keys, compatible with DID specs."""

    family: str
    public_key: bytes
    private_key: bytes | None
    creation_time: datetime

    def __init__(
        self,
        family: str,
        public_key: bytes | str,
        private_key: bytes | str | None,
        creation_time: datetime,
    ):
        """Create a Key object."""
        if isinstance(public_key, str):
            public_key = bytes.fromhex(public_key)

        if isinstance(private_key, str):
            private_key = bytes.fromhex(private_key)
        self.family = family
        self.public_key = public_key
        self.private_key = private_key
        self.creation_time = creation_time
        super().__init__(
            family=self.family,
            private_key=self.private_key,
            public_key=self.public_key,
        )

    @classmethod
    def create(cls, family: str) -> Self:
        """Initialise a Key from a DID key spec from a DID document."""
        crypt = Crypt.new(family)

        return cls(
            family=crypt.family,
            public_key=crypt.public_key,
            private_key=crypt.private_key,
            creation_time=datetime.now(UTC),
        )

    @classmethod
    def from_crypt(cls, crypt: Crypt, creation_time: datetime) -> Self:
        """Create a Key object from a Crypt object."""
        return cls(
            family=crypt.family,
            public_key=crypt.public_key,
            private_key=crypt.private_key,
            creation_time=creation_time,
        )

    @classmethod
    def from_key_spec(cls, key_spec: dict) -> Self:
        """Initialise a Key from a DID key spec from a DID document."""
        key = cls(
            family=key_spec["type"],
            public_key=key_spec["publicKeyMultibase"],
            private_key=None,
            creation_time=string_to_time(key_spec["creation_time"]),
        )
        if key_spec["id"].strip("#") != key.get_id():
            raise ValueError(
                "The key-spec's key ID doesn't match our convention"
            )
        return key

    @classmethod
    def from_id(cls, key_id: str) -> Self:
        """Initialise a Key from a key ID generated by this class."""
        if "|" in key_id:
            raise ValueError(
                "It looks like this key_id might be from a KeyGroup"
            )
        data = key_id.split(":")
        public_key = data[-1]
        timestamp = data[-2]
        family = ":".join(data[0:-2])
        key = cls(
            family=family,
            public_key=public_key,
            private_key=None,
            creation_time=string_to_time(timestamp),
        )
        return key

    def generate_key_spec(self, controller: str) -> dict:
        """Generate a key spec for a DID document."""
        return {
            "id": f"#{self.get_id()}",
            "type": self.family,
            "publicKeyMultibase": self.public_key.hex(),
            "creation_time": time_to_string(self.creation_time),
            "controller": controller,
        }

    def serialise_private(
        self,
    ) -> dict:
        """Serialise this key's data, including the private key encrypted."""
        if (
            not self.private_key
            or not self.family
            or not self.public_key
            or not self.creation_time
        ):
            error_message = "Not all of this objects' fields are set!\n".join(
                [
                    f"family: {type(self.family)}",
                    f"public_key: {type(self.public_key)}",
                    f"private_key: {type(self.private_key)}",
                    f"creation_time: {type(self.creation_time)}",
                ]
            )
            raise ValueError(error_message)

        return {
            "family": self.family,
            "public_key": self.public_key.hex(),
            "private_key": self.private_key.hex(),
            "creation_time": time_to_string(self.creation_time),
        }

    def serialise_private_encrypted(
        self, crypt: Crypt, allow_missing_private_key: bool = False
    ) -> dict:
        """Serialise this key's data, including the private key encrypted."""
        if not allow_missing_private_key and not self.private_key:
            raise ValueError(
                "Private Key is not set!\n"
                "You can use the `allow_missing_private_key` parameter to "
                "ignore this."
            )

        if not (self.family and self.public_key and self.creation_time):
            error_message = "Not all of this objects' fields are set!\n".join(
                [
                    f"family: {type(self.family)}",
                    f"public_key: {type(self.public_key)}",
                    f"creation_time: {type(self.creation_time)}",
                ]
            )
            raise ValueError(error_message)

        private_key = (
            crypt.encrypt(self.private_key).hex() if self.private_key else None
        )
        return {
            "family": self.family,
            "public_key": self.public_key.hex(),
            "private_key": private_key,
            "creation_time": time_to_string(self.creation_time),
        }

    def clone_public(self) -> Self:  # noqa: D102
        return Key.from_id(self.get_id())

    def is_unlocked(self) -> bool:  # noqa: D102
        if self.private_key:
            return True
        return False

    @classmethod
    def deserialise_private(
        cls,
        data: dict,
    ) -> Self:
        """Deserialise data with private key."""
        if isinstance(data, str):
            data = json.loads(data)
        return cls(
            family=data["family"],
            public_key=bytes.fromhex(data["public_key"]),
            private_key=bytes.fromhex(data["private_key"]),
            creation_time=string_to_time(data["creation_time"]),
        )

    @classmethod
    def deserialise_private_encrypted(cls, data: dict, crypt: Crypt) -> Self:
        """Deserialise data with encrypted private key."""
        if isinstance(data, str):
            data = json.loads(data)
        private_key = (
            crypt.decrypt(bytes.fromhex(data["private_key"]))
            if data.get("private_key")
            else None
        )
        return cls(
            family=data["family"],
            public_key=data["public_key"],
            private_key=private_key,
            creation_time=string_to_time(data["creation_time"]),
        )

    def get_private_key(self) -> str:
        """Get the private key as a hex string."""
        if not self.private_key:
            raise ValueError("This key's private key hasn't been defined")
        return self.private_key.hex()

    def get_id(self) -> str:  # noqa: D102
        return generate_key_id(
            family=self.family,
            creation_time=self.creation_time,
            public_key=self.public_key,
        )

    def __str__(self):
        """Get this key's ID."""
        return self.get_id()


def generate_key_id(
    family: str,
    public_key: bytes | str,
    creation_time: datetime,
) -> str:
    """Generate a key ID from metadata."""
    if isinstance(public_key, bytes) or isinstance(public_key, bytearray):
        public_key = public_key.hex()
    if not (family and public_key and creation_time):
        raise ValueError("Not all key fields provided.")
    return f"{family}:{time_to_string(creation_time)}:{public_key}"


class KeyGroup(GenericKey):
    """A composite key, consisting of multiple keys."""

    def __init__(self, keys: list[Key]):
        self.keys = keys
        assert len(self.keys) > 0, "Error: This GroupKey has 0 keys."

    @classmethod
    def create(cls, key_families: list[str]) -> Self:
        """Create a new composite key with newly generated keys."""
        keys = [Key.create(family=family) for family in key_families]
        return cls(keys)

    @classmethod
    def from_id(cls, group_key_id: str) -> Self:  # noqa: D102
        key_ids = decode_keygroup_id(group_key_id)
        keys = [Key.from_id(key_id) for key_id in key_ids]
        return cls(keys)

    def get_id(self) -> str:  # noqa: D102
        assert len(self.keys) > 0, "Error: This GroupKey has 0 keys."
        # leading "|" to ensure that key-groups with 1 key are recognised as
        # KeyGroup objects
        return "|" + "|".join(self.get_ids())

    def get_keys(self) -> list[Key]:
        """Get the key objects comprising this KeyGroup."""
        assert len(self.keys) > 0, "Error: This GroupKey has 0 keys."
        return self.keys

    def get_ids(self) -> list[str]:
        """Get the IDs of the keys comprising this KeyGroup."""
        assert len(self.keys) > 0, "Error: This GroupKey has 0 keys."
        return [key.get_id() for key in self.get_keys()]

    def verify_signature(  # noqa: D102
        self,
        signature: bytes,
        data: bytes,
        signature_options: str | None = None,
    ) -> bool:
        assert len(self.keys) > 0, "Error: This GroupKey has 0 keys."
        signatures = [
            bytes.fromhex(sig) for sig in signature.decode().split("-")
        ]
        if not len(signatures) == len(self.keys):
            logger.warning("Wrong number of signatures")
            return False
        for i, key in enumerate(self.keys):
            if not key.verify_signature(
                signatures[i], data, signature_options
            ):
                return False

        return True

    def sign(self, data: bytes, signature_options: str | None = None) -> bytes:  # noqa: D102
        assert len(self.keys) > 0, "Error: This GroupKey has 0 keys."
        signatures = []
        for key in self.keys:
            signatures.append(key.sign(data, signature_options))
        return str.encode(
            "-".join([bytes.hex(signature) for signature in signatures])
        )

    def encrypt(  # noqa: D102
        self,
        data_to_encrypt: bytes,
        encryption_options: str | None = None,
    ) -> bytes:
        assert len(self.keys) > 0, "Error: This GroupKey has 0 keys."
        data = data_to_encrypt
        for key in self.keys:
            data = key.encrypt(data, encryption_options=encryption_options)
        return data

    def decrypt(  # noqa: D102
        self,
        encrypted_data: bytes,
        encryption_options: str | None = None,
    ) -> bytes:
        data = encrypted_data
        assert len(self.keys) > 0, "Error: This GroupKey has 0 keys."

        for key in self.keys[::-1]:  # iterate through keys backwards
            data = key.decrypt(data, encryption_options=encryption_options)
        return data

    def is_unlocked(self) -> bool:  # noqa: D102
        for key in self.keys:
            if not key.is_unlocked():
                return False
        return True

    def serialise_private_encrypted(
        self, crypt: Crypt, allow_missing_private_key: bool = False
    ) -> list[dict]:
        """Serialise this key encryptedly, including its private keys."""
        return [
            key.serialise_private_encrypted(
                crypt=crypt,
                allow_missing_private_key=allow_missing_private_key,
            )
            for key in self.keys
        ]

    @classmethod
    def deserialise_private_encrypted(
        cls, data: list[dict], crypt: Crypt
    ) -> Self:
        """Deserialise data with encrypted private keys."""
        return cls([Key.deserialise_private_encrypted(s, crypt) for s in data])

    def serialise_private(
        self,
    ) -> list[dict]:
        """Serialise this key, including its private keys."""
        return [key.serialise_private() for key in self.keys]

    @classmethod
    def deserialise_private(
        cls,
        data: list[dict],
    ) -> Self:
        """Deserialise data with private keys."""
        return cls(
            [
                Key.deserialise_private(
                    s,
                )
                for s in data
            ]
        )

    def clone_public(self) -> "KeyGroup":  # noqa: D102
        return KeyGroup.from_id(self.get_id())

    def generate_key_specs(self, controller: str) -> list[dict]:
        """Generate a key spec for a DID document."""
        return [key.generate_key_spec(controller) for key in self.keys]

    @classmethod
    def from_key_specs(cls, key_spec: list[dict]) -> Self:
        """Instantiate from a DID-Document key-spec."""
        return cls([Key.from_key_spec(key_spec) for key_spec in key_spec])


def decode_keygroup_id(group_key_id: str) -> list[str]:
    """Extract the individual key IDs from a KeyGroup ID."""
    # take account for leading "|"
    return [x for x in group_key_id.split("|") if x]


@dataclass
class CodePackage:
    """Package of encrypted data or a signature with crypto-key-metadata."""

    def __init__(
        self,
        key: GenericKey,
        code: bytes,
        operation_options: str | None = None,
    ):
        self.key = key
        self.code = bytes(code)
        self.operation_options = operation_options

    @classmethod
    def deserialise(cls, data: str) -> Self:
        """Instatiate a CodePackage object from a string."""
        _data = json.loads(data)
        return cls(
            code=string_to_bytes(_data["code"]),
            key=generic_key_from_id(_data["key_id"]),
            operation_options=_data["operation_options"],
        )

    @classmethod
    def deserialise_bytes(cls, data: bytes) -> Self:
        """Instatiate a CodePackage object from bytes."""
        _data = data.decode()
        return cls.deserialise(_data)

    def serialise(self) -> str:
        """Serialise this object to a string."""
        return json.dumps(
            {
                "code": bytes_to_string(self.code),
                "key_id": self.key.get_id(),
                "operation_options": self.operation_options,
            }
        )

    def serialise_bytes(self) -> bytes:
        """Serialise this object to bytes."""
        return self.serialise().encode()

    def verify_signature(self, data: bytes) -> bool:
        """Verify self.code as a signature against the given signed data."""
        signature = self.code
        return self.key.verify_signature(
            signature=signature,
            data=data,
            signature_options=self.operation_options,
        )

    def decrypt(
        self,
    ) -> bytes:
        """Assuming self.code is a cipher, decrypt it."""
        return self.key.decrypt(
            encrypted_data=self.code,
            encryption_options=self.operation_options,
        )

    def unlock_key(self, key: GenericKey) -> None:
        """Set the key with its private key."""
        if not self.key.get_id() == key.get_id():
            raise ValueError(
                "Replacement key object doesn't have the same key ID"
            )
        if not key.is_unlocked():
            raise ValueError("Replacement key is locked.")
        self.key = key

    @classmethod
    def encrypt(
        cls,
        data_to_encrypt: bytes,
        key: GenericKey,
        encryption_options: str | None = None,
    ) -> Self:
        """Encrypt the provided data using the specified key.

        Args:
            data_to_encrypt (bytes): the data to encrypt
            key (Key): the key to use to encrypt the data
            encryption_options (str): specification code for which
                            encryption/decryption protocol should be used
        Returns:
            CodePackage: an object containing the ciphertext, public-key,
                            crypto-family and encryption-options
        """
        cipher = key.encrypt(
            data_to_encrypt=data_to_encrypt,
            encryption_options=encryption_options,
        )
        return cls(
            code=cipher,
            key=key,
            operation_options=encryption_options,
        )

    @classmethod
    def sign(
        cls, data: bytes, key: Key, signature_options: str | None = None
    ) -> Self:
        """Sign the provided data using the specified key.

        Args:
            data (bytes): the data to encrypt
            key (Key): the key to use to encrypt the data
            signature_options (str): specification code for which
                            signing/verification protocol should be used
        Returns:
            CodePackage: an object containing the ciphertext, public-key,
                            crypto-family and encryption-options
        """
        cipher = key.sign(
            data=data,
            signature_options=signature_options,
        )
        return cls(
            code=cipher,
            key=key,
            operation_options=signature_options,
        )

    def get_key(self) -> GenericKey:
        """Get this code package's key."""
        return self.key

    def get_key_id(self) -> str:
        """Get this code package's key's ID."""
        return self.key.get_id()


def generic_key_from_id(key_id: str) -> Key | KeyGroup:
    """Get a Key or KeyGroup object given a key ID."""
    if "|" in key_id:
        return KeyGroup.from_id(key_id)
    else:
        return Key.from_id(key_id)


class KeyLockedError(Exception):
    """When an error is caused by a Key being locked."""
