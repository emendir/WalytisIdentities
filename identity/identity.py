"""Classes for managing Person and Device identities."""

from strict_typing import strictly_typed
from decorate_all import decorate_all_functions
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Type, TypeVar

import ipfs_api
from brenthy_tools_beta.utils import bytes_to_string

from .did_objects import Key
from .did_manager import DidManager
from .key_store import KeyStore
from .utils import validate_did_doc

DID_METHOD_NAME = "wlaytis-contacts"
DID_URI_PROTOCOL_NAME = "waco"  # https://www.rfc-editor.org/rfc/rfc3986#section-3.1

CRYPTO_FAMILY = "EC-secp256k1"

_IdentityAccess = TypeVar('_IdentityAccess', bound='IdentityAccess')


@dataclass
class IdentityAccess(ABC):
    """Base class for managing Person & Device identities."""

    did_manager: DidManager

    keys: list
    services: list
    properties: dict

    @abstractmethod
    def generate_did_doc(self) -> dict:
        """Generate a DID-document."""
        pass

    def get_did(self) -> str:
        """Get our DID."""
        return self.did_manager.get_did()

    def get_blockchain_id(self) -> str:
        return self.did_manager.blockchain.blockchain_id

    def sign(self, data: bytes | bytearray):
        # get current DID-Doc
        # extract signing public key from DID-Doc
        # get private key for public key
        # sign data
        # return signature and public_key
        pass

    def verify_signature(self, data, signature, public_key):
        # ensure public_key belongs to this identity
        # verify signature
        pass

    def encrypt(self, data):
        # return cipher and public_key
        pass

    def decrypt(self, data, public_key):
        # return plaintext
        pass

    def delete(self) -> None:
        """Delete this Identity."""
        self.did_manager.delete()

    def terminate(self) -> None:
        """Stop this Identity object, cleaning up resources."""
        self.did_manager.terminate()

    def __del__(self) -> None:
        """Stop this Identity object, cleaning up resources."""
        self.terminate()


_DeviceIdentityAccess = TypeVar(
    '_DeviceIdentityAccess', bound='DeviceIdentityAccess')


class DeviceIdentityAccess(IdentityAccess):
    """Class for managing a device' identity."""

    def __init__(
        self,
        did_manager: DidManager,
        config_dir: str,
        key: Key,
        config_file: str,
        did_keystore_file: str,
    ):
        self.config_dir = config_dir
        self.key = key
        self.config_file = config_file
        self.did_keystore_file = did_keystore_file
        self.did_manager = did_manager

    @classmethod
    def create(
        cls: Type[_DeviceIdentityAccess],
        config_dir: str,
        key: Key,
    ) -> _DeviceIdentityAccess:
        """Create a new PersonIdentityAccess object."""
        # create PersonIdentityAccess object and
        # run it's IdentityAccess initialiser
        config_file = os.path.join(config_dir, "device_id.json")
        did_keystore_file = os.path.join(config_dir, "device_id_keys.json")
        key_store = KeyStore(did_keystore_file, key)
        did_manager = DidManager.create(key_store)

        person_id_acc = cls(
            did_manager,
            config_dir,
            key,
            config_file,
            did_keystore_file,
        )
        person_id_acc.save_appdata()
        return person_id_acc

    @classmethod
    def load_from_appdata(
        cls: Type[_DeviceIdentityAccess],
        config_dir: str,
        key: Key,
    ) -> _DeviceIdentityAccess:

        config_file = os.path.join(config_dir, "device_id.json")
        did_keystore_file = os.path.join(config_dir, "device_id_keys.json")

        with open(config_file, "r") as file:
            data = json.loads(file.read())

        did_manager = DidManager(
            blockchain=data["did_blockchain"],
            key_store=KeyStore(did_keystore_file, key),
        )
        return cls(
            did_manager,
            config_dir,
            key,
            config_file,
            did_keystore_file,
        )

    def serialise(self) -> dict:
        return {
            "did_blockchain": self.did_manager.blockchain.blockchain_id,
        }

    def save_appdata(self):
        data = json.dumps(self.serialise())
        with open(self.config_file, "w+") as file:
            file.write(data)

    @property
    def ipfs_peer_id(self) -> str:
        return ipfs_api.my_id()

    def get_members(self) -> list[str]:
        return self.did_manager.get_members()

    def generate_did_doc(self) -> dict:
        """Generate a DID-document."""
        did_doc = {
            "id": self.get_did(),
            "verificationMethod": [
                key.generate_key_spec(self.get_did()) for key in self.keys
            ],
            "service": [
                service.generate_service_spec() for service in self.services
            ],
            "ipfs_peer_id": self.ipfs_peer_id
        }

        # check that components produce valid URIs
        validate_did_doc(did_doc)
        return did_doc


_PersonIdentityAccess = TypeVar(
    '_PersonIdentityAccess', bound='PersonIdentityAccess'
)


class PersonIdentityAccess(IdentityAccess):
    """Class for managing a person's identity."""

    device_identity_access: DeviceIdentityAccess

    def __init__(
        self,
        did_manager: DidManager,
        device_identity_access: DeviceIdentityAccess,
        config_dir: str,
        key: Key,
        config_file: str,
        did_keystore_file: str,
        candidate_keys: list,
    ):
        self.device_identity_access = device_identity_access
        self.config_dir = config_dir
        self.key = key
        self.config_file = config_file
        self.did_keystore_file = did_keystore_file
        self.did_manager = did_manager
        self.candidate_keys = candidate_keys

    @classmethod
    def create(
        cls: Type[_PersonIdentityAccess],
        config_dir: str,
        key: Key,
    ) -> _PersonIdentityAccess:
        """Create a new PersonIdentityAccess object."""
        # create DeviceIdentityAccess object
        device_identity_access = DeviceIdentityAccess.create(
            config_dir,
            key
        )
        # create PersonIdentityAccess object and
        # run it's IdentityAccess initialiser
        config_file = os.path.join(config_dir, "person_id.json")
        did_keystore_file = os.path.join(config_dir, "person_id_keys.json")
        key_store = KeyStore(did_keystore_file, key)
        did_manager = DidManager.create(key_store)

        did_manager.update_members_list([
            {"did": device_identity_access.get_did()}
        ])
        person_id_acc = cls(
            did_manager,
            device_identity_access,
            config_dir,
            key,
            config_file,
            did_keystore_file,
            [],
        )
        person_id_acc.save_appdata()
        return person_id_acc

    @classmethod
    def load_from_appdata(
        cls: Type[_PersonIdentityAccess],
        config_dir: str,
        key: Key,
    ) -> _PersonIdentityAccess:
        """Load a saved PersonIdentityAccess object from appdata."""
        config_file = os.path.join(config_dir, "person_id.json")
        did_keystore_file = os.path.join(config_dir, "person_id_keys.json")

        with open(config_file, "r") as file:
            data = json.loads(file.read())

        did_manager = DidManager(
            blockchain=data["did_blockchain"],
            key_store=KeyStore(did_keystore_file, key),
        )
        candidate_keys = data["candidate_keys"]

        device_identity_access = DeviceIdentityAccess.load_from_appdata(
            config_dir, key
        )
        return cls(
            did_manager,
            device_identity_access,
            config_dir,
            key,
            config_file,
            did_keystore_file,
            candidate_keys,
        )

    def serialise(self) -> dict:
        return {
            "did_blockchain": self.did_manager.blockchain.blockchain_id,
            "candidate_keys": self.candidate_keys
        }

    def save_appdata(self):
        data = json.dumps(self.serialise())
        with open(self.config_file, "w+") as file:
            file.write(data)

    def get_members(self) -> list | None:
        """Get the current list of member-devices."""
        return self.did_manager.get_members()

    def generate_did_doc(self) -> dict:
        """Generate a DID-document."""
        did_doc = {
            "id": self.get_did(),
            "verificationMethod": [
                key.generate_key_spec(self.get_did()) for key in self.keys
            ],
            "service": [
                service.generate_service_spec() for service in self.services
            ],
            "members": self.get_members()
        }

        # check that components produce valid URIs
        validate_did_doc(did_doc)
        return did_doc

    def delete(self) -> None:
        """Delete this Identity."""
        self.device_identity_access.delete()
        super().delete()

    def terminate(self) -> None:
        """Stop this Identity object, cleaning up resources."""
        self.device_identity_access.terminate()
        super().terminate()

    def __del__(self):
        """Stop this Identity object, cleaning up resources."""
        self.terminate()

    def check_prepare_control_key_update(self) -> bool:
        """Check if we should prepare to renew our DID-manager's control key.

        Generates new control key and shares it with other devices,
        doesn't update the DID-Manager though
        """
        # TODO: check if we should generate and share a new control key
        # for our DID manager
        renew_control_key = True
        if not renew_control_key:
            return False

        key = Key.create(CRYPTO_FAMILY)
        self.did_manager.key_store.add_key(key)
        self.candidate_keys.append(key.get_key_id())

        # TODO: share candidate key with others
        return True

    def check_apply_control_key_update(self) -> bool:
        """Check if we should renew our DID-manager's control key."""
        # TODO check if enough of our brothers have the candidate new key
        # or urgency is high
        # TODO: choose control key from candidates
        if not self.candidate_keys:
            return False
        new_control_key = self.candidate_keys[0]
        renew_control_key = True
        if not renew_control_key:
            return False

        self.did_manager.renew_control_key(new_control_key)
        return True


decorate_all_functions(strictly_typed, __name__)
