"""Classes for managing Person and Device identities."""

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Type, TypeVar

import ipfs_api
from brenthy_tools_beta.utils import bytes_to_string
from decorate_all import decorate_all_functions
from ipfs_datatransmission import Conversation, TransmissionListener
from loguru import logger
from strict_typing import strictly_typed
from walytis_beta_api import Blockchain, decode_short_id

from .did_manager import DidManager, blockchain_id_from_did
from .did_manager_blocks import (
    KeyOwnershipBlock,
    get_latest_control_key,
    get_latest_did_doc,
)
from .did_objects import Key
from .key_store import KeyStore
from .settings import CTRL_KEY_MAX_RENEWAL_DUR_HR, CTRL_KEY_RENEWAL_AGE_HR
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
        key: Key
    ):
        self.config_dir = config_dir
        self.key = key
        self.did_manager = did_manager
        self.config_file = os.path.join(config_dir, "device_id.json")
        self.did_keystore_file = os.path.join(config_dir, "device_id_keys.json")

    @classmethod
    def create(
        cls: Type[_DeviceIdentityAccess],
        config_dir: str,
        key: Key,
    ) -> _DeviceIdentityAccess:
        """Create a new PersonIdentityAccess object."""
        # create PersonIdentityAccess object and
        # run it's IdentityAccess initialiser
        did_keystore_file = os.path.join(config_dir, "device_id_keys.json")
        key_store = KeyStore(did_keystore_file, key)
        did_manager = DidManager.create(key_store)

        person_id_acc = cls(
            did_manager,
            config_dir,
            key,
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
    ):
        self.device_identity_access = device_identity_access
        self.config_dir = config_dir
        self.key = key
        self.did_manager = did_manager
        self.config_file = os.path.join(config_dir, "person_id.json")
        self.did_keystore_file = os.path.join(config_dir, "person_id_keys.json")
        self.candidate_keys: dict[str, list[str]] = {}
        self.get_published_candidate_keys()

        self.key_requests_listener = TransmissionListener(
            f"{self.get_did()}-KeyRequests",
            self.key_requests_handler
        )

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

        device_identity_access = DeviceIdentityAccess.load_from_appdata(
            config_dir, key
        )
        return cls(
            did_manager,
            device_identity_access,
            config_dir,
            key,
        )

    def serialise(self) -> dict:
        """Generate this Identity's appdata."""
        return {
            "did_blockchain": self.did_manager.blockchain.blockchain_id,
        }

    def save_appdata(self) -> None:
        """Write this identy's appdata to a file."""
        data = json.dumps(self.serialise())
        with open(self.config_file, "w+") as file:
            file.write(data)

    def get_members(self) -> list:
        """Get the current list of member-devices."""
        members = self.did_manager.get_members()
        if not members:
            return []
        return members

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

        Returns:
            Whether or not we are now prepared to renew control keys
        """
        ctrl_key_timestamp = self.did_manager.get_control_key().creation_time
        ctrl_key_age_hr = (
            datetime.utcnow() - ctrl_key_timestamp
        ).total_seconds() / 60 / 60

        # if control key isn't too old yet
        if ctrl_key_age_hr < CTRL_KEY_RENEWAL_AGE_HR:
            self.candidate_keys = {}
            self.save_appdata()
            return False

        # refresh our list of published candidate_keys
        self.get_published_candidate_keys()

        # if we already have a control key candidate
        if self.candidate_keys:
            # try get the private keys of any candidate keys we don't yet own
            for key_id, members in list(self.candidate_keys.items()):
                if key_id not in self.did_manager.key_store.keys.keys():
                    for member in members:
                        if self.request_key(key_id, member):
                            break
            return True

        key = Key.create(CRYPTO_FAMILY)
        self.did_manager.key_store.add_key(key)
        self.candidate_keys.update(
            {key.get_key_id(): [self.device_identity_access.get_did()]}
        )
        self.save_appdata()

        self.publish_key_ownership(key)
        return True

    def publish_key_ownership(self, key: Key) -> None:
        """Publish a public key and proof that we have it's private key."""
        key_ownership = {
            "owner": self.device_identity_access.get_did(),
            "key": key.key_id()
        }
        sig = bytes_to_string(key.sign(json.dumps(key_ownership).encode()))
        key_ownership.update({"proof": sig})
        block = KeyOwnershipBlock.new(key_ownership)
        self.did_manager.add_info_block(block)

    def key_requests_handler(self, conv_name: str, peer_id: str) -> None:
        """Respond to key requests from other members."""
        conv = Conversation.join(
            conv_name,
            peer_id,
            conv_name
        )
        try:
            message = conv.listen()
            peer_did = message["did"]
            key_id = message["key_id"]
            sig = message["signature"]

            message.pop("signature")
            peer_key = self.get_member_control_key(peer_did)
            if not peer_key.verify_signature(sig, message):
                conv.say(json.dumps({
                    "error": "authenitcation failed",
                    "peer_public_key": peer_key.get_public_key()
                }).encode())
                conv.terminate()
                return
            try:
                key = self.did_manager.key_store.get_key(key_id)
            except IndexError:
                conv.say(json.dumps({
                    "error": "I don't own this key.",
                    "peer_public_key": peer_key.get_public_key()
                }).encode())
                conv.terminate()
                return

            conv.say(json.dumps({
                "private_key": peer_key.encrypt(key.private_key).hex()
            }))
        except Exception:
            conv.terminate()

    def get_member_ipfs_id(self, did: str) -> str:
        """Get the IPFS content ID of another member."""
        if did not in self.get_members():
            raise Exception("This DID is not among our members.")

        blockchain = Blockchain(blockchain_id_from_did(did))

        did_doc = get_latest_did_doc(blockchain)
        return did_doc["ipfs_peer_id"]

    def get_member_control_key(self, did: str) -> Key:
        """Get the DID control key of another member."""
        if did not in self.get_members():
            raise Exception("This DID is not among our members.")

        blockchain = Blockchain(blockchain_id_from_did(did))

        return get_latest_control_key(blockchain)

    def request_key(self, key_id: str, did: str) -> Key | None:
        """Request a key from another member."""
        peer_id = self.get_member_ipfs_id(did)

        try:
            conv = Conversation.start(
                conv_name=f"KeyRequest-{key_id}",
                peer_id=peer_id
            )
            key = self.device_identity_access.did_manager.get_control_key()
            message = {
                "did": self.device_identity_access.get_did(),
                "key_id": key_id,
            }
            message.update({"signature": key.sign(json.dumps(message).encode())})
            response = json.loads(conv.say(json.dumps(message).encode()).decode())

        except Exception:
            conv.close()
            return None

        if "error" in response.keys():
            logger.warning(response)
            return None
        private_key = bytes.fromhex(key.decrypt(response["private_key"]))
        key = Key.from_key_id(key_id)
        key.unlock(private_key)
        self.did_manager.key_store.add_key(key)
        self.publish_key_ownership(key)
        self.candidate_keys[key_id] += self.device_identity_access.get_did()
        conv.close()
        return key

    def get_published_candidate_keys(self) -> dict["str", list[str]]:
        """Update our list of candidate control keys and their owners."""
        candidate_keys: dict[str, list[str]] = {}
        for block_id in self.did_manager.blockchain.block_ids[::-1]:
            metadata = decode_short_id(block_id)
            if KeyOwnershipBlock.walytis_block_topic not in metadata["topics"]:
                continue
            key_expiry = (
                self.did_manager.get_control_key().creation_time +
                timedelta(hours=CTRL_KEY_RENEWAL_AGE_HR)
            )
            if metadata["creation_time"] < key_expiry:
                key_ownership = KeyOwnershipBlock.load_from_block_content(
                    self.did_manager.blockchain.get_block(block_id)
                ).get_key_ownership()

                key_id = key_ownership["key_id"]
                owner = key_ownership["owner"]

                key = Key.from_id()
                proof = key_ownership["proof"]
                key_ownership.pop("proof")

                if not key.verify_signature(proof, key_ownership):
                    logger.warning(
                        "Found key ownership block with invalid proof."
                    )
                    continue

                if key_id in candidate_keys.keys():
                    candidate_keys[key_id] += owner
                else:
                    candidate_keys.update({owner: owner})
        self.candidate_keys = candidate_keys
        return candidate_keys

    def check_apply_control_key_update(self) -> bool:
        """Check if we should renew our DID-manager's control key."""
        if not self.candidate_keys:
            return False

        ctrl_key_timestamp = self.did_manager.get_control_key().creation_time
        ctrl_key_age_hr = (
            datetime.utcnow() - ctrl_key_timestamp
        ).total_seconds() / 60 / 60

        new_control_key = ""
        num_key_owners = 1
        # if control key isn't too old yet
        if (ctrl_key_age_hr
                < CTRL_KEY_RENEWAL_AGE_HR + CTRL_KEY_MAX_RENEWAL_DUR_HR):
            for key_id, owners in list(self.candidate_keys.items()):
                nko = len(self.candidate_keys[key_id])
                if nko > num_key_owners:
                    num_key_owners = nko
                    new_control_key = key_id

                    if num_key_owners >= len(self.get_members()):
                        break
            # if not all devices have the same candidate key yet,
            # we'll wait a little longer
            if num_key_owners < len(self.get_members()):
                return False

        self.did_manager.renew_control_key(new_control_key)
        self.candidate_keys = {}
        self.save_appdata()
        return True


decorate_all_functions(strictly_typed, __name__)
