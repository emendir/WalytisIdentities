import ipfs_api
from abc import ABC, abstractmethod
from .did_objects import Key, Service
from multi_crypt import Crypt
import walytis_beta_api as walytis_api
from walytis_beta_api import Blockchain, delete_blockchain
import rfc3987
import json
from dataclasses import dataclass
from typing import Union
from .utils import validate_did_doc
from .did_manager import DidManager
DID_METHOD_NAME = "wlaytis-contacts"
DID_URI_PROTOCOL_NAME = "waco"  # https://www.rfc-editor.org/rfc/rfc3986#section-3.1

CRYPTO_FAMILY = "EC-secp256k1"


@dataclass
class IdentityAccess(ABC):
    """A class for accessing and controlling an Identity's data and functions.
    """
    did_manager: DidManager

    keys: list
    services: list
    properties: dict
    # # members: list[IdentityAccess]
    # members: list

    def __init__(self, did_manager):
        self.did_manager = did_manager

    @classmethod
    def create(cls):
        did_manager = DidManager.create()
        return cls(did_manager)

    @abstractmethod
    def generate_did_doc(self):
        pass

    def get_did(self):
        return self.did_manager.get_did()

    def sign(self, data):
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

    def delete(self):
        self.did_manager.delete()

    def terminate(self):
        self.did_manager.terminate()

    def __del__(self):
        self.terminate()


class DeviceIdentityAccess(IdentityAccess):
    @property
    def ipfs_peer_id(self) -> str:
        return ipfs_api.my_id()

    @classmethod
    def create(cls):
        return super().create()

    def generate_did_doc(self):
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


class PersonIdentityAccess(IdentityAccess):
    members: list
    device_identity_access: DeviceIdentityAccess

    @classmethod
    def create(cls, device_identity_access, *args):
        # create PersonIdentityAccess object and
        # run it's IdentityAccess initialiser
        person_id_acc = super().create(*args)

        # set its device_identity_access
        person_id_acc.device_identity_access = device_identity_access
        return person_id_acc

    def generate_did_doc(self):
        did_doc = {
            "id": self.get_did(),
            "verificationMethod": [
                key.generate_key_spec(self.get_did()) for key in self.keys
            ],
            "service": [
                service.generate_service_spec() for service in self.services
            ],
            "members": self.members
        }

        # check that components produce valid URIs
        validate_did_doc(did_doc)
        return did_doc

    def delete(self):
        self.device_identity_access.delete()
        super().delete()

    def terminate(self):
        self.device_identity_access.terminate()
        super().terminate()


def blockchain_id_from_did(did: str):
    if not (did.startswith("did:") and did.count(":") == 2):
        raise ValueError("Wrong DID format!")
    return did[:4].index()
