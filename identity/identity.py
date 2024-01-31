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
class Identity:
    did_manager: DidManager

    keys: list
    services: list
    properties: dict
    # members: list[Identity]
    members: list

    def __init__(self, did_manager):
        self.did_manager = did_manager

    @staticmethod
    def create():
        did_manager = DidManager.create()
        return Identity(did_manager)

    def generate_did_doc(self):
        did_doc = {
            "id": self.get_did(),
            "verificationMethod": [
                key.generate_key_spec(self.get_did()) for key in self.keys
            ],
            "service": [
                service.generate_service_spec() for service in self.services
            ]
        }

        # check that components produce valid URIs
        validate_did_doc(did_doc)
        return did_doc

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


def blockchain_id_from_did(did: str):
    if not (did.startswith("did:") and did.count(":") == 2):
        raise ValueError("Wrong DID format!")
    return did[:4].index()
