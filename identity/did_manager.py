from .did_objects import Key, Service
from multi_crypt import Crypt
import walytis_beta_api as walytis_api
from walytis_beta_api import Blockchain, delete_blockchain
import rfc3987
import json
from dataclasses import dataclass
from typing import Union
from .utils import validate_did_doc,  bytes_to_string, bytes_from_string
from .member_blocks import (
    NewMemberBlock, MemberUpdateBlock, KeyBlock, DidDocBlock,
    get_latest_control_key, get_latest_did_doc
)

DID_METHOD_NAME = "wlaytis-contacts"
DID_URI_PROTOCOL_NAME = "waco"  # https://www.rfc-editor.org/rfc/rfc3986#section-3.1

CRYPTO_FAMILY = "EC-secp256k1"


@dataclass
class DidManager:
    """
    Uses a Walytis Blockchain to publish DID documents, secured by an updatable
    control key system.
    """
    blockchain: Blockchain
    crypt: Crypt

    control_key: Key
    did_doc: dict

    @staticmethod
    def load_from_blockchain(blockchain: Blockchain, crypt: Crypt = None):
        if not isinstance(blockchain, Blockchain):
            blockchain = Blockchain(blockchain)

        control_key = get_latest_control_key(blockchain)
        did_doc = get_latest_did_doc(blockchain)

        return DidManager(
            blockchain=blockchain,
            crypt=crypt,
            control_key=control_key,
            did_doc=did_doc,
        )

    @staticmethod
    def create():
        # create crypto keys
        crypt = Crypt.new(CRYPTO_FAMILY)

        # create blockchain
        blockchain = Blockchain.create(blockchain_name=f"waco-{crypt.public_key}")

        # publish first key on blockchain
        keyblock = KeyBlock.new(
            old_key_type=crypt.family,
            old_key=crypt.public_key,
            new_key_type=crypt.family,
            new_key=crypt.public_key
        )
        keyblock.sign(crypt)
        blockchain.add_block(
            keyblock.generate_block_content(),
            topics="control_key"
        )

        did_manager = DidManager.load_from_blockchain(blockchain, crypt=crypt)
        did_manager.crypt = crypt
        blockchain.terminate()
        return did_manager

    # @ staticmethod
    # def load_from_did_doc(did_doc: dict, crypt: Crypt):
    #
    #     blockchain_id = did_doc['id'].split(":")[-1]
    #     return cls.load_from_blockchain(blockchain_id, crypt)
    #     # keys = [
    #     #     Key.from_key_spec(key_spec)
    #     #     for key_spec in did_doc['verificationMethod']
    #     # ]
    #     # services = [
    #     #     Service.from_service_spec(service_spec)
    #     #     for service_spec in did_doc['service']
    #     # ]
    #     #
    #     # return DidManager(
    #     #     blockchain=Blockchain(blockchain_id),
    #     #     keys=keys,
    #     #     services=services
    #     # )

    def update_did_doc(self, did_doc: dict):
        did_doc_block = DidDocBlock.new(did_doc)
        did_doc_block.sign(self.crypt)
        self.blockchain.add_block(
            did_doc_block.generate_block_content(),
            topics="did_doc"
        )

        self.did_doc = did_doc

    def get_did_doc(self):
        if not self.did_doc:
            self.did_doc = get_latest_did_doc(self.blockchain)
        return self.did_doc

    def get_did(self):
        return f"did:{DID_METHOD_NAME}:{self.blockchain.id}"

    def update_control_key(self):

        # create new crypto keys
        new_crypt = Crypt.new(CRYPTO_FAMILY)

        # create KeyBlock (becomes the Walytis-Block's content)
        keyblock = KeyBlock.new(
            old_key_type=self.crypt.family,
            old_key=self.crypt.public_key,
            new_key_type=new_crypt.family,
            new_key=new_crypt.public_key
        )
        keyblock.sign(self.crypt)

        self.blockchain.add_block(
            keyblock.generate_block_content(),
            topics="control_key"
        )

        self.crypt = new_crypt
        self.control_key = keyblock.get_new_key()

    def get_control_key(self):
        if not self.control_key:
            self.control_key = get_latest_control_key(self.blockchain)
        return self.control_key

    def update_members(self):
        pass

    def get_members(self):
        pass

    def delete(self):
        self.blockchain.terminate()
        delete_blockchain(self.blockchain.id)

    def terminate(self):
        self.blockchain.terminate()

    def __del__(self):
        self.terminate()


def blockchain_id_from_did(did: str):
    if not (did.startswith("did:") and did.count(":") == 2):
        raise ValueError("Wrong DID format!")
    return did[:4].index()
