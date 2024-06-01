"""Machinery for managing DID-Documents, i.e. identities' cryptography keys."""

from dataclasses import dataclass
from typing import Type, TypeVar

from multi_crypt import Crypt
from walytis_beta_api import Blockchain, delete_blockchain

from .did_manager_blocks import (
    ControlKeyBlock,
    DidDocBlock,
    MembersListBlock,
    get_latest_control_key,
    get_latest_did_doc,
    get_latest_members_list,
)
from .did_objects import Key
from .exceptions import NotValidDidBlockchainError
from .key_store import KeyStore
from .utils import bytes_to_string

DID_METHOD_NAME = "wlaytis-contacts"
DID_URI_PROTOCOL_NAME = "waco"  # https://www.rfc-editor.org/rfc/rfc3986#section-3.1

CRYPTO_FAMILY = "EC-secp256k1"

_DidManager = TypeVar('_DidManager', bound='DidManager')


@dataclass
class DidManager:
    """Manage DID documents using a Walytis blockchain.

    Publishes DID documents on a blockchain, secured by an updatable
    control key system.
    DOESN'T create ID documents.
    """

    blockchain: Blockchain
    key_store: KeyStore

    _control_key: Key
    did_doc: dict
    members_list: list | None

    def __init__(
        self,
        blockchain: Blockchain | str,
        key_store: KeyStore
    ):
        """Load a DidManager from a Walytis blockchain."""
        if isinstance(blockchain, str):
            blockchain = Blockchain(blockchain)

        self.blockchain = blockchain
        self.key_store = key_store

        self._control_key = get_latest_control_key(blockchain)
        self.did_doc = get_latest_did_doc(blockchain)
        if not self.did_doc:
            raise NotValidDidBlockchainError()
        self.members_list = get_latest_members_list(blockchain)
        self._crypt = self.key_store.get_key(self.get_control_key().key_id)

    @classmethod
    def create(cls: Type[_DidManager], key_store: KeyStore) -> _DidManager:
        """Create a new DID-Manager."""
        # create crypto keys
        crypt = Crypt.new(CRYPTO_FAMILY)
        key_store.add_key(bytes_to_string(crypt.public_key), crypt)
        # create blockchain
        blockchain = Blockchain.create(
            blockchain_name=f"waco-{crypt.public_key}"
        )

        # publish first key on blockchain
        keyblock = ControlKeyBlock.new(
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
        did = did_from_blockchain_id(blockchain.blockchain_id)

        did_doc = {"id": did}
        did_doc_block = DidDocBlock.new(did_doc)
        did_doc_block.sign(crypt)
        blockchain.add_block(
            did_doc_block.generate_block_content(),
            topics=DidDocBlock.walytis_block_topic
        )

        did_manager = cls(blockchain, key_store=key_store)
        blockchain.terminate()
        return did_manager

    def get_did(self) -> str:
        """Get this DID-Manager's DID."""
        return did_from_blockchain_id(self.blockchain.blockchain_id)

    def renew_control_key(self) -> None:
        """Change the control key to an automatically generated new one."""
        # create new crypto keys

        old_crypt = self.get_crypt()
        new_crypt = Crypt.new(CRYPTO_FAMILY)
        self.key_store.add_key(bytes_to_string(new_crypt.public_key), new_crypt)

        # create ControlKeyBlock (becomes the Walytis-Block's content)
        keyblock = ControlKeyBlock.new(
            old_key_type=old_crypt.family,
            old_key=old_crypt.public_key,
            new_key_type=new_crypt.family,
            new_key=new_crypt.public_key
        )
        keyblock.sign(old_crypt)

        self.blockchain.add_block(
            keyblock.generate_block_content(),
            topics="control_key"
        )

        self._control_key = keyblock.get_new_key()

    def get_control_key(self) -> Key:
        """Get the current control key."""
        if not self._control_key:
            self._control_key = get_latest_control_key(self.blockchain)
        return self._control_key

    def get_crypt(self) -> Crypt:
        """Get the Crypt object for the current control key."""
        return self.key_store.get_key(self.get_control_key().key_id)

    def update_did_doc(self, did_doc: dict) -> None:
        """Publish a new DID-document to replace the current one."""
        did_doc_block = DidDocBlock.new(did_doc)
        did_doc_block.sign(self.get_crypt())
        self.blockchain.add_block(
            did_doc_block.generate_block_content(),
            topics=DidDocBlock.walytis_block_topic
        )

        self.did_doc = did_doc

    def get_did_doc(self) -> dict:
        """Get the current DID-document."""
        if not self.did_doc:
            self.did_doc = get_latest_did_doc(self.blockchain)
        return self.did_doc

    def update_members_list(self, members_list: list) -> None:
        """Publish a new list of members to replace the current one."""
        members_block = MembersListBlock.new(members_list)
        members_block.sign(self.get_crypt())
        self.blockchain.add_block(
            members_block.generate_block_content(),
            topics=MembersListBlock.walytis_block_topic
        )

        self.members_list = members_list

    def get_members(self) -> list | None:
        """Get the current list of member-devices."""
        if not self.members_list:
            self.members_list = get_latest_members_list(self.blockchain)
        return self.members_list

    def delete(self) -> None:
        """Delete this DID-Manager."""
        self.blockchain.terminate()
        delete_blockchain(self.blockchain.blockchain_id)

    def terminate(self) -> None:
        """Stop this DID-Manager, cleaning up resources."""
        self.blockchain.terminate()

    def __del__(self):
        """Stop this DID-Manager, cleaning up resources."""
        self.terminate()


def blockchain_id_from_did(did: str) -> str:
    """Given a DID, get its Walytis blockchain's ID."""
    did_parts = did.split(":")
    if not (
        len(did_parts) == 3
        and did_parts[0] == "did"
        and did_parts[1] == DID_METHOD_NAME
    ):
        raise ValueError("Wrong DID format!")
    return did_parts[2]


def did_from_blockchain_id(blockchain_id: str) -> str:
    """Convert a Walytis blockchain ID to a DID."""
    return f"did:{DID_METHOD_NAME}:{blockchain_id}"
