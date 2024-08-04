"""Machinery for managing DID-Documents, i.e. identities' cryptography keys.

Also includes machinery for managing other members
"""

from dataclasses import dataclass
from typing import Type, TypeVar

from decorate_all import decorate_all_functions
import json
from multi_crypt import Crypt
from strict_typing import strictly_typed
from walytis_beta_api import Blockchain, Block, delete_blockchain
from loguru import logger
from . import did_manager_blocks
from .did_manager_blocks import (
    ControlKeyBlock,
    DidDocBlock,
    InfoBlock,
    MemberJoiningBlock,
    MemberUpdateBlock,
    MemberLeavingBlock,
    MemberInvitationBlock,
    get_latest_control_key,
    get_latest_did_doc,
    get_members,
    get_block_type,
    get_info_blocks,
)
from .did_objects import Key
from .exceptions import NotValidDidBlockchainError
from .key_store import KeyStore, CodePackage, UnknownKeyError
from brenthy_tools_beta.utils import bytes_to_string
from typing import Callable

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
        key_store: KeyStore,
        non_did_blocks_handler: Callable[[Block], None] | None = None,
    ):
        """Load a DidManager from a Walytis blockchain.

        Args:
            blockchain: the blockchain on which this DID-Manager's data is
            key_store: the KeyStore object in which to store this DID's keys
            non_did_blocks_handler: eventhandler for blocks published on
                `blockchain` that aren't related to this DID-Manager work
        """
        if isinstance(blockchain, str):
            blockchain = Blockchain(blockchain)
        self.blockchain = blockchain
        self.non_did_blocks_handler = non_did_blocks_handler
        self.blockchain.block_received_handler = self.on_block_received
        self.blockchain.update_blockids_before_handling = True
        self.key_store = key_store
        # logger.debug("DM: Getting control key...")
        self._control_key = get_latest_control_key(blockchain)
        # logger.debug("DM: Getting DID-Doc...")
        self.did_doc = get_latest_did_doc(blockchain)
        if not self.did_doc:
            raise NotValidDidBlockchainError()
        # logger.debug("DM: Getting members...")
        self.members_list = list(get_members(blockchain).values())
        # logger.debug("DM: Built DID-Manager object!")

    @classmethod
    def create(cls: Type[_DidManager], key_store: KeyStore) -> _DidManager:
        """Create a new DID-Manager."""
        # logger.debug("DM: Creating DID-Manager...")
        # create crypto keys
        ctrl_key = Key.create(CRYPTO_FAMILY)
        key_store.add_key(ctrl_key)
        # logger.debug("DM: Createing DID-Manager's blockchain...")
        # create blockchain
        # logger.debug("DM: Creating Blockchain...")

        blockchain = Blockchain.create(
            blockchain_name=f"waco-{bytes_to_string(ctrl_key.public_key)}"
        )
        # logger.debug("DM: Initialising cryptography...")

        # publish first key on blockchain
        # logger.debug("DM: Adding ControlKey block...")
        keyblock = ControlKeyBlock.new(
            old_key=ctrl_key,
            new_key=ctrl_key,
        )
        keyblock.sign(ctrl_key)
        blockchain.add_block(
            keyblock.generate_block_content(),
            topics=keyblock.walytis_block_topic
        )

        # logger.debug("DM: Adding DID-Doc block...")
        did = did_from_blockchain_id(blockchain.blockchain_id)
        did_doc = {"id": did}
        did_doc_block = DidDocBlock.new(did_doc)
        did_doc_block.sign(ctrl_key)
        blockchain.add_block(
            did_doc_block.generate_block_content(),
            did_doc_block.walytis_block_topic
        )
        # logger.debug("DM: Instantiating...")

        did_manager = cls(blockchain, key_store=key_store)
        blockchain.terminate()

        # logger.debug("DM: created DID-Manager!")
        return did_manager

    @property
    def did(self) -> str:
        """Get this DID-Manager's DID."""
        return did_from_blockchain_id(self.blockchain.blockchain_id)

    def renew_control_key(self, new_ctrl_key: Crypt | None = None) -> None:
        """Change the control key to an automatically generated new one."""
        if not self.get_control_key().private_key:
            raise DidNotOwnedError()
        # create new control key if the user hasn't provided one
        if not new_ctrl_key:
            new_ctrl_key = Key.create(CRYPTO_FAMILY)

        old_ctrl_key = self.get_control_key()
        self.key_store.add_key(new_ctrl_key)

        # create ControlKeyBlock (becomes the Walytis-Block's content)
        keyblock = ControlKeyBlock.new(
            old_key=old_ctrl_key,
            new_key=new_ctrl_key,
        )
        keyblock.sign(old_ctrl_key)

        self.blockchain.add_block(
            keyblock.generate_block_content(),
            topics=keyblock.walytis_block_topic
        )

        self._control_key = keyblock.get_new_key()

    def add_info_block(self, block: InfoBlock) -> None:
        """Add an InfoBlock type block to this DID-Block's blockchain."""
        if not block.signature:
            block.sign(self.get_control_key())
        self.blockchain.add_block(
            block.generate_block_content(), block.walytis_block_topic
        )

    def get_control_key(self) -> Key:
        """Get the current control key."""
        if not self._control_key:
            self._control_key = get_latest_control_key(self.blockchain)
        if not self._control_key.private_key:
            try:
                self._control_key = self.key_store.get_key(
                    self._control_key.get_key_id()
                )
            except UnknownKeyError:
                pass
        if self._control_key.get_key_id() not in self.key_store.keys.keys():
            self.key_store.add_key(self._control_key)
            self.key_store.save_appdata()
        return self._control_key

    def update_did_doc(self, did_doc: dict) -> None:
        """Publish a new DID-document to replace the current one."""
        did_doc_block = DidDocBlock.new(did_doc)
        self.add_info_block(did_doc_block)

        self.did_doc = did_doc

    def get_did_doc(self) -> dict:
        """Get the current DID-document."""
        if not self.did_doc:
            self.did_doc = get_latest_did_doc(self.blockchain)
        return self.did_doc

    def get_members(self) -> list[dict]:
        """Get the current list of member-members."""
        if not self.members_list:
            self.members_list = list(get_members(self.blockchain).values())
            if self.members_list is None:
                return []

        return self.members_list

    def add_member_invitation(self, member_invitation: dict) -> None:
        member_invitation_block = MemberInvitationBlock.new(member_invitation)
        self.add_info_block(member_invitation_block)

    def add_member_update(self, member: dict) -> None:
        block = MemberUpdateBlock.new(member)
        self.add_info_block(block)

    def add_member_leaving(self, member: dict) -> None:
        block = MemberLeavingBlock.new(member)
        self.add_info_block(block)

    def invite_member(self) -> dict:
        """Create and register a member invitation on the blockchain."""
        # generate a key to be used by new member when registering themselves
        key = Key.create(CRYPTO_FAMILY)

        person_blockchain_invitation = json.loads(
            self.blockchain.create_invitation(
                one_time=False, shared=True
            )
        )
        member_invitation = {
            "blockchain_invitation": person_blockchain_invitation,
            "invitation_key": key.get_key_id()
        }
        signature = bytes_to_string(key.sign(str.encode(json.dumps(
            member_invitation
        ))))
        member_invitation.update({"signature": signature})

        self.add_member_invitation(member_invitation)
        member_invitation.update({"private_key": key.get_private_key()})

        return member_invitation

    @classmethod
    def join_as_member(
        cls: Type[_DidManager],
        invitation: dict,
        blockchain: Blockchain,
        member_keystore_file: str,
        key: Key,
    ) -> _DidManager:
        """Create a new IdentityAccess object."""
        # logger.debug("DM: Member joining a did_manager.")
        invitation_key = Key.from_key_id(invitation["invitation_key"])
        try:
            invitation_key.unlock(invitation["private_key"])
        except:
            raise IdentityJoinError(
                "Invalid invitation: public-private key mismatch"
            )
        member_invitation_blocks = get_info_blocks(
            blockchain, MemberInvitationBlock
        )
        member_invitation_blocks.reverse()
        member_invitation_block = None
        # TODO: filter by creation time
        for invitation_block in member_invitation_blocks:
            if invitation_block.get_member_invitation()["invitation_key"] == invitation["invitation_key"]:
                member_invitation_block = invitation_block
                break

        if not member_invitation_block:
            # TODO: wait little and try again
            raise IdentityJoinError(
                "The Person's blockchain doesn't have our invitation in it!"
            )

        member_keystore = KeyStore(member_keystore_file, key)
        member_did_manager = cls.create(member_keystore)

        joining_block = MemberJoiningBlock.new({
            "did": member_did_manager.did,
            "invitation": member_did_manager.blockchain.create_invitation(
                one_time=False, shared=True
            ),
            "invitation_key": invitation["invitation_key"]
        })
        joining_block.sign(invitation_key)
        blockchain.add_block(
            joining_block.generate_block_content(), joining_block.walytis_block_topic
        )
        return member_did_manager

    def on_block_received(self, block: Block) -> None:
        # logger.debug("DM: Received block!")
        block_type = get_block_type(block.topics)
        if not block_type:
            logger.warning("DM: Received block of unknown type.")
            return None

        match block_type:
            case (
                did_manager_blocks.ControlKeyBlock
                | did_manager_blocks.KeyOwnershipBlock
            ):
                self._control_key = get_latest_control_key(self.blockchain)
            case did_manager_blocks.DidDocBlock:
                self.did_doc = get_latest_did_doc(self.blockchain)
            case (
                did_manager_blocks.MemberJoiningBlock
                | did_manager_blocks.MemberUpdateBlock
                | did_manager_blocks.MemberLeavingBlock
            ):
                self.members_list = list(get_members(self.blockchain).values())
            case _:
                logger.warning(
                    f"DM: Did not recognise block type: {block_type}")
                # if user defined an event-handler for non-DID blocks, call it
                if self.non_did_blocks_handler:
                    self.non_did_blocks_handler(block)

    def unlock(self, private_key: bytes | bytearray | str) -> None:
        control_key = self.get_control_key()
        if control_key:
            control_key.unlock(private_key)
            self.key_store.save_appdata()
        else:
            # TODO: raise custom exception
            raise Exception("Don't have control key yet!")

    def encrypt(
        self,
        data: bytes,
        encryption_options: str = ""
    ) -> bytes:
        """Encrypt the provided data using the specified public key.

        Args:
            data_to_encrypt (bytes): the data to encrypt
            encryption_options (str): specification code for which
                                    encryption/decryption protocol should be used
        Returns:
            bytes: the encrypted data
        """
        return self.key_store.encrypt(
            data=data,
            key=self.get_control_key(),
            encryption_options=encryption_options,
        ).serialise_bytes()

    def decrypt(
        self,
        data: bytes,
    ) -> bytes:
        """Decrypt the provided data using the specified private key.

        Args:
            data (bytes): the data to decrypt
        Returns:
            bytes: the decrypted data
        """
        cipher_package = CodePackage.deserialise_bytes(data)
        return self.key_store.decrypt(
            cipher_package,
        )

    def sign(self, data: bytes, signature_options: str = "") -> bytes:
        """Sign the provided data using the specified private key.

        Args:
            data (bytes): the data to sign
            private_key (bytes): the private key to be used for the signing
            signature_options (str): specification code for which
                                signature/verification protocol should be used
        Returns:
            bytes: the signature
        """
        return self.key_store.sign(
            data=data,
            key=self.get_control_key(),
            signature_options=signature_options,
        ).serialise_bytes()

    def verify_signature(
        self,
        signature: bytes,
        data: bytes,
    ) -> bool:
        """Verify the given signature of the given data using the given key.

        Args:
            signature (bytes): the signaure to verify
            data (bytes): the data to sign
            public_key (bytes): the public key to verify the signature against
            signature_options (str): specification code for which
                                signature/verification protocol should be used
        Returns:
            bool: whether or not the signature matches the data
        """
        signature_package = CodePackage.deserialise_bytes(signature)
        return self.key_store.verify_signature(
            signature_package,
            data=data
        )

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


class DidNotOwnedError(Exception):
    """When we don't have the private key to a DID-Manager's control key."""


class IdentityJoinError(Exception):
    """When `DidManager.join_as_member()` fails."""

    def __init__(self, message: str):
        self.message = message

    def __str__(self):
        return self.message

# decorate_all_functions(strictly_typed, __name__)
