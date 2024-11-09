"""Machinery for managing DID-Documents, i.e. identities' cryptography keys.

Doesn't include machinery for managing other members.
"""
import os
from dataclasses import dataclass
from typing import Callable, TypeVar

import walytis_beta_api as waly
from brenthy_tools_beta.utils import bytes_to_string
from multi_crypt import Crypt
from walytis_beta_api import Block, Blockchain

from . import did_manager_blocks
from .did_manager_blocks import (
    ControlKeyBlock,
    DidDocBlock,
    InfoBlock,
    get_block_type,
    get_latest_control_key,
    get_latest_did_doc,
)
from .did_objects import Key
from .exceptions import NotValidDidBlockchainError
from .key_store import CodePackage, KeyStore

DID_METHOD_NAME = "wlaytis-contacts"
DID_URI_PROTOCOL_NAME = "waco"  # https://www.rfc-editor.org/rfc/rfc3986#section-3.1

CRYPTO_FAMILY = "EC-secp256k1"

_DidManager = TypeVar('_DidManager', bound='DidManager')
KEYSTORE_DID = "owner_did"  # DID field name in KeyStore's custom metadata


@dataclass
class DidManager:
    """Manage DID documents using a Walytis blockchain.

    Publishes DID documents on a blockchain, secured by an updatable
    control key system.
    DOESN'T create ID documents.
    """

    blockchain: Blockchain

    # The current control key's ID.
    # This key's Key object is always available in self.key_store
    _control_key_id: str
    key_store: KeyStore

    did_doc: dict

    def __init__(
        self,
        key_store: KeyStore,
        other_blocks_handler: Callable[[Block], None] | None = None,
        appdata_dir: str = "",
    ):
        """Load a DidManager from a Walytis blockchain.

        Args:
            blockchain: the blockchain on which this DID-Manager's data is
            key_store: the KeyStore object in which to store this DID's keys
            other_blocks_handler: eventhandler for blocks published on
                `blockchain` that aren't related to this DID-Manager work
        """
        if not isinstance(key_store, KeyStore):
            raise TypeError(
                "The parameter `key_store` must be of type KeyStore, "
                f"not {type(key_store)}"
            )
        # assert that the key_store is unlocked
        key_store.key.get_private_key()
        

        # load blockchain_id from the KeyStore's metadata
        keystore_did = key_store.get_custom_metadata().get(KEYSTORE_DID)

        if not keystore_did:
            raise Exception(
                "The KeyStore passed doesn't have "
                f"{KEYSTORE_DID} in its custom metadata"
            )
        blockchain_id = blockchain_id_from_did(keystore_did)

        # ensure we aren't using another ekystore
        if blockchain_id != blockchain_id_from_did(keystore_did):
            raise Exception(
                "The blockchain_id passed doesn't match the the DID encoded "
                "in the keystore's custom metadata"
            )

        self.blockchain = Blockchain(
            blockchain_id,
            appdata_dir=appdata_dir,
            auto_load_missed_blocks=False,
            block_received_handler=self.on_block_received,
            update_blockids_before_handling=True,
        )
        self._dm_other_blocks_handler = other_blocks_handler
        self.key_store = key_store
        self._control_key_id = ""
        # logger.debug("DM: Getting control key...")
        # logger.debug("DM: Getting DID-Doc...")
        import walytis_beta_api as waly
        self.blockchain.load_missed_blocks(
            waly.blockchain_model.N_STARTUP_BLOCKS
        )
        self.did_doc = get_latest_did_doc(self.blockchain)
        if not self.did_doc:
            raise NotValidDidBlockchainError()

        # logger.debug("DM: Built DID-Manager object!")

    @classmethod
    def create(cls, key_store: KeyStore | str):
        """Create a new DID-Manager.

        Args:
            key_store: KeyStore for this DidManager to store private keys.
                    If a directory is passed, a KeyStore is created in there
                    named after the blockchain ID of the created DidManager.
        """
        # logger.debug("DM: Creating DID-Manager...")
        # create crypto keys
        ctrl_key = Key.create(CRYPTO_FAMILY)
        # logger.debug("DM: Createing DID-Manager's blockchain...")
        # create blockchain
        # logger.debug("DM: Creating Blockchain...")

        blockchain = Blockchain.create(
            blockchain_name=f"waco-{bytes_to_string(ctrl_key.public_key)}"
        )

        key_store = cls.assign_keystore(key_store, blockchain.blockchain_id)
        key_store.add_key(ctrl_key)

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

        blockchain.terminate()
        did_manager = cls(key_store)

        # logger.debug("DM: created DID-Manager!")
        return did_manager

    @staticmethod
    def assign_keystore(key_store: KeyStore | str, blockchain_id: str) -> KeyStore:
        """Mark a key_store as belonging to a DidManager.

        Args:
            key_store: KeyStore for this DidManager to store private keys.
                    If a directory is passed, a KeyStore is created in there
                    named after the blockchain ID of the created DidManager.
        """
        if isinstance(key_store, str):
            if not os.path.isdir(key_store):
                raise ValueError(
                    "If a string is passed for the `key_store` parameter, "
                    "it should be a valid directory"
                )
            # use blockchain ID instead of DID
            # as some filesystems don't support colons
            key_store_path = os.path.join(
                key_store, blockchain_id + ".json"
            )
            key_store = KeyStore(key_store_path, Key.create(CRYPTO_FAMILY))
        # TODO: assert that key store has control key
        # encode our DID into the keystore
        key_store.update_custom_metadata(
            {KEYSTORE_DID: did_from_blockchain_id(blockchain_id)}
        )
        return key_store

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

        self._control_key_id = new_ctrl_key.get_key_id()
        # logger.info(
        #     "Renewed control key:\n"
        #     f"    old: {old_ctrl_key.get_key_id()}\n"
        #     f"    new: {new_ctrl_key.get_key_id()}"
        # )

    def add_info_block(self, block: InfoBlock) -> Block:
        """Add an InfoBlock type block to this DID-Block's blockchain."""
        if not block.signature:
            block.sign(self.get_control_key())
        return self.blockchain.add_block(
            block.generate_block_content(), block.walytis_block_topic
        )

    def check_control_key(self) -> Key:
        """Read the blockchain for the latest control key.

        Updates self._control_key_id, returns the control key object.
        The returned Key NEVER has the private key.
        """
        control_key = get_latest_control_key(self.blockchain)
        self._control_key_id = control_key.get_key_id()
        if self._control_key_id not in self.key_store.keys.keys():
            # add key to key store
            self.key_store.add_key(control_key)
        return control_key

    def get_control_key(self) -> Key:
        """Get the current control key, with private key if possible."""
        if not self._control_key_id:
            # update self._control_key_id from the blockchain
            self.check_control_key()
        # load key from key store to get potential private key
        control_key = self.key_store.get_key(self._control_key_id)
        return control_key

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

    def on_block_received(self, block: Block) -> None:
        # logger.debug("DM: Received block!")
        block_type = get_block_type(block.topics)
        match block_type:
            case (
                did_manager_blocks.ControlKeyBlock
                | did_manager_blocks.KeyOwnershipBlock
            ):
                # update self._control_key_id from the blockchain
                self.check_control_key()
                # logger.debug(self._control_key_id)
            case did_manager_blocks.DidDocBlock:
                self.did_doc = get_latest_did_doc(self.blockchain)
            case 0:
                # if user defined an event-handler for non-DID blocks, call it
                if self._dm_other_blocks_handler:
                    self._dm_other_blocks_handler(block)

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
        try:
            self.blockchain.delete()
        except waly.exceptions.NoSuchBlockchainError:
            pass

    def terminate(self) -> None:
        """Stop this DID-Manager, cleaning up resources."""
        try:
            self.key_store.terminate()
            self.blockchain.terminate()
        except waly.exceptions.NoSuchBlockchainError:
            pass

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


# decorate_all_functions(strictly_typed, __name__)
