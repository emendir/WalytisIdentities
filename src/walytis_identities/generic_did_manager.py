"""Machinery for managing DID-Documents, i.e. identities' cryptography keys.

Doesn't include machinery for managing other members.
"""

from abc import ABC, abstractmethod, abstractproperty
from collections.abc import Generator
from typing import Callable

from docstring_inheritance import (  # type: ignore
    GoogleDocstringInheritanceMeta,
)
from walytis_beta_api import Block, Blockchain  # type: ignore
from walytis_beta_api._experimental.generic_blockchain import (  # type: ignore
    GenericBlockchain,  # type: ignore
)
from walytis_beta_tools._experimental.generic_block import (  # type: ignore
    GenericBlock,  # type: ignore
)

from .key_objects import KeyGroup
from .key_store import KeyStore


class GenericDidManager(
    GenericBlockchain, ABC, metaclass=GoogleDocstringInheritanceMeta
):
    """Manage DID documents using a Walytis blockchain.

    Publishes DID documents on a blockchain, secured by an updatable
    control key system.
    DOESN'T create ID documents.
    """

    @abstractproperty
    def blockchain(self) -> Blockchain:
        """The blockchain underlying this DidManager."""

    @property
    def blockchain_id(self) -> str:
        """Get the ID of the blockchain underlying this DidManger."""
        return self.blockchain.blockchain_id

    @abstractproperty
    def key_store(self) -> KeyStore:
        """The key storage object."""

    @abstractproperty
    def did(self) -> str:
        """DID (decentralised identifier)."""

    @abstractproperty
    def did_doc(self) -> dict:
        """DID-Document: a formal declaration a DID's associated keys etc."""

    @abstractmethod
    def renew_control_key(self, new_ctrl_key: KeyGroup | None = None) -> None:
        """Renew (rotate) the underlying DidManager's control key."""

    @abstractmethod
    def get_control_keys(self) -> KeyGroup:
        """Get the current control key, with private key if possible."""

    @abstractmethod
    def update_did_doc(self, did_doc: dict) -> None:
        """Set a new DID-Document for this DidManager."""

    @abstractmethod
    def encrypt(self, data: bytes, encryption_options: str = "") -> bytes:
        """Encrypt the provided data.

        Args:
            data (bytes): the data to encrypt
            encryption_options (str): specification code for which
                                encryption/decryption protocol should be used
        Returns:
            bytes: the encrypted data
        """

    @abstractmethod
    def decrypt(
        self,
        data: bytes,
    ) -> bytes:
        """Decrypt the provided data.

        Args:
            data (bytes): the data to decrypt
        Returns:
            bytes: the decrypted data
        """

    @abstractmethod
    def sign(self, data: bytes, signature_options: str = "") -> bytes:
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
    def get_peers(self) -> list[str]:
        """Get the IPFS IDs of this DidManager instance's online peers."""

    @abstractmethod
    def delete(self) -> None:
        """Delete this DID-Manager."""

    @abstractmethod
    def terminate(self) -> None:
        """Stop this object's functionality and clean up resources."""

    @abstractproperty
    def block_received_handler(self) -> Callable[[Block], None] | None:
        """Event handler for blocks not used by any DidManager machinery."""

    @abstractmethod
    def add_block(
        self, content: bytes, topics: list[str] | str | None = None
    ) -> GenericBlock:
        """Add a block to this DidManager's underlying blockchain."""

    @abstractmethod
    def get_blocks(self, reverse: bool = False) -> Generator[GenericBlock]:
        """Get all blocks that aren't used by any DidManager machinery."""

    @abstractmethod
    def get_block_ids(self) -> list[bytes]:
        """Get the IDs of blocks not used by any DidManager machinery."""

    @abstractmethod
    def get_num_blocks(self) -> int:
        """Get the number of blocks not used by DidManager machinery."""

    @abstractmethod
    def get_block(self, block_id: bytes) -> GenericBlock:
        """Get a block given its ID.

        Only for blocks that aren't part of DidManager machinery.
        """
