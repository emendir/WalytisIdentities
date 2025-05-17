"""Machinery for managing DID-Documents, i.e. identities' cryptography keys.

Doesn't include machinery for managing other members.
"""
from walytis_beta_api.exceptions import BlockNotFoundError
from collections.abc import Generator
from walytis_beta_tools._experimental.block_lazy_loading import BlockLazilyLoaded, BlocksList
from walytis_beta_api._experimental.generic_blockchain import GenericBlockchain, GenericBlock
import os
from dataclasses import dataclass
from typing import Callable, TypeVar

import walytis_beta_api as waly
from brenthy_tools_beta.utils import bytes_to_string
from multi_crypt import Crypt
from walytis_beta_api import Block, Blockchain, create_blockchain
from .utils import logger
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
from abc import ABC, abstractmethod, abstractproperty

class GenericDidManager(GenericBlockchain, ABC):
    """Manage DID documents using a Walytis blockchain.

    Publishes DID documents on a blockchain, secured by an updatable
    control key system.
    DOESN'T create ID documents.
    """
    @abstractproperty
    def blockchain(self)->Blockchain:
        pass

    @abstractproperty
    def key_store(self)-> KeyStore:
        pass


    
    @abstractproperty
    def did_doc(self):
        pass

    @abstractproperty
    def did(self) -> str:
        """Get this DID-Manager's DID."""
        pass
    @abstractmethod
    def renew_control_key(self, new_ctrl_key: Crypt | None = None) -> None:
        """Change the control key to an automatically generated new one."""
        pass

    @abstractmethod
    def get_control_key(self) -> Key:
        """Get the current control key, with private key if possible."""
        pass

    @abstractmethod
    def update_did_doc(self, did_doc: dict) -> None:
        """Publish a new DID-document to replace the current one."""
        pass

    def unlock(self, private_key: bytes | bytearray | str) -> None:
        pass

    @abstractmethod
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
        pass

    @abstractmethod
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
        pass
    @abstractmethod
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
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    def delete(self) -> None:
        """Delete this DID-Manager."""
        pass

    def terminate(self) -> None:
        """Stop this DID-Manager, cleaning up resources."""
        pass

    @property
    def blockchain_id(self) -> str:
        return self.blockchain.blockchain_id

    @abstractproperty
    def block_received_handler(self) -> Callable[[Block], None] | None:
        pass
    
