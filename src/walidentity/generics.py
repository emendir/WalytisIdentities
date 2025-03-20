from abc import ABC, abstractmethod, abstractproperty
from collections.abc import Generator
from typing import Callable

from walytis_beta_api import (
    Block,
)
from walytis_beta_api._experimental.generic_blockchain import (
    GenericBlock,
)

from .group_did_manager import GroupDidManager
from .key_store import KeyStore

from .generic_did_manager import GenericDidManager
from .did_manager import DidManager
class DidManagerWrapper(GenericDidManager,ABC):

    @abstractmethod
    def __init__(self, did_manager: GroupDidManager):
        pass

    @abstractproperty
    def did_manager(self) -> GroupDidManager:
        pass

    @abstractproperty
    def org_did_manager(self) -> GenericDidManager:
        pass

    @classmethod
    def create(
        cls,
        key_store: KeyStore | str,
        other_blocks_handler: Callable[[Block], None] | None = None,
    ):
        did_manager = DidManager.create(
            key_store=key_store,
            other_blocks_handler=other_blocks_handler,
        )
        return cls(did_manager)


    def add_block(
        self, content: bytes, topics: list[str] | str | None = None
    ) -> GenericBlock:
        return self.did_manager.add_block(
            content=content, topics=topics
        )

    def get_blocks(self, reverse: bool = False) -> Generator[GenericBlock]:
        return self.did_manager.get_blocks(reverse=reverse)

    def get_block_ids(self) -> list[bytes]:
        return self.did_manager.get_block_ids()

    def get_num_blocks(self) -> int:
        return self.did_manager.get_num_blocks()

    def get_block(self, id: bytes) -> GenericBlock:
        return self.did_manager.get_block(id=id)
    def encrypt(
        self,
        data: bytes,
        encryption_options: str = ""
    ) -> bytes:
        """Encrypt the provided data using the specified public key.

        Args:
            data_to_encrypt(bytes): the data to encrypt
            encryption_options(str): specification code for which
                                    encryption / decryption protocol should be used
        Returns:
            bytes: the encrypted data
        """
        return self.org_did_manager.encrypt(
            data=data,
            encryption_options=encryption_options,
        )

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
        return self.org_did_manager.decrypt(data=data)

    def sign(self, data: bytes, signature_options: str = "") -> bytes:
        """Sign the provided data using the specified private key.

        Args:
            data(bytes): the data to sign
            private_key(bytes): the private key to be used for the signing
            signature_options(str): specification code for which
                                signature / verification protocol should be used
        Returns:
            bytes: the signature
        """
        return self.org_did_manager.sign(
            data=data,
            signature_options=signature_options,
        )

    def verify_signature(
        self,
        signature: bytes,
        data: bytes,
    ) -> bool:
        return self.org_did_manager.verify_signature(
            signature=signature,
            data=data,
        )



    def get_peers(self) -> list[str]:
        return self.org_did_manager.get_peers()

    @property
    def did(self) -> str:
        return self.org_did_manager.did

    @property
    def did_doc(self):
        return self.org_did_manager.did_doc

    def terminate(self, terminate_member: bool = True):
        self.did_manager.terminate(terminate_member=terminate_member)

    def delete(self):
        self.did_manager.delete()

    def __del__(self):
        self.terminate()

class GroupDidManagerWrapper(ABC):

    @abstractmethod
    def __init__(self, did_manager: GroupDidManager):
        pass

    @abstractproperty
    def did_manager(self) -> GroupDidManager:
        pass

    @abstractproperty
    def org_did_manager(self) -> GroupDidManager:
        pass

    @classmethod
    def create(
        cls,
        group_key_store: KeyStore | str,
        member: GroupDidManager | KeyStore,
        other_blocks_handler: Callable[[Block], None] | None = None,
    ):
        did_manager = GroupDidManager.create(
            group_key_store=group_key_store,
            member=member,
            other_blocks_handler=other_blocks_handler,
        )
        return cls(did_manager)

    @classmethod
    def join(
        cls,
        invitation: str | dict,
        group_key_store: KeyStore | str,
        member: GroupDidManager,
        other_blocks_handler: Callable[[Block], None] | None = None,
    ):
        did_manager = GroupDidManager.join(
            invitation=invitation,
            group_key_store=group_key_store,
            member=member,
            other_blocks_handler=other_blocks_handler,
        )
        return cls(did_manager)

    def invite_member(self) -> dict:
        return self.org_did_manager.invite_member()
    def add_block(
        self, content: bytes, topics: list[str] | str | None = None
    ) -> GenericBlock:
        return self.did_manager.add_block(
            content=content, topics=topics
        )

    def get_blocks(self, reverse: bool = False) -> Generator[GenericBlock]:
        return self.did_manager.get_blocks(reverse=reverse)

    def get_block_ids(self) -> list[bytes]:
        return self.did_manager.get_block_ids()

    def get_num_blocks(self) -> int:
        return self.did_manager.get_num_blocks()

    def get_block(self, id: bytes) -> GenericBlock:
        return self.did_manager.get_block(id=id)
    def encrypt(
        self,
        data: bytes,
        encryption_options: str = ""
    ) -> bytes:
        """Encrypt the provided data using the specified public key.

        Args:
            data_to_encrypt(bytes): the data to encrypt
            encryption_options(str): specification code for which
                                    encryption / decryption protocol should be used
        Returns:
            bytes: the encrypted data
        """
        return self.org_did_manager.encrypt(
            data=data,
            encryption_options=encryption_options,
        )

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
        return self.org_did_manager.decrypt(data=data)

    def sign(self, data: bytes, signature_options: str = "") -> bytes:
        """Sign the provided data using the specified private key.

        Args:
            data(bytes): the data to sign
            private_key(bytes): the private key to be used for the signing
            signature_options(str): specification code for which
                                signature / verification protocol should be used
        Returns:
            bytes: the signature
        """
        return self.org_did_manager.sign(
            data=data,
            signature_options=signature_options,
        )

    def verify_signature(
        self,
        signature: bytes,
        data: bytes,
    ) -> bool:
        return self.org_did_manager.verify_signature(
            signature=signature,
            data=data,
        )

    @property
    def block_received_handler(self) -> Callable[[Block], None] | None:
        return self.did_manager.block_received_handler

    @block_received_handler.setter
    def block_received_handler(
        self, block_received_handler: Callable[Block, None]
    ) -> None:
        self.did_manager.block_received_handler = block_received_handler

    def clear_block_received_handler(self) -> None:
        self.did_manager.clear_block_received_handler()

    def get_peers(self) -> list[str]:
        return self.org_did_manager.get_peers()

    @property
    def did(self) -> str:
        return self.org_did_manager.did

    @property
    def did_doc(self):
        return self.org_did_manager.did_doc

    def terminate(self, terminate_member: bool = True):
        self.did_manager.terminate(terminate_member=terminate_member)

    def delete(self):
        self.did_manager.delete()

    def __del__(self):
        self.terminate()
