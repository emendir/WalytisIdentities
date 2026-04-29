"""Prototype for classes that wrap GroupDidManager objects."""

from abc import ABC, abstractmethod, abstractproperty
from collections.abc import Generator
from typing import Callable, Self

from docstring_inheritance import (  # type: ignore
    GoogleDocstringInheritanceMeta,
)
from walytis_beta_api import (  # type: ignore
    Block,
)
from walytis_beta_api._experimental.generic_blockchain import (  # type: ignore
    GenericBlock,
    GenericBlockchain,
)

from ..group_did_manager import GroupDidManager
from ..key_store import KeyStore
from .dm_wrapper import DidManagerWrapper


class GroupDidManagerWrapper(
    DidManagerWrapper, ABC, metaclass=GoogleDocstringInheritanceMeta
):
    """Prototype for classes that wrap GroupDidManager objects."""

    @abstractmethod
    def __init__(self, did_manager: GroupDidManager):
        pass

    @abstractproperty
    def did_manager(self) -> GroupDidManager:
        """The GroupDidManager underlying this DMWS (including wrappers)."""
        pass

    @abstractproperty
    def org_did_manager(self) -> GroupDidManager:
        """The underlying GroupDidManager GroupDidManager without wrappers."""
        pass

    @property
    def blockchain(self) -> GenericBlockchain:  # noqa: D102
        return self.org_did_manager.blockchain

    @property
    def key_store(self) -> KeyStore:  # noqa: D102
        return self.org_did_manager.key_store

    @classmethod
    def create(
        cls,
        group_key_store: KeyStore | str,
        member: GroupDidManager | KeyStore,
        other_blocks_handler: Callable[[Block], None] | None = None,
    ) -> Self:
        """Create a new instance of this object with a new GroupDidManager."""
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
    ) -> Self:
        """Join membership of an existing GroupDidManager."""
        did_manager = GroupDidManager.join(
            invitation=invitation,
            group_key_store=group_key_store,
            member=member,
            other_blocks_handler=other_blocks_handler,
        )
        return cls(did_manager)

    def invite_member(self) -> dict:
        """Create an invitation for a new peer to join this GroupDidManager."""
        return self.org_did_manager.invite_member()

    def add_block(  # noqa: D102
        self, content: bytes, topics: list[str] | str | None = None
    ) -> GenericBlock:
        return self.did_manager.add_block(content=content, topics=topics)

    def get_blocks(self, reverse: bool = False) -> Generator[GenericBlock]:  # noqa: D102
        return self.did_manager.get_blocks(reverse=reverse)

    def get_block_ids(self) -> list[bytes]:  # noqa: D102
        return self.did_manager.get_block_ids()

    def get_num_blocks(self) -> int:  # noqa: D102
        return self.did_manager.get_num_blocks()

    def get_block(self, block_id: bytes) -> GenericBlock:  # noqa: D102
        return self.did_manager.get_block(block_id)

    def encrypt(self, data: bytes, encryption_options: str = "") -> bytes:  # noqa: D102
        return self.org_did_manager.encrypt(
            data=data,
            encryption_options=encryption_options,
        )

    def decrypt(  # noqa: D102
        self,
        data: bytes,
    ) -> bytes:
        return self.org_did_manager.decrypt(data=data)

    def sign(self, data: bytes, signature_options: str = "") -> bytes:  # noqa: D102
        return self.org_did_manager.sign(
            data=data,
            signature_options=signature_options,
        )

    def verify_signature(  # noqa: D102
        self,
        signature: bytes,
        data: bytes,
    ) -> bool:
        return self.org_did_manager.verify_signature(
            signature=signature,
            data=data,
        )

    @property
    def block_received_handler(self) -> Callable[[Block], None] | None:  # noqa: D102
        return self.did_manager.block_received_handler

    @block_received_handler.setter
    def block_received_handler(
        self, block_received_handler: Callable[[Block], None]
    ) -> None:
        self.did_manager.block_received_handler = block_received_handler

    def clear_block_received_handler(self) -> None:
        """Remove the eventhandler for processing received blocks."""
        self.did_manager.clear_block_received_handler()

    def get_peers(self) -> list[str]:  # noqa: D102
        return self.org_did_manager.get_peers()

    @property
    def did(self) -> str:  # noqa: D102
        return self.org_did_manager.did

    @property
    def did_doc(self) -> dict:  # noqa: D102
        return self.org_did_manager.did_doc

    def terminate(self, terminate_member: bool = True) -> None:  # noqa: D102
        self.did_manager.terminate(terminate_member=terminate_member)

    def delete(self, terminate_member: bool = True) -> None:  # noqa: D102
        self.did_manager.delete(terminate_member=terminate_member)

    def __del__(self):  # noqa: D105
        self.terminate()
