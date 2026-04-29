"""Prototype for classes that wrap DidManager objects."""

from abc import ABC, abstractproperty
from collections.abc import Generator

from docstring_inheritance import (  # type: ignore  # type: ignore
    GoogleDocstringInheritanceMeta,
)
from walytis_beta_api._experimental.generic_blockchain import (  # type: ignore  # type: ignore
    GenericBlock,
    GenericBlockchain,
)

from ..did_manager import DidManager
from ..key_objects import KeyGroup
from ..key_store import KeyStore
from .generic_did_manager import GenericDidManager


class DidManagerWrapper(
    GenericDidManager, ABC, metaclass=GoogleDocstringInheritanceMeta
):
    """Prototype for classes that wrap DidManager objects."""

    @abstractproperty
    def did_manager(self) -> GenericDidManager:
        """The DidManager underlying this DMWS (including wrappers)."""
        pass

    @abstractproperty
    def org_did_manager(self) -> DidManager:
        """The underlying DidManager without wrappers."""
        pass

    @property
    def blockchain(self) -> GenericBlockchain:  # noqa: D102
        return self.org_did_manager.blockchain

    @property
    def key_store(self) -> KeyStore:
        """The keystore of this DidManager."""
        return self.org_did_manager.key_store

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

    def get_peers(self) -> list[str]:  # noqa: D102
        return self.org_did_manager.get_peers()

    @property
    def did(self) -> str:  # noqa: D102
        return self.org_did_manager.did

    @property
    def did_doc(self) -> dict:  # noqa: D102
        return self.org_did_manager.did_doc

    def terminate(self) -> None:  # noqa: D102
        self.did_manager.terminate()

    def delete(self) -> None:  # noqa: D102
        self.did_manager.delete()

    def __del__(self) -> None:  # noqa: D105
        self.terminate()

    def is_control_key_active(self, key_id: str) -> bool:
        """Check if the specified key is in current use."""
        return self._did_manager.is_control_key_active(key_id=key_id)

    def get_control_keys_history(self) -> list[KeyGroup]:
        """Get chronological list of all keys ever used."""
        return self._did_manager.get_control_keys_history()

    def get_control_keys(self) -> KeyGroup:
        """Get the current control key, with private key if possible."""
        return self._did_manager.get_control_keys()

    def renew_control_key(self, new_ctrl_key: KeyGroup | None = None) -> None:
        """Change the control key to an automatically generated new one."""
        return self._did_manager.renew_control_key(new_ctrl_key)

    def update_did_doc(self, did_doc: dict) -> None:
        """Publish a new DID-document to replace the current one."""
        return self._did_manager.update_did_doc(did_doc)
