from abc import ABC, abstractmethod, abstractproperty
from typing import Callable, Type

from walytis_beta_api import (
    Block,
)

from .group_did_manager import GroupDidManager
from .key_store import KeyStore


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
    @property
    def did(self)->str:
        return self.org_did_manager.did
    def terminate(self, terminate_member:bool=True):
        self.did_manager.terminate(terminate_member=terminate_member)
    def delete(self):
        self.did_manager.delete()
    def __del__(self):
        self.terminate()