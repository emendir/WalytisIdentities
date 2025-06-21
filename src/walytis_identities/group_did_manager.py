"""Classes for managing Person and Device identities."""
from walytis_beta_api import list_blockchain_ids
import traceback
import json
from walytis_beta_api.exceptions import BlockNotFoundError
from collections.abc import Generator
from walytis_beta_tools._experimental.block_lazy_loading import BlockLazilyLoaded, BlocksList
import walytis_beta_api
from walytis_beta_api._experimental.generic_blockchain import GenericBlockchain, GenericBlock
import os
from dataclasses import dataclass
from typing import Callable, TypeVar
import ipfs_tk_transmission
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
    get_info_blocks,
)
import walytis_beta_tools
from .did_objects import Key
from .exceptions import NotValidDidBlockchainError
from .key_store import CodePackage, KeyStore
from .generic_did_manager import GenericDidManager
import os
import time
from datetime import datetime, timedelta
from threading import Thread
from time import sleep
from typing import Callable, Type, TypeVar

from walytis_beta_embedded import ipfs
from walytis_beta_embedded import ipfs

import walytis_beta_api
import walytis_beta_api as walytis_beta
from brenthy_tools_beta.utils import bytes_to_string, string_to_bytes
from ipfs_tk_transmission.errors import ConvListenTimeout, CommunicationTimeout
from .utils import logger
from walytis_beta_api import (
    Block,
    Blockchain,

    list_blockchain_ids,
)
from walytis_beta_tools.exceptions import (
    BlockchainAlreadyExistsError,
    JoinFailureError,
)
from . import did_manager_blocks
from .did_manager import DidManager, blockchain_id_from_did
from .did_manager_blocks import (
    KeyOwnershipBlock,
    MemberInvitationBlock,
    MemberJoiningBlock,
    MemberLeavingBlock,
    MemberUpdateBlock,
    get_block_type,
    get_latest_control_key,
    get_latest_did_doc,
    get_members,
    InfoBlock,
)
from .did_objects import Key
from .key_store import KeyStore, UnknownKeyError
from .settings import CTRL_KEY_MAX_RENEWAL_DUR_HR, CTRL_KEY_RENEWAL_AGE_HR
from .utils import validate_did_doc
WALYTIS_BLOCK_TOPIC = "GroupDidManager"

DID_METHOD_NAME = "wlaytis-contacts"
DID_URI_PROTOCOL_NAME = "waco"  # https://www.rfc-editor.org/rfc/rfc3986#section-3.1

CRYPTO_FAMILY = "EC-secp256k1"


GroupDidManagerType = TypeVar(
    'GroupDidManagerType', bound='GroupDidManager'
)
LISTEN_TIMEOUT = 30
SEND_TIMEOUT = 10


class Member:
    did: str
    invitation: str
    _blockchain: Blockchain | None

    def __init__(self, did: str, invitation: str, blockchain: Blockchain = None):
        self.did = did
        self.invitation = invitation
        if blockchain:
            self._blockchain = blockchain
        else:
            self._blockchain = None

    @classmethod
    def from_dict(cls, data: dict):
        return cls(data["did"], data["invitation"])

    def to_dict(self) -> dict:
        return {"did": self.did, "invitation": self.invitation}

    @property
    def blockchain(self):
        if self._blockchain:
            return self._blockchain
        self._blockchain = self._get_member_blockchain()
        return self._blockchain

    def _get_member_ipfs_ids(self) -> set[str]:
        did_doc = self._get_member_did_doc()
        ipfs_ids: list[str] | None = did_doc.get("ipfs_peer_ids")

        if not ipfs_ids:
            # TODO: find better way of getting DidManager's peer ID than blockchain invitation?
            ipfs_ids = json.loads(self.invitation)["peers"]
        return set(ipfs_ids)

    def _get_member_did_doc(self, ) -> dict:

        did_doc = get_latest_did_doc(self.blockchain)
        return did_doc

    def _get_member_control_key(self) -> Key:
        ctrl_key = get_latest_control_key(self.blockchain)
        return ctrl_key

    def _get_member_blockchain(self) -> Blockchain:
        # logger.debug("Getting member blockchain...")
        blockchain_id = blockchain_id_from_did(self.did)
        if blockchain_id not in list_blockchain_ids():
            if blockchain_id != json.loads(self.invitation)["blockchain_id"]:
                raise Exception(
                    "Invalid member entry:"
                    f"{blockchain_id}"
                    f"{json.loads(self.invitation)['blockchain_id']}"
                )

            logger.debug(f"GDM: joining member's blockchain... {self.did}")
            logger.debug(self.invitation)

            try:
                blockchain = Blockchain.join(self.invitation)
            except (BlockchainAlreadyExistsError) as e:
                blockchain = Blockchain(blockchain_id)
            except ipfs_tk_transmission.errors.CommunicationTimeout:
                try:
                    blockchain = Blockchain.join(self.invitation)
                except (Exception, BlockchainAlreadyExistsError, walytis_beta_tools.exceptions.BlockchainAlreadyExistsError) as e:
                    blockchain = Blockchain(blockchain_id)
            logger.debug(f"GDM: joined member's blockchain! {self.did}")
        else:
            # logger.debug("Loading member blockchain...")
            blockchain = Blockchain(blockchain_id)
        # logger.debug("Got member blockchain!")
        return blockchain

    def __del__(self):
        self.terminate()

    def terminate(self):
        if self._blockchain:
            self._blockchain.terminate()


class _GroupDidManager(DidManager):
    """DidManager with member-managment functionality.

    Includes functionality for keeping a list of member-DIDs, including
    the cryptographic invitations for independent joining of new members.
    DOES NOT include control-key sharing functionality, that is coded in
    GroupDidManager, which inherits this class.
    """

    def __init__(
        self,
        key_store: KeyStore,
        other_blocks_handler: Callable[[Block], None] | None = None,
        auto_load_missed_blocks: bool = True,

    ):
        self._gdm_other_blocks_handler = other_blocks_handler
        DidManager.__init__(
            self,
            key_store=key_store,
            # we handle member management blocks
            other_blocks_handler=self._gdm_on_block_received,
            auto_load_missed_blocks=False,

        )
        self._init_blocks_list_gdm()
        self._members: dict[str, Member] = {}
        self.get_members(no_cache=True)
        if auto_load_missed_blocks:
            _GroupDidManager.load_missed_blocks(self)

    def load_missed_blocks(self):
        DidManager.load_missed_blocks(self)

    def _gdm_add_info_block(self, block: InfoBlock) -> Block:
        """Add an InfoBlock type block to this DID-Block's blockchain."""
        if not block.signature:
            block.sign(self.get_control_key())
        return self.blockchain.add_block(
            block.generate_block_content(),
            [WALYTIS_BLOCK_TOPIC, block.walytis_block_topic]
        )

    def _gdm_on_block_received(self, block: Block) -> None:
        block_type = get_block_type(block.topics)
        # logger.debug(f"GDM: received block: {block.topics}")

        if WALYTIS_BLOCK_TOPIC in block.topics:
            match block_type:
                case (
                    did_manager_blocks.MemberJoiningBlock
                    | did_manager_blocks.MemberUpdateBlock
                    | did_manager_blocks.MemberLeavingBlock
                ):
                    self.get_members(no_cache=True)
                case did_manager_blocks.KeyOwnershipBlock:
                    self.check_control_key()
                case did_manager_blocks.MemberInvitationBlock:
                    pass
                case 0:
                    logger.warning(
                        "This block is marked as belong to GroupDidManager, "
                        "but it's InfoBlock type is not handled: "
                        f"{block.topics}"
                    )
        else:
            # logger.info(f"GDM: passing on received block: {block.topics}")
            self._blocks_list_gdm.add_block(
                BlockLazilyLoaded.from_block(block))

            # if user defined an event-handler for non-DID blocks, call it
            if self._gdm_other_blocks_handler:
                self._gdm_other_blocks_handler(block)
        # logger.debug(f"GDM: processed block")

    @property
    def block_received_handler(self) -> Callable[[Block], None] | None:
        return self._gdm_other_blocks_handler

    @block_received_handler.setter
    def block_received_handler(
        self, block_received_handler: Callable[Block, None]
    ) -> None:
        self._gdm_other_blocks_handler = block_received_handler

    def _update_members(self):
        self._members = dict([
            (member_info["did"], Member.from_dict(member_info))
            for member_info in get_members(self.blockchain).values()
        ])

    def get_members(self, no_cache: bool = False) -> list[Member]:
        """Get the current list of member-members."""
        if no_cache or not self._members:
            self._update_members()

        return list(self._members.values())

    def get_members_dids(self, no_cache: bool = False) -> set[str]:
        if no_cache or not self._members:
            self._update_members()
        return set(self._members.keys())

    def add_member_invitation(self, member_invitation: dict) -> Block:
        member_invitation_block = MemberInvitationBlock.new(member_invitation)
        return self._gdm_add_info_block(member_invitation_block)

    def add_member_update(self, member: dict) -> Block:
        block = MemberUpdateBlock.new(member)
        block = self._gdm_add_info_block(block)
        self.update_did_doc(self.generate_did_doc())
        return block

    def add_member_leaving(self, member: dict) -> Block:
        block = MemberLeavingBlock.new(member)
        block = self._gdm_add_info_block(block)
        self.update_did_doc(self.generate_did_doc())
        return block

    def invite_member(self) -> dict:
        """Create and register a member invitation on the blockchain."""
        # generate a key to be used by new member when registering themselves
        key = Key.create(CRYPTO_FAMILY)

        group_blockchain_invitation = json.loads(
            self.blockchain.create_invitation(
                one_time=False, shared=True
            )
        )
        member_invitation = {
            "blockchain_invitation": group_blockchain_invitation,
            "invitation_key": key.get_key_id()
        }
        signature = bytes_to_string(key.sign(str.encode(json.dumps(
            member_invitation
        ))))
        member_invitation.update({"signature": signature})

        invitation_block = self.add_member_invitation(member_invitation)
        member_invitation.update({"private_key": key.get_private_key()})
        member_invitation.update(
            {"invitation_block_id": bytes_to_string(invitation_block.long_id)}
        )

        return member_invitation

    def add_member(
        self,
        member: GenericDidManager
    ) -> None:
        """Add an existing DID-Manager as a member to this Group-DID."""
        logger.debug("GDM: Adding DidManager as member...")
        
        invitation_key = Key.create(CRYPTO_FAMILY)

        group_blockchain_invitation = json.loads(
            self.blockchain.create_invitation(
                one_time=False, shared=True
            )
        )
        member_invitation = {
            "blockchain_invitation": group_blockchain_invitation,
            "invitation_key": invitation_key.get_key_id()
        }
        signature = bytes_to_string(invitation_key.sign(str.encode(json.dumps(
            member_invitation
        ))))
        member_invitation.update({"signature": signature})

        self.add_member_invitation(member_invitation)

        joining_block = MemberJoiningBlock.new({
            "did": member.did,
            "invitation": member.blockchain.create_invitation(
                one_time=False, shared=True
            ),  # invitation for other's to join our member DID blockchain
            "invitation_key": invitation_key.get_key_id()  # Key object
        })
        joining_block.sign(invitation_key)
        self._gdm_add_info_block(joining_block)
        member.key_store.add_key(self.get_control_key())

        if self.get_control_key().private_key:
            self.update_did_doc(self.generate_did_doc())
        logger.debug("GDM: Added DidManager as member!")
        

    def make_member(
        self,
        invitation: dict,
        member: GenericDidManager
    ) -> None:
        """Creating a new member DID-Manager joining an existing Group-DID.

        Returns the member's DidManager.
        """
        logger.debug("GDM: Member joining...")
        invitation_key = Key.from_key_id(invitation["invitation_key"])
        try:
            invitation_key.unlock(invitation["private_key"])
        except:
            raise IdentityJoinError(
                "Invalid invitation: public-private key mismatch"
            )

        # make sure the Group-DID-Manager has the invitation block
        invitation_block = MemberInvitationBlock.load_from_block_content(

            self.blockchain.get_block(
                string_to_bytes(invitation["invitation_block_id"])
            ).content
        )
        if invitation_block.get_member_invitation()["invitation_key"] != invitation["invitation_key"]:
            raise IdentityJoinError("Looks like a corrupt invitation")

        joining_block = MemberJoiningBlock.new({
            "did": member.did,
            "invitation": member.blockchain.create_invitation(
                one_time=False, shared=True
            ),  # invitation for other's to join our member DID blockchain
            "invitation_key": invitation["invitation_key"]  # Key object
        })
        joining_block.sign(invitation_key)
        self._gdm_add_info_block(joining_block)
        if self.get_control_key().private_key:
            self.update_did_doc(self.generate_did_doc())
        logger.debug("GDM: Member joined!")
        

    def _init_blocks_list_gdm(self):
        # present to other programs all blocks not created by this DidManager
        blocks = [
            block for block in DidManager.get_blocks(self)
            if WALYTIS_BLOCK_TOPIC not in block.topics and block.topics != ["genesis"]
        ]
        self._blocks_list_gdm = BlocksList.from_blocks(
            blocks, BlockLazilyLoaded)

    def get_blocks(self, reverse: bool = False) -> Generator[GenericBlock]:
        return self._blocks_list_gdm.get_blocks(reverse=reverse)

    def get_block_ids(self) -> list[bytes]:
        return self._blocks_list_gdm.get_long_ids()

    def get_num_blocks(self) -> int:
        return self._blocks_list_gdm.get_num_blocks()

    def get_block(self, id: bytes) -> GenericBlock:

        # if index is passed instead of block_id, get block_id from index
        if isinstance(id, int):
            try:
                id = self.get_block_ids()[id]
            except IndexError:
                message = (
                    "Walytis_BetaAPI.Blockchain: Get Block from index: "
                    "Index out of range."
                )
                raise IndexError(message)
        else:
            id_bytearray = bytearray(id)
            len_id = len(id_bytearray)
            if bytearray([0, 0, 0, 0]) not in id_bytearray:  # if a short ID was passed
                short_id = None
                for long_id in self.get_block_ids():
                    if bytearray(long_id)[:len_id] == id_bytearray:
                        short_id = long_id
                        break
                if not short_id:
                    raise BlockNotFoundError()
                id = bytes(short_id)
        if isinstance(id, bytearray):
            id = bytes(id)
        try:
            block = self._blocks_list_gdm[id]
            return block
        except KeyError:

            error = BlockNotFoundError(
                "This block isn't recorded (by brenthy_api.Blockchain) as being "
                "part of this blockchain."
            )
            raise error

    def get_member_invitation_blocks(self):
        # TODO: ensure teh MemberInvitationBlock is in the correct place in the list of block topics
        # TODO: see if we should/can use get_info_blocks
        return [b for b in DidManager.get_blocks(self) if MemberInvitationBlock.walytis_block_topic in b.topics]

    def get_member_joining_blocks(self):
        # TODO: ensure teh MemberJoiningBlock is in the correct place in the list of block topics
        # TODO: see if we should/can use get_info_blocks
        return [b for b in DidManager.get_blocks(self) if MemberJoiningBlock.walytis_block_topic in b.topics]

    def get_member_update_blocks(self):
        # TODO: ensure teh MemberJoiningBlock is in the correct place in the list of block topics
        # TODO: see if we should/can use get_info_blocks
        return [b for b in DidManager.get_blocks(self) if MemberUpdateBlock.walytis_block_topic in b.topics]

    def generate_did_doc(self) -> dict:
        """Generate a DID-document."""
        did_doc = {
            "id": self.did,
            "verificationMethod": [
                self.get_control_key().generate_key_spec(
                    self.did)

                # key.generate_key_spec(self.did)
                # for key in self.keys
            ],
            # "service": [
            #     service.generate_service_spec() for service in self.services
            # ],
            "members": [
                member.to_dict()
                for member in self.get_members()
            ]
        }

        # check that components produce valid URIs
        validate_did_doc(did_doc)
        return did_doc

    def terminate(self):
        DidManager.terminate(self)
        for member in self.get_members():
            member.terminate()


class GroupDidManager(_GroupDidManager):
    """DidManager controlled by multiple member DIDs.

    Includes functionality for sharing of the Group DID's control key
    among the member DIDs.
    """

    def __init__(
        self,
        group_key_store: KeyStore,
        member: KeyStore | GenericDidManager,
        other_blocks_handler: Callable[[Block], None] | None = None,
        auto_load_missed_blocks: bool = True,
    ):
        self._terminate = False

        if not isinstance(group_key_store, KeyStore):
            raise TypeError(
                "The parameter `key_store` must be of type KeyStore, "
                f"not {type(group_key_store)}"
            )
        # assert that the key_store is unlocked
        group_key_store.key.get_private_key()

        if isinstance(member, KeyStore):
            self.member_did_manager = DidManager(
                key_store=member,
            )
        elif issubclass(type(member), GenericDidManager):
            self.member_did_manager = member
        else:
            raise TypeError(
                "The parameter `member` must be of type KeyStore or DidManager, "
                f"not {type(member)}"
            )
        # TODO: assert that member_did_manager is indeed a member of the GroupDidManager(group_key_store, member)

        _GroupDidManager.__init__(
            self,
            key_store=group_key_store,
            other_blocks_handler=other_blocks_handler,
            auto_load_missed_blocks=False,
        )
        self.candidate_keys: dict[str, list[str]] = {}
        self._terminate = False

        self.get_published_candidate_keys()

        self.key_requests_listener = ipfs.listen_for_conversations(
            f"{self.did}-KeyRequests",
            self.key_requests_handler
        )

        self.control_key_manager_thr = None
        self.member_keys_manager_thr = None

        if auto_load_missed_blocks:
            GroupDidManager.load_missed_blocks(self)

    def load_missed_blocks(self):
        _GroupDidManager.load_missed_blocks(self)
        if not self.control_key_manager_thr:
            self.control_key_manager_thr = Thread(
                target=self.manage_control_key
            )
            self.control_key_manager_thr.start()

        if not self.member_keys_manager_thr:
            self.member_keys_manager_thr = Thread(
                target=self.manage_member_keys
            )
            self.member_keys_manager_thr.start()

    @classmethod
    def create(
        cls,
        group_key_store: KeyStore | str,
        member: GenericDidManager | KeyStore,
        other_blocks_handler: Callable[[Block], None] | None = None,
    ):
        """Create a new GroupDidManager object.
        Args:
            group_key_store: KeyStore for this DidManager to store private keys
                    If a directory is passed, a KeyStore is created in there
                    named after the blockchain ID of the created DidManager.
        """

        if isinstance(member, KeyStore):
            logger.debug("GDM: Creating member DID manager...")
            member_did_manager = DidManager(
                key_store=member,
            )
        elif isinstance(member, GenericDidManager):
            member_did_manager = member
        else:
            raise TypeError(
                "The parameter `member` must be of type KeyStore, "
                f"not {type(member)}"
            )

        logger.debug("GDM: Creating Group Did-Manager...")
        g_did_manager = _GroupDidManager.create(group_key_store)
        g_did_manager.add_member(member)

        member_did_manager.key_store.add_key(g_did_manager.key_store.key)

        g_did_manager.terminate()  # group_did_manager will take over
        g_keystore = g_did_manager.key_store.reload()
        logger.debug("GDM: Loading GroupDidManager...")
        group_did_manager = cls(
            g_keystore,
            member_did_manager,
            other_blocks_handler=other_blocks_handler,
        )
        logger.debug("GDM: Generating DID-Doc...")
        group_did_manager.member_did_manager.update_did_doc(
            group_did_manager.generate_member_did_doc())
        logger.debug("GDM: Created DID-Manager!")
        return group_did_manager

    @classmethod
    def join(
        cls: Type[GroupDidManagerType],
        invitation: str | dict,
        group_key_store: KeyStore | str,
        member: KeyStore | GenericDidManager,
        other_blocks_handler: Callable[[Block], None] | None = None,
    ) -> GroupDidManagerType:
        """Join an exisiting Group-DID-Manager.


        Uses the provided DidManager as the member if provided,
        otherwise creates a new member DID.

        Args:
            group_key_store: KeyStore for this DidManager to store private keys
                    If a directory is passed, a KeyStore is created in there
                    named after the blockchain ID of the created DidManager.

        """

        if isinstance(member, KeyStore):
            member = DidManager(
                key_store=member,
            )
        elif isinstance(member, GenericDidManager):
            member = member
        else:
            raise TypeError(
                "The parameter `member` must be of type KeyStore, "
                f"not {type(member)}"
            )

        if isinstance(invitation, str):
            _invitation = json.loads(invitation)
        else:
            _invitation = invitation
        blockchain_invitation: dict = _invitation["blockchain_invitation"]

        # join blockchain
        try:
            # logger.debug(f"Joining blockchain {blockchain_invitation}")
            blockchain = Blockchain.join(blockchain_invitation)
        except BlockchainAlreadyExistsError:
            blockchain = Blockchain(blockchain_invitation["blockchain_id"])

        if isinstance(group_key_store, str):
            if not os.path.isdir(group_key_store):
                raise ValueError(
                    "If a string is passed for the `key_store` parameter, "
                    "it should be a valid directory"
                )
            # use blockchain ID instead of DID
            # as some filesystems don't support colons
            key_store_path = os.path.join(
                group_key_store, blockchain_invitation["blockchain_id"] + ".json"
            )
            group_key_store = KeyStore(
                key_store_path, Key.create(CRYPTO_FAMILY))

        blockchain.terminate()
        DidManager.assign_keystore(group_key_store, blockchain.blockchain_id)
        g_did_manager = _GroupDidManager(group_key_store)
        g_did_manager.make_member(
            invitation=_invitation,
            member=member
        )

        member.key_store.add_key(g_did_manager.key_store.key)
        g_did_manager.terminate()   # group_did_manager will take over from here
        group_key_store.reload()

        group_did_manager = cls(
            group_key_store,
            member,
            other_blocks_handler=other_blocks_handler,
        )

        group_did_manager.member_did_manager.update_did_doc(
            group_did_manager.generate_member_did_doc())

        return group_did_manager

    @classmethod
    def from_did_managers(
        cls,
        group_did_manager: DidManager,
        member_did_manager: DidManager,
        config_dir: str,
    ):
        return cls(
            group_did_manager.key_store,
            group_did_manager.key_store,
        )

    def assert_ownership(self) -> None:
        """If we don't yet own the control key, get it."""
        control_key = self.get_control_key()
        # logger.debug(self.get_control_key())
        # logger.debug(
        #     get_latest_control_key(self.blockchain).get_key_id()
        # )
        # logger.debug(self.blockchain._terminate)
        if control_key.private_key:
            # logger.debug(f"GDM: Already control key owner {self.did}")
            return

        # logger.debug(f"GDM: Not yet control key owner: {self.did}")
        while not self._terminate:
            # logger.debug(
            #     f"Num Members: {len(self.get_members(no_cache=True))} "
            #     f"{self.get_members()} {self.did}"
            # )
            for member in self.get_members():
                if self._terminate:
                    return
                did = member.did
                # if did == self.member_did_manager.did:
                #     continue
                logger.debug(f"Requesting control key from {did}")
                try:
                    key = self.request_key(control_key.get_key_id(), did)
                except IncompletePeerInfoError:
                    continue
                if key:
                    self.key_store.add_key(key)
                    if self.get_control_key().private_key:
                        self.update_did_doc(
                            self.generate_did_doc())
                        return
                    else:
                        logger.warning(
                            "Strange, Control key hasn't unlocked after key reception."
                        )
                logger.warning(
                    f"GDM: Request for control key failed. {self.did}")
            sleep(0.5)


    def manage_control_key(self):
        # logger.debug(f"Starting Control key manager for {self.did}")
        while not self._terminate:
            try:
                self.assert_ownership()
                time.sleep(1)
                self.check_prepare_control_key_update()
                self.check_apply_control_key_update()
            except Exception as e:
                traceback.format_exc()
                logger.warning(
                    f"Recovered from bug in manage_control_key:\n{e}")
            sleep(5)

    def manage_member_keys(self):
        while not self._terminate:
            try:
                for member in self._members.values():
                    if self._terminate:
                        return
                    try:
                        member._get_member_control_key()
                    except JoinFailureError:
                        pass
            except Exception as e:
                traceback.format_exc()
                logger.warning(
                    f"Recovered from bug in manage_member_keys\n{e}")
            if self._terminate:
                return
            sleep(5)

    def serialise(self) -> dict:
        """Generate this Identity's appdata."""
        return {
            "group_blockchain": self.blockchain.blockchain_id,
            "member_blockchain": self.member_did_manager.blockchain.blockchain_id,
        }

    def generate_member_did_doc(self) -> dict:
        """Generate a DID-document."""

        did_doc = {
            "id": self.member_did_manager.did,
            "verificationMethod": [
                self.member_did_manager.get_control_key().generate_key_spec(
                    self.member_did_manager.did)
                # key.generate_key_spec(self.did)
                # for key in self.keys
            ],
            # "service": [
            #     service.generate_service_spec() for service in self.services
            # ],
            "ipfs_peer_ids": list(self.get_my_member_ipfs_ids())
        }

        # check that components produce valid URIs
        validate_did_doc(did_doc)
        return did_doc

    def get_my_member_ipfs_ids(self,) -> set[str]:
        ipfs_ids = set()
        for member_info in get_members(self.member_did_manager.blockchain).values():
            ipfs_ids.update(Member.from_dict(
                member_info)._get_member_ipfs_ids())
        return ipfs_ids

    def get_member_ipfs_ids(self, member_did: str) -> set[str]:
        return self._members[member_did]._get_member_ipfs_ids()

    def get_ipfs_ids(self) -> set[str]:
        ipfs_ids = set()
        for member in self.get_members():
            ipfs_ids.update(member._get_member_ipfs_ids())
        return set(ipfs_ids)

    def publish_key_ownership(self, key: Key) -> None:
        """Publish a public key and proof that we have it's private key."""
        key_ownership = {
            "owner": self.member_did_manager.did,
            "key_id": key.get_key_id()
        }
        sig = bytes_to_string(key.sign(json.dumps(key_ownership).encode()))
        key_ownership.update({"proof": sig})
        block = KeyOwnershipBlock.new(key_ownership)
        self._gdm_add_info_block(block)

    def key_requests_handler(self, conv_name: str, peer_id: str) -> None:
        """Respond to key requests from other members."""
        logger.debug(f"KRH: Getting key request! {conv_name} {peer_id}")
        logger.debug("Joining conv...")
        try:
            conv = ipfs.join_conversation(
                conv_name,
                peer_id,
                conv_name,
                timeout_sec=SEND_TIMEOUT
            )
        except CommunicationTimeout:
            logger.warning("KRH: failed to join conversation")
            # conv.close()
            return
        if self._terminate:
            conv.close()
        logger.debug("Joined conv!")
        logger.debug("KRH: Joined conversation.")
        success = conv.say("Hello there!".encode())
        if self._terminate:
            conv.close()
        if not success:
            logger.debug("KRH: failed at salutation.")
            conv.terminate()
            return
        try:
            try:
                message = json.loads(conv.listen(
                    timeout=LISTEN_TIMEOUT).decode())
            except ConvListenTimeout:
                logger.warning("Timeout waiting for key request.")
                conv.close()
                return None
            if self._terminate:
                conv.close()
            logger.debug("KRH: got key request.")
            peer_did = message["did"] # member DID of peer who is requesting
            key_id = message["key_id"]
            sig = bytes.fromhex(message["signature"])

            message.pop("signature")
            try:
                logger.debug("Getting member control key...")
                peer_key = self.get_member_control_key(peer_did)
                logger.debug("Got member control key!")
            except NotMemberError as error:
                ## the peer requesting the key
                ## is not known to us to be a member of this GroupDidManager
                logger.warning(str(error))
                logger.debug(
                    "KRH: Sending NotMemberError. "
                    f"Num Members: {len(self.get_members())}"
                )
                success = conv.say(json.dumps({
                    "error": "NotMemberError",
                }).encode())
                conv.terminate()
                if not success:
                    logger.warning(
                        "KRH: Failed sending response NotMemberError")
                return
            logger.debug("KRH: got peer's key.")

            if not peer_key.verify_signature(sig, json.dumps(message).encode()):
                logger.debug("KRH: Sending AuthenitcationFailure")

                success = conv.say(json.dumps({
                    "error": "authenitcation failed",
                    "peer_key_id": peer_key.get_key_id()
                }).encode())
                conv.terminate()
                logger.warning("KRH: authentication failed.")
                if not success:
                    logger.warning(
                        "KRH: Failed sending response authentication failed.")
                return
            logger.debug("KRH: verified peer's request.")
            private_key = None
            try:
                key = self.key_store.get_key(key_id)
                private_key = key.private_key
            except UnknownKeyError:
                logger.debug("KRH: unknown private key!.")
                private_key = None

            if not private_key:
                logger.debug("KRH: Sending DontOwnKey")
                success = conv.say(json.dumps({
                    "error": "I don't own this key.",
                    "peer_key_id": peer_key.get_key_id()
                }).encode())
                conv.terminate()
                logger.warning(
                    f"KRH: Don't have requested key: {peer_key.get_key_id()}"
                )
                if not success:
                    logger.warning(
                        "KRH: Failed sending response I don't own this key")
                return

            logger.debug("KRH: Sending key!")
            success = conv.say(json.dumps({
                "private_key": peer_key.encrypt(private_key).hex()
            }).encode())
            if not success:
                logger.warning("KRH: Failed sending response with key.")
            else:
                logger.debug(f"KRH: Shared key!: {key.get_key_id()}")
            conv.terminate()

        except Exception as error:
            import traceback
            traceback.print_exc()
            logger.error(f"Error in key_requests_handler: {error}")
            conv.terminate()

    def get_member_control_key(self, did: str) -> Key:
        """Get the DID control key of another member."""
        members = [
            member for member in self.get_members()
            if member.did == did
        ]
        if not members:
            members = [
                member for member in self.get_members(no_cache=True)
                if member.did == did
            ]
        if not members:
            raise NotMemberError("This DID is not among our members.")
        member = members[0]
        return member._get_member_control_key()

    def get_member_did_doc(self, did: str) -> dict:
        """Get the DID control key of another member."""
        members = [
            member for member in self.get_members()
            if member.did == did
        ]
        if not members:
            members = [
                member for member in self.get_members(no_cache=True)
                if member.did == did
            ]
        if not members:
            raise NotMemberError("This DID is not among our members.")
        member = members[0]
        return member._get_member_did_doc()

    def request_key(self, key_id: str, other_member_did: str) -> Key | None:
        """Request a key from another member."""
        key = self.member_did_manager.get_control_key()
        key_request_message = {
            "did": self.member_did_manager.did,
            "key_id": key_id,
        }
        key_request_message.update({"signature": key.sign(
            json.dumps(key_request_message).encode()).hex()})
        count = 0
        for peer_id in self.get_member_ipfs_ids(other_member_did):
            if peer_id == ipfs.peer_id:
                continue
            count += 1
            logger.debug(
                f"RK: Requesting key from {other_member_did} for {key_id}..."
            )
            try:
                conv = None
                try:
                    conv = ipfs.start_conversation(
                        conv_name=f"KeyRequest-{key_id}",
                        peer_id=peer_id,
                        others_req_listener=f"{self.did}-KeyRequests",
                        timeout_sec=SEND_TIMEOUT
                    )
                except CommunicationTimeout:
                    logger.warning(
                        "RK: Failed to initiate key request (timeout): "
                        f"KeyRequest-{key_id}, "
                        f"{peer_id}, {other_member_did}-KeyRequests"
                        f"\nRequested key for {other_member_did} "
                        f"from {peer_id}"
                    )
                    # conv.close()
                    continue
                if self._terminate:
                    conv.close()
                logger.debug("RK: started conversation")

                try:
                    # receive salutation
                    _ = conv.listen(timeout=LISTEN_TIMEOUT)
                except ConvListenTimeout:
                    logger.warning("RK: Timeout waiting for salutation.")
                    conv.close()
                    continue
                if self._terminate:
                    conv.close()
                logger.debug("RK: requesting key...")
                sleep(0.15)
                success = conv.say(json.dumps(key_request_message).encode(), )
                if self._terminate:
                    conv.close()
                if not success:
                    logger.warning(
                        "RK: Timeout communicating when requesting key.")
                    conv.close()
                    continue
                logger.debug("RK: awaiting response...")
                try:
                    response = json.loads(conv.listen(
                        timeout=LISTEN_TIMEOUT).decode())
                except ConvListenTimeout:
                    logger.warning(
                        "RK: Timeout waiting for key response."
                        f"KeyRequest-{key_id}, "
                        f"{peer_id}, {other_member_did}-KeyRequests"
                        f"\nRequested key for {other_member_did} "
                        f"from {peer_id}"
                    )

                    conv.close()
                    continue
                if self._terminate:
                    conv.close()
                logger.debug("RK: Got Response!")
                conv.close()

            except Exception as error:
                # logger.warning(traceback.format_exc())
                logger.warning(
                    f"RK: Error in request_key: {type(error)} {error}")
                if conv:
                    conv.close()
                continue

            if "error" in response.keys():
                logger.warning(response)
                continue
            private_key = key.decrypt(bytes.fromhex(response["private_key"]))
            key = Key.from_key_id(key_id)
            key.unlock(private_key)
            self.key_store.add_key(key)
            self.publish_key_ownership(key)
            logger.debug(f"RK: Got key!: {key.get_key_id()}")
            return key
        logger.debug(
            f"RK: Failed to get key for {other_member_did} "
            f"after asking {count} peers"
        )
        return None

    def get_published_candidate_keys(self) -> dict["str", list[str]]:
        """Update our list of candidate control keys and their owners."""
        candidate_keys: dict[str, list[str]] = {}
        for block in (self.blockchain.get_blocks(reverse=True)):
            if KeyOwnershipBlock.walytis_block_topic not in block.topics:
                continue
            key_expiry = (
                self.get_control_key().creation_time +
                timedelta(hours=CTRL_KEY_RENEWAL_AGE_HR)
            )
            if block.creation_time < key_expiry:
                key_ownership = KeyOwnershipBlock.load_from_block_content(
                    block.content
                ).get_key_ownership()
                key_id = key_ownership["key_id"]
                owner = key_ownership["owner"]

                key = Key.from_key_id(key_id)
                proof = string_to_bytes(key_ownership["proof"])
                key_ownership.pop("proof")

                if not key.verify_signature(proof, json.dumps(key_ownership).encode()):
                    logger.warning(
                        "Found key ownership block with invalid proof."
                    )
                    continue

                if key_id in candidate_keys.keys():
                    candidate_keys[key_id] += owner
                else:
                    candidate_keys.update({owner: owner})
        self.candidate_keys = candidate_keys
        return candidate_keys

    def check_prepare_control_key_update(self) -> bool:
        """Check if we should prepare to renew our DID-manager's control key.

        Generates new control key and shares it with other members,
        doesn't update the DID-Manager though

        Returns:
            Whether or not we are now prepared to renew control keys
        """
        # logger.debug("Checking control key update preparation...")
        ctrl_key_timestamp = self.get_control_key().creation_time
        ctrl_key_age_hr = (
            datetime.utcnow() - ctrl_key_timestamp
        ).total_seconds() / 60 / 60

        # if control key isn't too old yet
        if ctrl_key_age_hr < CTRL_KEY_RENEWAL_AGE_HR:
            self.candidate_keys = {}
            return False

        # refresh our list of published candidate_keys
        self.get_published_candidate_keys()

        # if we already have a control key candidate
        if self.candidate_keys:
            # try get the private keys of any candidate keys we don't yet own
            for key_id, members in list(self.candidate_keys.items()):
                if key_id not in self.key_store.keys.keys():
                    for member in members:
                        if self._terminate:
                            return True
                        # if member == self.member_did_manager.did:
                        #     continue
                        key = self.request_key(key_id, member)
                        if key:
                            self.candidate_keys[key_id] += self.member_did_manager.did
                            break
            return True

        key = Key.create(CRYPTO_FAMILY)
        self.key_store.add_key(key)
        self.candidate_keys.update(
            {key.get_key_id(): [self.member_did_manager.did]}
        )

        self.publish_key_ownership(key)
        return True

    def check_apply_control_key_update(self) -> bool:
        """Check if we should renew our DID-manager's control key."""
        # logger.debug("Checking control key update application...")
        if not self.candidate_keys:
            return False

        ctrl_key_timestamp = self.get_control_key().creation_time
        ctrl_key_age_hr = (
            datetime.utcnow() - ctrl_key_timestamp
        ).total_seconds() / 60 / 60

        new_control_key = ""
        num_key_owners = 1
        # if control key isn't too old yet
        if (ctrl_key_age_hr
                < CTRL_KEY_RENEWAL_AGE_HR + CTRL_KEY_MAX_RENEWAL_DUR_HR):
            for key_id, owners in list(self.candidate_keys.items()):
                nko = len(self.candidate_keys[key_id])
                if nko > num_key_owners:
                    num_key_owners = nko
                    new_control_key = key_id

                    if num_key_owners >= len(self.get_members()):
                        break
            # if not all members have the same candidate key yet,
            # we'll wait a little longer
            if num_key_owners < len(self.get_members()):
                return False

        self.renew_control_key(new_control_key)
        self.candidate_keys = {}
        return True

    def delete(self, terminate_member: bool = True) -> None:
        """Delete this Identity."""
        GroupDidManager.terminate(self, terminate_member=terminate_member)
        if terminate_member:
            self.member_did_manager.delete()
        DidManager.delete(self)

    def terminate(self, terminate_member: bool = True) -> None:
        """Stop this Identity object, cleaning up resources."""
        if not self._terminate:
            self._terminate = True
            try:
                logger.debug("GDM: terminating key_requests_listener...")
                self.key_requests_listener.terminate()
            except Exception as e:
                logger.warning(f"GDM TERMINATING: {e}")
                pass
            try:
                logger.debug("GDM: terminating member_keys_manager_thr...")
                if self.member_keys_manager_thr:
                    self.member_keys_manager_thr.join()

            except Exception as e:
                logger.warning(f"GDM TERMINATING: {e}")
                pass
            try:
                logger.debug("GDM: terminating control_key_manager_thr...")
                if self.control_key_manager_thr:
                    self.control_key_manager_thr.join()

            except Exception as e:
                logger.warning(f"GDM TERMINATING: {e}")
                pass
            try:
                if terminate_member:
                    logger.debug("GDM: terminating member_did_manager...")
                    self.member_did_manager.terminate()
            except Exception as e:
                logger.warning(f"GDM TERMINATING: {e}")
                pass
            try:
                logger.debug("GDM: terminating DidManager...")
                DidManager.terminate(self)
            except Exception as e:
                logger.warning(f"GDM TERMINATING: {e}")
                pass
            
            
        logger.debug("GDM: terminating _GroupDidManager...")
        _GroupDidManager.terminate(self)
        logger.debug("GDM: terminated!")
        

    def __del__(self):
        """Stop this Identity object, cleaning up resources."""
        self.terminate()


class IncompletePeerInfoError(Exception):
    """When a peer's DID document doesn't contain all the info we need."""


class NotMemberError(Exception):
    """When a peer isn't among our members."""


class IdentityJoinError(Exception):
    """When `DidManager.make_member()` fails."""

    def __init__(self, message: str):
        self.message = message

    def __str__(self):
        return self.message
# decorate_all_functions(strictly_typed, __name__)
