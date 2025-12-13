"""Classes for managing Person and Device identities."""

from .utils import generate_random_string
from hashlib import sha256
from . import settings
from .datatransmission import (
    COMMS_TIMEOUT_S,
    ChallengeFailedError,
    HandshakeFailedError,
)
from .utils import string_to_time
from .key_store import CodePackage
from ipfs_tk_transmission import Conversation
from .utils import NUM_ACTIVE_CONTROL_KEYS, NUM_NEW_CONTROL_KEYS
from .log import logger_gdm_join, logger_gdm as logger, logger_ckm
from threading import Event
from walytis_beta_api import Blockchain, join_blockchain_from_zip
from dataclasses_json import dataclass_json
from dataclasses import dataclass
from . import datatransmission
from .datatransmission import CHALLENGE_STRING_LENGTH
import json
import os
import random
import time
import traceback
from collections.abc import Generator
from datetime import datetime, timedelta, UTC
from random import randint
from threading import Lock, Thread
from time import sleep
from typing import Callable, Type, TypeVar
import ipfs_tk_transmission
import walytis_beta_tools
from brenthy_tools_beta.utils import bytes_to_string, string_to_bytes
from ipfs_tk_transmission.errors import CommunicationTimeout, ConvListenTimeout
from walytis_beta_api import (
    Block,
    Blockchain,
    list_blockchain_ids,
)
from walytis_beta_api._experimental.generic_blockchain import (
    GenericBlock,
)
from walytis_beta_api.exceptions import BlockNotFoundError
from walytis_beta_embedded import ipfs
from walytis_beta_tools._experimental.block_lazy_loading import (
    BlockLazilyLoaded,
    BlocksList,
)
from walytis_beta_tools.exceptions import (
    BlockchainAlreadyExistsError,
    JoinFailureError,
)

from . import did_manager_blocks
from .did_manager import DidManager, blockchain_id_from_did, CTRL_KEY_FAMILIES
from .did_manager_blocks import (
    InfoBlock,
    KeyOwnershipBlock,
    MemberJoiningBlock,
    MemberLeavingBlock,
    MemberUpdateBlock,
    get_block_type,
    get_control_keys_history,
    get_latest_control_key,
    get_control_key_age,
    get_latest_did_doc,
    get_members,
)
from .key_objects import Key, KeyGroup
from .generic_did_manager import GenericDidManager
from .key_store import KeyStore, UnknownKeyError
from .settings import (
    CTRL_KEY_MAX_RENEWAL_DUR_HR,
    CTRL_KEY_RENEWAL_AGE_HR,
    CTRL_KEY_RENEWAL_RANDOMISER_MAX,
    CTRL_KEY_MGMT_PERIOD,
)
from .utils import validate_did_doc
from ipfs_tk_transmission.errors import PeerNotFound as PeerNotFoundError

random.seed(datetime.now(UTC).microsecond)


WALYTIS_BLOCK_TOPIC = "GroupDidManager"

CRYPTO_FAMILY = "EC-secp256k1"
INVITATION_KEY_FAMILY = "EC-secp256k1"
GroupDidManagerType = TypeVar("GroupDidManagerType", bound="GroupDidManager")


class Member:
    did: str
    invitation: str
    _blockchain: Blockchain | None

    def __init__(
        self, did: str, invitation: str, blockchain: Blockchain = None
    ):
        self.did = did
        self.invitation = invitation
        self._blockchain_lock = Lock()
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
        print("DEPRECATED: Member.blockchain")
        import traceback

        print("    ".join(traceback.format_stack()))
        return self.get_blockchain()

    def get_blockchain(self) -> Blockchain:
        with self._blockchain_lock:
            if self._blockchain:
                return self._blockchain
            self._blockchain = self._get_member_blockchain()
            if not self._blockchain:
                raise MemberBlockchainNotJoinedError()
            return self._blockchain

    def _get_member_ipfs_ids(self) -> set[str]:
        did_doc = self._get_member_did_doc()
        ipfs_ids: list[str] | None = did_doc.get("ipfs_peer_ids")

        if not ipfs_ids:
            # TODO: find better way of getting DidManager's peer ID than blockchain invitation?
            ipfs_ids = json.loads(self.invitation)["peers"]
        return set(ipfs_ids)

    def _get_member_did_doc(
        self,
    ) -> dict:
        did_doc = get_latest_did_doc(self.get_blockchain())
        return did_doc

    def _get_member_control_key(self) -> KeyGroup:
        return get_latest_control_key(self.get_blockchain())

    def _get_member_control_keys(self) -> list[KeyGroup]:
        return get_control_keys_history(self.get_blockchain())

    def _get_control_key_age(self, key_id: str) -> int:
        return get_control_key_age(self.get_blockchain(), key_id)

    def is_control_key_active(self, key_id: str) -> bool:
        return self._get_control_key_age(key_id) < NUM_ACTIVE_CONTROL_KEYS

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
            except BlockchainAlreadyExistsError:
                blockchain = Blockchain(blockchain_id)
            except CommunicationTimeout:
                try:
                    blockchain = Blockchain.join(self.invitation)
                except (
                    Exception,
                    BlockchainAlreadyExistsError,
                    walytis_beta_tools.exceptions.BlockchainAlreadyExistsError,
                ):
                    blockchain = Blockchain(blockchain_id)
            logger.debug(f"GDM: joined member's blockchain! {self.did}")
        else:
            # logger.debug("Loading member blockchain...")
            blockchain = Blockchain(blockchain_id)
        # logger.debug("Got member blockchain!")
        return blockchain

    def encrypt(self, data: bytes, encryption_options: str = "") -> bytes:
        """Encrypt the provided data using the specified public key.

        Args:
            data_to_encrypt (bytes): the data to encrypt
            encryption_options (str): specification code for which
                                    encryption/decryption protocol should be used
        Returns:
            bytes: the encrypted data
        """
        return self._key_store.encrypt(
            data=data,
            key=self._get_control_key(),
            encryption_options=encryption_options,
        ).serialise_bytes()

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
        self.member_invitations: list[InvitationManager] = []
        self.load_invitations()
        self.get_members(no_cache=True)
        if auto_load_missed_blocks:
            _GroupDidManager.load_missed_blocks(self)

    def load_missed_blocks(self):
        DidManager.load_missed_blocks(self)

    def _gdm_add_info_block(self, block: InfoBlock) -> Block:
        """Add an InfoBlock type block to this DID-Block's blockchain."""
        if not block.signature:
            block.sign(self.get_control_keys())
        return self.blockchain.add_block(
            block.generate_block_content(),
            [WALYTIS_BLOCK_TOPIC, block.walytis_block_topic],
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
                case _:
                    logger.warning(
                        "This block is marked as belong to GroupDidManager, "
                        "but it's InfoBlock type is not handled: "
                        f"{block.topics}"
                    )
        else:
            # logger.info(f"GDM: passing on received block: {block.topics}")
            self._blocks_list_gdm.add_block(
                BlockLazilyLoaded.from_block(block)
            )

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
        self._members = dict(
            [
                (member_info["did"], Member.from_dict(member_info))
                for member_info in get_members(self.blockchain).values()
            ]
        )

    def get_members(self, no_cache: bool = False) -> list[Member]:
        """Get the current list of member-members."""
        if no_cache or not self._members:
            self._update_members()

        return list(self._members.values())

    def get_members_dict(self, no_cache: bool = False) -> dict[Member]:
        """Get the current list of member-members."""
        if no_cache or not self._members:
            self._update_members()

        return self._members

    def get_members_dids(self, no_cache: bool = False) -> set[str]:
        if no_cache or not self._members:
            self._update_members()
        return set(self._members.keys())

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
        invitation = InvitationManager.create(self)
        self.member_invitations.append(invitation)
        self.save_invitations()
        return invitation.generate_code().serialise_dict()

    def save_invitations(self) -> None:
        data = [
            invitation.serialise() for invitation in self.member_invitations
        ]
        with open(self._get_invitations_file(), "w+") as file:
            file.write(json.dumps(data))

    def load_invitations(self) -> None:
        if self.member_invitations:
            raise Exception("MemberInvitations already loaded")
        if os.path.exists(self._get_invitations_file()):
            with open(self._get_invitations_file(), "r") as file:
                data = json.loads(file.read())
            self.member_invitations = [
                InvitationManager.deserialise(self, inv) for inv in data
            ]

    def _get_invitations_file(self) -> str:
        return os.path.join(
            os.path.dirname(self.key_store.key_store_path),
            f"member_invitations-{self.blockchain.blockchain_id}.json",
        )

    def load_invitation(self, key: Key) -> dict:
        """Create and register a member invitation on the blockchain."""
        invitation = InvitationManager(self, key)
        self.member_invitations.append(invitation)
        self.save_invitations()
        return invitation.generate_code().serialise_dict()

    def add_member(self, member: GenericDidManager) -> None:
        """Add an existing DID-Manager as a member to this Group-DID."""
        logger.debug("GDM: Adding DidManager as member...")

        joining_block = MemberJoiningBlock.new(
            {
                "did": member.did,
                "invitation": member.blockchain.create_invitation(
                    one_time=False, shared=True
                ),  # invitation for other's to join our member DID blockchain
            }
        )
        self.get_control_keys().sign(member.did.encode())
        self._gdm_add_info_block(joining_block)
        member.key_store.add_key(self.get_control_keys())

        if self.get_control_keys().is_unlocked():
            self.update_did_doc(self.generate_did_doc())
        logger.debug("GDM: Added DidManager as member!")

    def _init_blocks_list_gdm(self):
        # present to other programs all blocks not created by this DidManager
        blocks = [
            block
            for block in DidManager.get_blocks(self)
            if WALYTIS_BLOCK_TOPIC not in block.topics
            and block.topics != ["genesis"]
        ]
        self._blocks_list_gdm = BlocksList.from_blocks(
            blocks, BlockLazilyLoaded
        )

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
            if (
                bytearray([0, 0, 0, 0]) not in id_bytearray
            ):  # if a short ID was passed
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

    def get_member_joining_blocks(self):
        # TODO: ensure teh MemberJoiningBlock is in the correct place in the list of block topics
        # TODO: see if we should/can use get_info_blocks
        return [
            b
            for b in DidManager.get_blocks(self)
            if MemberJoiningBlock.walytis_block_topic in b.topics
        ]

    def get_member_update_blocks(self):
        # TODO: ensure teh MemberJoiningBlock is in the correct place in the list of block topics
        # TODO: see if we should/can use get_info_blocks
        return [
            b
            for b in DidManager.get_blocks(self)
            if MemberUpdateBlock.walytis_block_topic in b.topics
        ]

    def generate_did_doc(self) -> dict:
        """Generate a DID-document."""
        did_doc = {
            "id": self.did,
            "verificationMethod": self.get_control_keys().generate_key_specs(
                self.did
            ),
            # "service": [
            #     service.generate_service_spec() for service in self.services
            # ],
            "members": [member.to_dict() for member in self.get_members()],
        }

        # check that components produce valid URIs
        validate_did_doc(did_doc)
        return did_doc

    def get_peers(self) -> list[str]:
        """Get IPFS peer IDs of nodes that are part of or watching this GDM.

        This list may be sorted in the future.

        Returns:
            A list of IPFS peer IDs.
        """
        peer_ids = []
        for member_did in self.get_members_dids():
            for peer_id in self.get_member_ipfs_ids(member_did):
                if peer_id not in peer_ids:
                    peer_ids.append(peer_id)
        return peer_ids

    def terminate(self) -> None:
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
        allow_locked=False,  # only used in auto_load_missed_blocks==True
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
        self.CTRL_KEY_RENEWAL_RANDOMISER = randint(
            0, CTRL_KEY_RENEWAL_RANDOMISER_MAX
        )
        self._terminate = False

        self.get_published_candidate_keys()

        self.key_requests_listener = datatransmission.listen_for_conversations(
            self, f"{self.did}-KeyRequests", self.key_requests_handler
        )

        self.control_key_manager_thr = None
        self.member_keys_manager_thr = None

        if auto_load_missed_blocks:
            GroupDidManager.load_missed_blocks(self, allow_locked=allow_locked)

    def load_missed_blocks(self, allow_locked: bool = False):
        _GroupDidManager.load_missed_blocks(self)
        if not allow_locked:
            if not self.get_control_keys().is_unlocked():
                error_message = "This GDM has no unlocked control keys."
                logger.error(error_message)
                raise Exception(error_message)
        if not self.control_key_manager_thr:
            self.control_key_manager_thr = Thread(
                target=self.manage_control_key, name="GDM-control_key_manager"
            )
            self.control_key_manager_thr.start()

        if not self.member_keys_manager_thr:
            self.member_keys_manager_thr = Thread(
                target=self.manage_member_keys, name="GDM-member_keys_manager"
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

        key = g_did_manager.get_control_keys()
        logger.debug(key)
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
            group_did_manager.generate_member_did_doc()
        )
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
        join_process = JoinProcess(
            invitation=invitation,
            group_key_store=group_key_store,
            member=member,
            other_blocks_handler=other_blocks_handler,
        )
        join_process.joined.wait()
        if join_process.error_message:
            raise GdmJoinFailureError(join_process.error_message)
        return join_process.group_did_manager

    @classmethod
    def _join_from_blockchain(
        cls: Type[GroupDidManagerType],
        blockchain: Blockchain,
        group_key_store: KeyStore | str,
        member: KeyStore | GenericDidManager,
        other_blocks_handler: Callable[[Block], None] | None = None,
    ) -> GroupDidManagerType:
        """Join an exisiting Group-DID-Manager given its blockchain.

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

        if isinstance(group_key_store, str):
            if not os.path.isdir(group_key_store):
                raise ValueError(
                    "If a string is passed for the `key_store` parameter, "
                    "it should be a valid directory"
                )
            # use blockchain ID instead of DID
            # as some filesystems don't support colons
            key_store_path = os.path.join(
                group_key_store,
                f"{blockchain.blockchain_id}.json",
            )
            group_key_store = KeyStore(
                key_store_path, Key.create(CRYPTO_FAMILY)
            )

        blockchain.terminate()
        DidManager.assign_keystore(group_key_store, blockchain.blockchain_id)
        g_did_manager = _GroupDidManager(group_key_store)
        g_did_manager.add_member(member=member)

        member.key_store.add_key(g_did_manager.key_store.key)
        g_did_manager.terminate()  # group_did_manager will take over from here
        group_key_store.reload()

        group_did_manager = cls(
            group_key_store,
            member,
            other_blocks_handler=other_blocks_handler,
        )

        group_did_manager.member_did_manager.update_did_doc(
            group_did_manager.generate_member_did_doc()
        )

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
        control_key = self.get_control_keys()
        # logger.debug(self.get_control_keys())
        # logger.debug(
        #     get_latest_control_key(self.blockchain).get_id()
        # )
        # logger.debug(self.blockchain._terminate)
        if control_key.is_unlocked():
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
                key = None
                try:
                    key = self.request_key(control_key.get_id(), did)
                except IncompletePeerInfoError as e:
                    logger.debug(e)
                    continue
                except Exception as e:
                    logger.error(e)
                if key:
                    self.key_store.add_key(key)
                    if self.get_control_keys().is_unlocked():
                        self.update_did_doc(self.generate_did_doc())
                        return
                    else:
                        logger.warning(
                            "Strange, Control key hasn't unlocked after key reception."
                        )
                logger.warning(
                    f"GDM: Request for control key failed. {self.did}"
                )
            if not sleep(0.5):
                return

    def manage_control_key(self):
        # logger.debug(f"Starting Control key manager for {self.did}")
        while not self._terminate:
            try:
                self.assert_ownership()
                if not self.sleep(1):
                    return
                # refresh our list of published candidate_keys
                self.get_published_candidate_keys()
                self.check_prepare_control_key_update()
                self.check_apply_control_key_update()
            except Exception as e:
                logger_ckm.error(traceback.format_exc())
                logger_ckm.error(
                    f"Recovered from bug in manage_control_key:\n{e}"
                )
            if not self.sleep(CTRL_KEY_MGMT_PERIOD):
                return

    def sleep(self, sleep_dur_sec: float) -> bool:
        """Sleep with centisecond precision, to be interrupted if self._terminate."""
        for i in range(round(sleep_dur_sec * 100)):
            if self._terminate:
                return False
            sleep(0.01)
        if self._terminate:
            return False
        return True

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
                logger_ckm.error(traceback.format_exc())
                logger_ckm.error(
                    f"Recovered from bug in manage_member_keys\n{e}"
                )
            if self._terminate:
                return
            if not self.sleep(5):
                return

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
            "verificationMethod": self.member_did_manager.get_control_keys().generate_key_specs(
                self.member_did_manager.did
            ),
            # "service": [
            #     service.generate_service_spec() for service in self.services
            # ],
            "ipfs_peer_ids": list(self.get_my_member_ipfs_ids()),
        }

        # check that components produce valid URIs
        validate_did_doc(did_doc)
        return did_doc

    def get_my_member_ipfs_ids(
        self,
    ) -> set[str]:
        ipfs_ids = set()
        for member_info in get_members(
            self.member_did_manager.blockchain
        ).values():
            ipfs_ids.update(
                Member.from_dict(member_info)._get_member_ipfs_ids()
            )
        return ipfs_ids

    def get_member_ipfs_ids(self, member_did: str) -> set[str]:
        return self._members[member_did]._get_member_ipfs_ids()

    def get_ipfs_ids(self) -> set[str]:
        ipfs_ids = set()
        for member in self.get_members():
            ipfs_ids.update(member._get_member_ipfs_ids())
        return set(ipfs_ids)

    def publish_key_ownership(self, key: KeyGroup) -> None:
        """Publish a public key and proof that we have it's private key."""
        key_ownership = {
            "owner": self.member_did_manager.did,
            "key_id": key.get_id(),
        }
        sig = bytes_to_string(key.sign(json.dumps(key_ownership).encode()))
        key_ownership.update({"proof": sig})
        block = KeyOwnershipBlock.new(key_ownership)
        self._gdm_add_info_block(block)

    def key_requests_handler(self, conv: Conversation) -> None:
        """Respond to key requests from other members."""
        logger_ckm.debug(f"KRH: Getting key request!")
        # double-check communications are encrypted
        assert conv._encryption_callback is not None
        assert conv._decryption_callback is not None

        logger_ckm.start_recording("KEY_REQUESTS_HANDLER")
        try:
            if self._terminate:
                return
            logger_ckm.debug("KRH: Joined conversation.")
            assert conv.say("Hello there!".encode())
            if self._terminate:
                return

            message = json.loads(conv.listen(timeout=COMMS_TIMEOUT_S).decode())
            if self._terminate:
                return
            logger_ckm.debug("KRH: got key request.")
            key_id = message["key_id"]

            key = None
            try:
                key = self.key_store.get_generic_key(key_id)
            except UnknownKeyError:
                logger_ckm.debug("KRH: unknown private key!.")
                return

            if not (key and key.is_unlocked()):
                logger_ckm.debug("KRH: Sending DontOwnKey")
                assert conv.say(
                    json.dumps(
                        {
                            "error": "I don't own this key.",
                            "key_id": key_id,
                        }
                    ).encode()
                )
                logger_ckm.warning(
                    f"KRH: Don't have requested key: {key_id[:30]}"
                )
                return

            logger_ckm.debug("KRH: Sending key!")
            assert conv.say(
                json.dumps({"key": key.serialise_private()}).encode()
            )
            logger_ckm.debug(f"KRH: Shared key!: {key.get_id()[:30]}")

        except ConvListenTimeout:
            logger_ckm.warning(
                "KRH: Timeout in key request handler."
                f"\n{logger_ckm.get_recording('KEY_REQUESTS_HANDLER')}"
            )

        except Exception as error:
            logger_ckm.error(
                f"\n{logger_ckm.get_recording('KEY_REQUESTS_HANDLER')}"
                f"\n{traceback.format_exc()}"
                f"RK: Error in request_key: {type(error)} {error}"
            )
        finally:
            if conv:
                conv.terminate()
            logger_ckm.stop_recording("KEY_REQUESTS_HANDLER")

    def get_member_control_key(self, did: str) -> KeyGroup:
        """Get the DID control key of another member."""
        members = [
            member for member in self.get_members() if member.did == did
        ]
        if not members:
            members = [
                member
                for member in self.get_members(no_cache=True)
                if member.did == did
            ]
        if not members:
            raise NotMemberError("This DID is not among our members.")
        member = members[0]
        return member._get_member_control_key()

    def get_member_did_doc(self, did: str) -> dict:
        """Get the DID control key of another member."""
        members = [
            member for member in self.get_members() if member.did == did
        ]
        if not members:
            members = [
                member
                for member in self.get_members(no_cache=True)
                if member.did == did
            ]
        if not members:
            raise NotMemberError("This DID is not among our members.")
        member = members[0]
        return member._get_member_did_doc()

    def request_key(
        self, key_id: str, other_member_did: str
    ) -> KeyGroup | None:
        """Request a key from another member."""
        key_request_message = {
            "key_id": key_id,
        }
        count = 0
        for peer_id in self.get_member_ipfs_ids(other_member_did):
            if peer_id == ipfs.peer_id:
                continue
            count += 1
            logger_ckm.debug(
                f"RK: Requesting key from {other_member_did} for "
                f"{key_id[:30]}..."
            )

            # collect debug logs in case we encounter error
            logger_ckm.start_recording("KEY_REQUESTS")

            conv = None
            try:
                conv = datatransmission.start_conversation(
                    self,
                    conv_name=(
                        f"KeyRequest-{sha256(key_id.encode()).hexdigest()}"
                    ),
                    peer_id=peer_id,
                    others_req_listener=f"{self.did}-KeyRequests",
                )
                # double-check communications are encrypted
                assert conv._encryption_callback is not None
                assert conv._decryption_callback is not None

                if self._terminate:
                    return
                logger_ckm.debug("RK: started conversation")

                # receive salutation
                salute = conv.listen(timeout=COMMS_TIMEOUT_S)
                assert salute == "Hello there!".encode()

                if self._terminate:
                    return
                logger_ckm.debug("RK: requesting key...")
                assert conv.say(
                    json.dumps(key_request_message).encode(),
                )
                if self._terminate:
                    return
                logger_ckm.debug("RK: awaiting response...")
                response = json.loads(
                    conv.listen(timeout=COMMS_TIMEOUT_S).decode()
                )
                if self._terminate:
                    return
                logger_ckm.debug("RK: Got Response!")

            except ConvListenTimeout:
                logger_ckm.warning(
                    "RK: Timeout in key request."
                    f"KeyRequest-{key_id[:30]}, "
                    f"{peer_id}, {other_member_did}-KeyRequests"
                    f"\nRequested key for {other_member_did} "
                    f"from {peer_id}"
                    f"\n{logger_ckm.get_recording('KEY_REQUESTS')}"
                )

                continue
            except Exception as error:
                logger_ckm.error(
                    f"\n{logger_ckm.get_recording('KEY_REQUESTS')}"
                    f"\n{traceback.format_exc()}"
                    f"RK: Error in request_key: {type(error)} {error}"
                )
                continue
            finally:
                if conv:
                    conv.terminate()
                logger_ckm.stop_recording("KEY_REQUESTS")

            if "error" in response.keys():
                logger_ckm.warning(response)
                continue
            key = KeyGroup.deserialise_private(response["key"])
            if not key.get_id() == key_id:
                logger_ckm.warning("RK: Received wrong key.")
                continue
            self.key_store.add_keygroup(key)
            self.publish_key_ownership(key)
            logger_ckm.debug(f"RK: Got key!: {key.get_id()[:30]}")
            return key
        logger_ckm.debug(
            f"RK: Failed to get key for {other_member_did} "
            f"after asking {count} peers"
        )
        return None

    def get_published_candidate_keys(self) -> dict["str", list[str]]:
        """Update our list of candidate control keys and their owners."""
        # logger_ckm.debug("Updating candidate keys...")
        candidate_keys: dict[str, list[str]] = {}
        for block in self.blockchain.get_blocks(reverse=True):
            if KeyOwnershipBlock.walytis_block_topic not in block.topics:
                continue
            if (
                block.creation_time
                - self.get_control_keys().keys[0].creation_time
            ).total_seconds() > 0:
                key_ownership = KeyOwnershipBlock.load_from_block_content(
                    block.content
                ).get_key_ownership()
                key_id = key_ownership["key_id"]
                owner = key_ownership["owner"]

                # filter out keys that have already been used as control keys
                if key_id in [
                    key.get_id() for key in self.get_control_keys_history()
                ]:
                    continue

                key = KeyGroup.from_id(key_id)
                proof = string_to_bytes(key_ownership["proof"])
                key_ownership.pop("proof")

                if not key.verify_signature(
                    proof, json.dumps(key_ownership).encode()
                ):
                    logger_ckm.warning(
                        "Found key ownership block with invalid proof."
                    )
                    continue

                if key_id in candidate_keys.keys():
                    candidate_keys[key_id].append(owner)
                else:
                    candidate_keys.update({key_id: [owner]})
        self.candidate_keys = candidate_keys
        return candidate_keys

    def check_prepare_control_key_update(self) -> bool:
        """Check if we should prepare to renew our DID-manager's control key.

        Generates new control key and shares it with other members,
        doesn't update the DID-Manager though

        Returns:
            Whether or not we are now prepared to renew control keys
        """
        # logger_ckm.debug(
        #     "Checking control key update preparation "
        #     f"{len(self.candidate_keys)}"
        # )
        ctrl_key_timestamp = self.get_control_keys().keys[0].creation_time
        ctrl_key_age_hr = (
            (datetime.now(UTC) - ctrl_key_timestamp).total_seconds() / 60 / 60
        )

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
                            self.candidate_keys[key_id].append(
                                self.member_did_manager.did
                            )
                            break
            return True

        # we don't have any candidate keys from other memebers

        self.CTRL_KEY_RENEWAL_RANDOMISER = randint(
            0, CTRL_KEY_RENEWAL_RANDOMISER_MAX
        )
        if (
            ctrl_key_age_hr
            > CTRL_KEY_RENEWAL_AGE_HR + self.CTRL_KEY_RENEWAL_RANDOMISER
        ):
            self.initiate_control_key_update()
            return True
        return False

    def initiate_control_key_update(self):
        """Initiate a control key update process.

        Generates new control key and shares it with other members,
        doesn't update the DID-Manager though

        Returns:
            Whether or not we are now prepared to renew control keys
        """
        logger_ckm.debug("Initiating control key update...")
        key = KeyGroup.create(CTRL_KEY_FAMILIES)
        self.key_store.add_keygroup(key)
        self.candidate_keys.update(
            {key.get_id(): [self.member_did_manager.did]}
        )

        self.publish_key_ownership(key)

    def check_apply_control_key_update(self) -> bool:
        """Check if we should renew our DID-manager's control key.

        Renews our DidManager's control key if the new key has already been shared
        with all peers or the current keys have reached a critical age.
        """
        logger_ckm.debug(
            "Checking control key update application: "
            f"{len(self.candidate_keys)}"
        )
        if not self.candidate_keys:
            return False

        ctrl_key_timestamp = self.get_control_keys().keys[0].creation_time
        ctrl_key_age_hr = (
            (datetime.now(UTC) - ctrl_key_timestamp).total_seconds() / 60 / 60
        )

        new_control_key = None
        num_key_owners = 0
        # if control key isn't too old yet
        # look for key with the most key owners
        for key_id, owners in list(self.candidate_keys.items()):
            # exclude keys which we don't own
            try:
                key = self.key_store.get_keygroup(key_id)
            except UnknownKeyError:
                continue

            nko = len(self.candidate_keys[key_id])
            if nko > num_key_owners:
                num_key_owners = nko
                new_control_key = key

                if num_key_owners >= len(self.get_members()):
                    break
        if not new_control_key:
            logger_ckm.debug("We don't own any candidate keys yet")
            return False

        # control key is critically old, renew now
        if (
            ctrl_key_age_hr
            > CTRL_KEY_RENEWAL_AGE_HR
            + CTRL_KEY_MAX_RENEWAL_DUR_HR
            + self.CTRL_KEY_RENEWAL_RANDOMISER
        ):
            logger_ckm.debug("Renewing control keys...")
            self.renew_control_key(new_control_key)
            self.candidate_keys = {}
            return True

        # if not all members have the same candidate key yet,
        # we'll wait a little longer
        if num_key_owners < len(self.get_members()):
            logger_ckm.debug("control keys not fully shared yet...")
            return False
        # all members have the candidate control key
        if (
            ctrl_key_age_hr
            < CTRL_KEY_RENEWAL_AGE_HR + self.CTRL_KEY_RENEWAL_RANDOMISER
        ):
            logger_ckm.debug("Renewing control keys...")
            self.renew_control_key(new_control_key)
            self.candidate_keys = {}
            return True

        logger_ckm.debug("Awaiting randomness before renewing control key")
        return False

    def listen_for_conversations(
        self, listener_name: str, eventhandler: Callable
    ):
        return datatransmission.listen_for_conversations(
            gdm=self, listener_name=listener_name, eventhandler=eventhandler
        )

    def start_conversation(
        self, conv_name: str, peer_id: str, others_req_listener: str
    ) -> Conversation | None:
        return datatransmission.start_conversation(
            self, conv_name, peer_id, others_req_listener
        )

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
                logger.debug("GDM: terminating invitation managers...")
                for e in self.member_invitations:
                    e.terminate()
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


@dataclass_json
@dataclass
class InvitationCode:
    key: Key
    ipfs_id: str
    ipfs_addresses: list[str]

    def serialise_dict(self) -> str:
        return {
            "key": self.key.get_id(),
            "ipfs_id": self.ipfs_id,
            "ipfs_addresses": self.ipfs_addresses,
        }

    def serialise(self) -> str:
        return json.dumps(self.serialise_dict())

    @classmethod
    def deserialise_from_dict(cls, data: dict):
        return cls(
            key=Key.from_id(data["key"]),
            ipfs_id=data["ipfs_id"],
            ipfs_addresses=data["ipfs_addresses"],
        )

    @classmethod
    def deserialise(cls, code: str):
        data = json.loads(code)
        return cls.deserialise_from_dict(data)


class JoinProcess:
    def __init__(
        self,
        invitation: str | dict | InvitationCode,
        group_key_store: KeyStore | str,
        member: KeyStore | GenericDidManager,
        other_blocks_handler: Callable[[Block], None] | None = None,
    ):
        logger_gdm_join.debug("Joining GDM...")
        if isinstance(invitation, InvitationCode):
            invitation_code = invitation
        elif isinstance(invitation, dict):
            invitation_code = InvitationCode.deserialise_from_dict(invitation)
        elif isinstance(invitation, str):
            invitation_code = InvitationCode.deserialise(invitation)
        else:
            raise TypeError(f"Wrong type or invitation: {type(invitation)}")

        self.error_message = None
        self.invitation_code = invitation_code
        self.peer_found = Event()
        self.data_received = Event()
        self.joined_blockchain = Event()
        self.joined = Event()
        self.group_did_manager: GroupDidManager | None = None
        self.group_key_store = group_key_store
        self.member = member
        self.other_blocks_handler = other_blocks_handler
        if isinstance(self.group_key_store, str):
            if not os.path.isdir(self.group_key_store):
                raise ValueError(
                    "If a string is passed for the `key_store` parameter, "
                    "it should be a valid directory"
                )

        def join():
            try:
                self.join_blockchain()
            except Exception as e:
                logger_gdm_join.error(e)
                traceback.print_exc()

        self.thread = Thread(target=join, name="JoinGdmBlockchain")
        self.thread.start()

    def join_blockchain(self):
        try:
            one_time_key = KeyGroup.create(CTRL_KEY_FAMILIES)

            # find and connect to IPFS peer
            logger_gdm_join.debug("Finding peer...")
            ipfs_join_threads: list[Thread] = []
            for i, addr in enumerate(self.invitation_code.ipfs_addresses):
                logger_gdm_join.debug(
                    f"{addr}/p2p/{self.invitation_code.ipfs_id}"
                )
                thr = Thread(
                    target=ipfs.peers.connect,
                    args=(f"{addr}/p2p/{self.invitation_code.ipfs_id}",),
                    name=f"Gdm-Join-Connect-to-peer-{i}",
                )
                thr.start()
            ipfs_join_threads.append(thr)
            for thr in ipfs_join_threads:
                thr.join()
            if not ipfs.peers.is_connected(
                self.invitation_code.ipfs_id, ping_count=1
            ):
                logger_gdm_join.debug("Couldn't find peer.")
                logger_gdm_join.debug(self.invitation_code.ipfs_id)
                raise PeerNotFoundError
            self.peer_found.set()

            # talk to peer, get data
            logger_gdm_join.debug("Contacting peer...")
            others_req_listener = (
                f"WaliInvite-"
                + sha256(
                    self.invitation_code.key.get_id().encode()
                ).hexdigest()
            )
            logger_gdm_join.debug(f"Contacting peer at {others_req_listener}")
            logger.debug(self.invitation_code.key.get_id())
            keys_data = None
            blockchain_data = None
            conv = None
            handshake_error = None
            try:
                # START HANDSHAKE -----------------------
                our_challenge_data = generate_random_string(
                    CHALLENGE_STRING_LENGTH
                )
                salutation = json.dumps(
                    {
                        # "member_did": gdm.member_did_manager.did,
                        "one_time_key": one_time_key.get_id(),
                        "challenge_data": our_challenge_data,
                    }
                ).encode()

                logger_gdm_join.debug("GJT: STARTING TRANSMISSION")
                conv = ipfs.start_conversation(
                    conv_name=(
                        f"WalidJoin-"
                        + sha256(
                            self.invitation_code.key.get_id().encode()
                        ).hexdigest()
                    ),
                    peer_id=self.invitation_code.ipfs_id,
                    others_req_listener=others_req_listener,
                    # encryption_callbacks=(encrypt, decrypt),
                    salutation_message=salutation,
                )

                salutation_join = json.loads(conv.salutation_join.decode())

                # upgrade to a more secure key than the one from the invitation
                their_key = KeyGroup.from_id(salutation_join["one_time_key"])
                if not self.invitation_code.key.verify_signature(
                    string_to_bytes(salutation_join["inviter_proof"]),
                    (our_challenge_data).encode(),
                ):
                    logger_gdm_join.warning(
                        "Failed to verify that our peer is the author of this invitaion."
                    )
                    conv.terminate()
                    raise ChallengeFailedError()

                def encrypt(data):
                    return their_key.encrypt(data)

                def decrypt(data):
                    return one_time_key.decrypt(data)

                conv.set_encryption_functions(encrypt, decrypt)
                logger_gdm_join.debug("Talking to peer...")
                conv.say("Ready!".encode())
                # FINISH HANDSHAKE -----------------------

                keys_data = conv.listen(datatransmission.COMMS_TIMEOUT_S)

                # logger.debug(conv.ipfs_client.tunnels.get_tunnels())
                logger.debug("Awaiting file...")
                blockchain_data = conv.listen_for_file(
                    no_coms_timeout=COMMS_TIMEOUT_S
                )["filepath"]
                conv.terminate()
                if not (blockchain_data and keys_data):
                    raise HandshakeFailedError(
                        "Completed handshake, but data was empty."
                    )
            except (CommunicationTimeout, ConvListenTimeout) as e:
                handshake_error = e
            finally:
                if conv:
                    logger_gdm_join.debug("GJT: CLOSING TRANSMISSION")
                    conv.terminate()
                else:
                    logger_gdm_join.debug("GJT: FAILED TRANSMISSION")

            if not (blockchain_data and keys_data):
                raise HandshakeFailedError(handshake_error)

            self.data_received.set()

            # load data received from peer
            logger_gdm_join.debug("Processing data...")
            data = json.loads(bytes.decode(keys_data))
            gdm_keys = [
                Key.deserialise_private_encrypted(key, one_time_key)
                for key in data["group_keys"]
            ]
            blockchain_id = data["blockchain_id"]
            logger_gdm_join.debug("Joining blockchain...")
            try:
                join_blockchain_from_zip(blockchain_id, blockchain_data)
            except BlockchainAlreadyExistsError:
                pass
            logger_gdm_join.debug("Loading blockchain...")
            blockchain = Blockchain(blockchain_id)
            self.joined_blockchain.set()

            logger_gdm_join.debug("Processing keys...")
            if isinstance(self.group_key_store, str):
                # use blockchain ID instead of DID
                # as some filesystems don't support colons
                key_store_path = os.path.join(
                    self.group_key_store,
                    f"{blockchain.blockchain_id}.json",
                )
                self.group_key_store = KeyStore(
                    key_store_path, Key.create(CRYPTO_FAMILY)
                )

            for key in gdm_keys:
                self.group_key_store.add_key(key)
            logger_gdm_join.debug("Loading GroupDidManager...")
            self.group_did_manager = GroupDidManager._join_from_blockchain(
                blockchain=blockchain,
                group_key_store=self.group_key_store,
                member=self.member,
                other_blocks_handler=self.other_blocks_handler,
            )
            logger_gdm_join.debug("Joined GroupDidManager!")
            self.joined.set()
        except Exception as e:
            logger_gdm_join.error(e)
            logger_gdm_join.error(traceback.format_exc())
        finally:
            if not self.peer_found.is_set():
                self.error_message = "Peer not found."
            elif not self.data_received.is_set():
                self.error_message = "Failed to negotiate with peer."
            elif not self.joined_blockchain.is_set():
                self.error_message = "Failed to join blockchain."
            elif not self.joined.is_set():
                self.error_message = "Failed to load Group-DID-Manager."
            self.peer_found.set()
            self.data_received.set()
            self.joined_blockchain.set()
            self.joined.set()


class InvitationManager:
    def __init__(self, gdm: GroupDidManager, key: Key):
        self.gdm = gdm
        self.key = key
        listener_name = (
            f"WaliInvite-{sha256(self.key.get_id().encode()).hexdigest()}"
        )
        self.listener = ipfs_tk_transmission.ConversationListener(
            ipfs_client=ipfs,
            listener_name=listener_name,
            eventhandler=self._handler,
        )
        logger_gdm_join.debug(f"Created InvitationManager: {listener_name}")
        logger.debug(key.get_id())

    @classmethod
    def create(cls, gdm: GroupDidManager):
        return cls(gdm=gdm, key=Key.create(INVITATION_KEY_FAMILY))

    def serialise(self) -> str:
        # encrypt self.key with key from self.gdm
        key = self.gdm.get_control_keys()

        return CodePackage(
            code=key.encrypt(
                str.encode(json.dumps(self.key.serialise_private()))
            ),
            key=key,
        ).serialise()

    @classmethod
    def deserialise(cls, gdm: GroupDidManager, data: str):
        cp = CodePackage.deserialise(data)
        invitation_key = Key.deserialise_private(
            json.loads(bytes.decode(gdm.decrypt(cp.serialise_bytes())))
        )
        return cls(gdm, invitation_key)

    def _handler(self, conv_name, peer_id, salutation_start):
        logger_gdm_join.debug("_Received request.")
        try:
            self.handler(
                conv_name=conv_name,
                peer_id=peer_id,
                salutation_start=salutation_start,
            )
        except Exception as e:
            logger_gdm_join.error(e)

    def handler(self, conv_name, peer_id, salutation_start):
        # START HANDSHAKE -----------------------
        logger_gdm_join.debug("Received request.")

        salutation_start = json.loads(salutation_start.decode())
        their_key = KeyGroup.from_id(salutation_start["one_time_key"])

        # sign their challenge with invitation key to prove that we created the invitation
        their_challenge = (salutation_start["challenge_data"]).encode()
        challenge_signature = self.key.sign(their_challenge)

        # use a stronger key for communications than the invitation key
        our_key = self.gdm.get_control_keys()
        salutation = json.dumps(
            {
                # "member_did": gdm.member_did_manager.did,
                "one_time_key": our_key.get_id(),
                "inviter_proof": bytes_to_string(challenge_signature),
            }
        ).encode()

        def encrypt(data):
            return their_key.encrypt(data)

        def decrypt(data):
            return our_key.decrypt(data)

        logger_gdm_join.debug("Joining conversation...")
        conv = ipfs.join_conversation(
            conv_name=conv_name,
            peer_id=peer_id,
            others_trsm_listener=conv_name,
            encryption_callbacks=(encrypt, decrypt),
            salutation_message=salutation,
        )

        # prepare while waiting
        keys = [
            key.serialise_private_encrypted(their_key)
            for key in self.gdm.key_store.get_all_keys()
        ]

        # wait until peer has finished setting up new encryption
        ready = conv.listen(timeout=COMMS_TIMEOUT_S)
        if ready != b"Ready!":
            logger_gdm_join.error(f"Received unexpected reply: {ready}")
            conv.terminate()
            return

        # FINISH HANDSHAKE -----------------------

        logger_gdm_join.debug("Sending keys...")
        conv.say(
            str.encode(
                json.dumps(
                    {
                        "group_keys": keys,
                        "blockchain_id": self.gdm.blockchain.blockchain_id,
                    }
                )
            )
        )

        logger_gdm_join.debug("Retrieving blockchain data...")
        blockchain_data = self.gdm.blockchain.get_blockchain_data()
        logger_gdm_join.debug("Sending blockchain data...")
        conv.transmit_file(blockchain_data)
        logger_gdm_join.debug("Terminating...")
        conv.terminate()

        self.listener.terminate()
        if self in self.gdm.member_invitations:
            self.gdm.member_invitations.remove(self)
            self.gdm.save_invitations()

    def generate_code(self) -> InvitationCode:
        return InvitationCode(
            key=self.key.clone_public(),
            ipfs_id=ipfs.peer_id,
            ipfs_addresses=[
                addr.split("/p2p/")[0]
                for addr in ipfs.get_addrs()
                if not addr.startswith("/dns")
                and "127.0.0.1" not in addr
                and "webrtc" not in addr
                and "certhash" not in addr
            ],
        )

    def terminate(self):
        self.listener.terminate()

    def __del__(self):
        self.terminate()


class IncompletePeerInfoError(Exception):
    """When a peer's DID document doesn't contain all the info we need."""


class NotMemberError(Exception):
    """When a peer isn't among our members."""


class IdentityJoinError(Exception):
    """When `DidManager.add_member()` fails."""

    def __init__(self, message: str):
        self.message = message

    def __str__(self):
        return self.message


class MemberBlockchainNotJoinedError(Exception):
    pass


class GdmJoinFailureError(Exception):
    def __init__(self, data):
        self.data = data

    def __str__(self):
        return f"{self.data}"


# decorate_all_functions(strictly_typed, __name__)
