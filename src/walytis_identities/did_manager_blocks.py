"""Machinery for working with Walytis blocks for the DID-Manager."""
from .utils import logger
from decorate_all import decorate_all_functions
from strict_typing import strictly_typed
import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Type, TypeVar
from datetime import datetime
from brenthy_tools_beta.utils import time_to_string, string_to_time
import walytis_beta_api as walytis_api
from multi_crypt import Crypt, verify_signature
from walytis_beta_api import Blockchain

from .did_objects import Key
from .exceptions import NotValidDidBlockchainError
from .utils import bytes_from_string, bytes_to_string

PRIBLOCKS_VERSION = (0, 0, 1)


_ControlKeyBlock = TypeVar('_ControlKeyBlock', bound='ControlKeyBlock')


@strictly_typed
@dataclass
class ControlKeyBlock:
    """Representation of a block that publishes a control key update."""

    old_key: str
    old_key_type: str
    old_key_timestamp: str
    new_key: str
    new_key_type: str
    new_key_timestamp: str
    signature: str

    priblocks_version: tuple | list
    walytis_block_topic = "control_key"

    @classmethod
    def new(
        cls: Type[_ControlKeyBlock],
        old_key: Key,
        new_key: Key,
    ) -> _ControlKeyBlock:
        """Prepare a control-key-update block (not yet signed)."""
        return cls(
            old_key=bytes_to_string(old_key.public_key),
            old_key_type=old_key.family,
            old_key_timestamp=time_to_string(old_key.creation_time),
            new_key=bytes_to_string(new_key.public_key),
            new_key_type=new_key.family,
            new_key_timestamp=time_to_string(new_key.creation_time),
            priblocks_version=PRIBLOCKS_VERSION,
            signature=""
        )

    def get_signature_data(self) -> bytes:
        """Get the portion of this block's content that will be signed."""
        return (
            f"{self.old_key_type}: {self.old_key}"
            f"{self.new_key_type}: {self.new_key}"
        ).encode()

    def sign(self, crypt: Crypt) -> None:
        """Sign key update with old key."""
        self.signature = bytes_to_string(crypt.sign(self.get_signature_data()))

    @classmethod
    def load_from_block_content(
        cls: Type[_ControlKeyBlock], block_content: bytearray
    ) -> _ControlKeyBlock:
        """Create a ControlKeyBlock object given raw block content."""
        return cls(**json.loads(block_content.decode()))

    def generate_block_content(self) -> bytes:
        """Generate raw block content for a Walytis block."""
        return json.dumps(asdict(self)).encode()

    def get_old_key(self) -> Key:
        """Get this control-key-update's old key."""
        return Key(
            family=self.old_key_type,
            public_key=bytes_from_string(self.old_key),
            private_key=None,
            creation_time=string_to_time(self.old_key_timestamp),
        )

    def get_new_key(self) -> Key:
        """Get this control-key-update's new key."""
        return Key(
            family=self.new_key_type,
            public_key=bytes_from_string(self.new_key),
            private_key=None,
            creation_time=string_to_time(self.new_key_timestamp),
        )


_InfoBlock = TypeVar('_InfoBlock', bound='InfoBlock')


# @strictly_typed
@dataclass
class InfoBlock(ABC):
    """Base class for representing blocks other than the control-key blocks.

    It defines the fields that are encapsulated into a Walytis-Block, and
    includes functionality for serialisation into blocks and content signing.
    """

    # essential content of this block from the perspective of the DidManager
    info_content: dict | list
    signature: str
    priblocks_version: tuple | list

    @property
    @abstractmethod
    def walytis_block_topic(self) -> str:
        """The Walytis block topic that identifies this type of block."""

    @classmethod
    def new(
            cls: Type[_InfoBlock],
            info_content: dict | list
    ) -> _InfoBlock:
        """Prepare a Block (not yet signed).

        Args:
            info_content: the essential content of this block from the
                perspective of the DidManager, e.g. DID-doc, members list
        """
        return cls(
            info_content=info_content,
            priblocks_version=PRIBLOCKS_VERSION,
            signature=""
        )

    @classmethod
    def load_from_block_content(
            cls: Type[_InfoBlock], block_content: bytes | bytearray
    ) -> _InfoBlock:
        """Create a BlockInfo object given raw block content."""
        return cls(**json.loads(block_content.decode()))

    def generate_block_content(self) -> bytes:
        """Generate raw block content for a Walytis block."""
        return json.dumps(asdict(self)).encode()

    def get_signature_data(self) -> bytes:
        """Get the portion of this block's content that will be signed."""
        return json.dumps(self.info_content).encode()

    def sign(self, crypt: Crypt) -> None:
        """Sign this block's content with a control-key."""
        self.signature = bytes_to_string(crypt.sign(self.get_signature_data()))

    def verify_signature(self, key: Key) -> bool:
        """Verify this block's signature."""
        return verify_signature(
            key.family,
            bytes_from_string(self.signature),
            self.get_signature_data(),
            key.public_key
        )


@strictly_typed
class DidDocBlock(InfoBlock):
    """A block containing a DID document."""

    walytis_block_topic = "did_doc"
    info_content: dict

    def get_did_doc(self) -> dict:
        """Get the DID-Document which this block publishes."""
        return self.info_content


@strictly_typed
class MemberInvitationBlock(InfoBlock):
    """A block containing a DID document."""

    walytis_block_topic = "member_invitation"
    info_content: dict

    def get_member_invitation(self) -> dict:
        """Get the DID-Document which this block publishes."""
        return self.info_content


@strictly_typed
class MemberJoiningBlock(InfoBlock):
    """A block containing a DID document."""

    walytis_block_topic = "member_joining"
    info_content: dict

    def get_member(self) -> dict:
        """Get the DID-Document which this block publishes."""
        return self.info_content


@strictly_typed
class MemberLeavingBlock(InfoBlock):
    """A block containing a DID document."""

    walytis_block_topic = "member_leaving"
    info_content: dict

    def get_member(self) -> dict:
        """Get the DID-Document which this block publishes."""
        return self.info_content


@strictly_typed
class MemberUpdateBlock(InfoBlock):
    """A block containing a DID document."""

    walytis_block_topic = "member_update"
    info_content: dict

    def get_member(self) -> dict:
        """Get the DID-Document which this block publishes."""
        return self.info_content

@dataclass
class SuperRegistrationBlock(InfoBlock):
    """Block in a DidManagerWithSupers's blockchain registering a GroupDidManager."""
    walytis_block_topic = "endra_corresp_reg"
    info_content: dict

    @classmethod
    def create(
        cls, correspondence_id: str, active: bool, invitation: dict | None,
    ) -> 'SuperRegistrationBlock':

        info_content = {
            "correspondence_id": correspondence_id,
            "active": active,
            "invitation": invitation,
        }
        return cls.new(info_content)

    @property
    def correspondence_id(self) -> str:
        return self.info_content["correspondence_id"]

    @property
    def active(self) -> bool:
        return self.info_content["active"]

    @property
    def invitation(self) -> dict | None:
        return self.info_content["invitation"]

@strictly_typed
class KeyOwnershipBlock(InfoBlock):
    """Representation of a block publishing annoucing key ownership."""

    walytis_block_topic = 'key_ownership'
    info_content: dict

    def get_key_ownership(self) -> dict:
        """Get the members published."""
        return self.info_content


def verify_control_key_update(
        key_block_1: ControlKeyBlock, key_block_2: ControlKeyBlock
) -> bool:
    """Verify a control-key-update's validity.

    Checks if the untrusted key_block_2 is a valid successor for the trusted
    key_block_1.
    """
    # assert that the new block refers to the old block's key
    if not (
        key_block_1.new_key == key_block_2.old_key and
        key_block_1.new_key_type == key_block_2.old_key_type
    ):
        return False

    # verify the new block's signature against the current key
    return verify_signature(
        key_block_1.old_key_type,
        bytes_from_string(key_block_2.signature),
        key_block_2.get_signature_data(),
        bytes_from_string(key_block_1.new_key)
    )


def get_latest_control_key(blockchain: Blockchain) -> Key:
    """Get a DID-Manager's blockchain's newest control-key."""
    # get all key blocks from blockchain
    ctrl_key_blocks = [
        ControlKeyBlock.load_from_block_content(
            block.content
        )
        for block in blockchain.get_blocks()
        if get_block_type(block.topics) == ControlKeyBlock
    ]
    if not ctrl_key_blocks:
        raise Exception(f"Blockchain has no control keys! {blockchain.blockchain_id}")
    # ensure the first ControlKeyBlock has identical current and new keys
    if not (
        ctrl_key_blocks[0].old_key == ctrl_key_blocks[0].new_key
        and ctrl_key_blocks[0].old_key_type == ctrl_key_blocks[0].new_key_type
    ):
        raise Exception("First key block doesn't have identical keys!")

    # iterate through key updates, verifying them
    # to determine the currently valid ControlKeyBlock
    i = 1
    last_key_block = ctrl_key_blocks[0]
    while i < len(ctrl_key_blocks):
        if verify_control_key_update(last_key_block, ctrl_key_blocks[i]):
            last_key_block = ctrl_key_blocks[i]
        i += 1

    control_key = last_key_block.get_new_key()
    return control_key


# type representing the child-classes of InfoBlocks
InfoBlockType = TypeVar('InfoBlockType', bound=InfoBlock)


def get_info_blocks(
    blockchain: Blockchain,
    block_types: Type[InfoBlockType] | set[Type[InfoBlockType]]
) -> list[InfoBlockType]:
    """Get the latest validly signed block of the given topic.

    Iterates through the blockchain's blocks to find the latest valid
    block of the given topic, except for control-key blocks
    (use get_latest_control_key for control-key blocks).
    This function looks so complex because it has to work even if the latest
    valid block was created before the currently valid control key.

    Args:
        blockchain: the identity-control-blockchain of the
                                identity whose DID-doc is to be retrieved
        block_type: the type of blocks to search through
    Returns:
        dict: the currently valid DID-document of the identity
    """
    last_key_block = None
    valid_member_invitations = {}
    if not isinstance(block_types, set):
        block_types = {block_types}
    valid_blocks = []

    # logger.debug(f"WAB: Getting latest {block_type} block...")
    for block in blockchain.get_blocks():
        block_type = get_block_type(block.topics)
        # logger.debug("WAB: Analysing block...")
        # if this block is a control key update block
        if not block_type:
            pass
        elif block_type == ControlKeyBlock:
            # load block content
            # logger.debug("WAB: Getting Control Key block...")
            ctrl_key_block = ControlKeyBlock.load_from_block_content(
                block.content
            )
            # logger.debug("WAB: Processing block...")
            # if we haven't processed this blockchain's first ctrl key yet
            if not last_key_block:
                # ensure the first ControlKeyBlock
                # has identical current and new keys
                if not (
                    ctrl_key_block.old_key == ctrl_key_block.new_key
                    and ctrl_key_block.old_key_type
                   == ctrl_key_block.new_key_type
                   ):
                    raise Exception(
                        "First key block doesn't have identical keys!")
                last_key_block = ctrl_key_block
                if ControlKeyBlock in block_types:
                    valid_blocks.append(block)

            # we've already processed this blockchain's first ctrl key
            # if this block's signaure is validated by the last ctrl key
            elif verify_control_key_update(last_key_block, ctrl_key_block):
                last_key_block = ctrl_key_block
                if ControlKeyBlock in block_types:
                    valid_blocks.append(block)
            else:
                print("Found Control Key Block with invalid signature")
        elif block_type == MemberInvitationBlock:
            invitation_block = MemberInvitationBlock.load_from_block_content(
                block.content
            )
            invitation = invitation_block.get_member_invitation()
            if (last_key_block and
                    invitation_block.verify_signature(last_key_block.get_new_key())):

                # set this to the latest info-block
                valid_member_invitations.update(
                    {invitation["invitation_key"]: invitation})
                if block_type in block_types:
                    valid_blocks.append(invitation_block)
            else:
                print("Found info-block Block with invalid signature")
        elif block_type == MemberJoiningBlock and block_type in block_types:
            joining_block = block_type.load_from_block_content(
                block.content
            )
            member = joining_block.get_member()
            _invitation = valid_member_invitations.get(
                member["invitation_key"])
            if _invitation and joining_block.verify_signature(
                Key.from_key_id(_invitation["invitation_key"])
            ):
                valid_blocks.append(joining_block)
            else:
                logger.warning("Found joining block with invalid signature.")

        # if this block is of the type we are looking for
        elif block_type in block_types:
            # load block content
            # logger.debug("WAB: Getting block...")
            info_block = block_type.load_from_block_content(
                block.content
            )
            # logger.debug("WAB: Processing block...")
            # if its signature is validated by the last ctrl key
            if (last_key_block and
                    info_block.verify_signature(last_key_block.get_new_key())):
                # set this to the latest info-block
                valid_blocks.append(info_block)
            else:
                logger.warning(f"Found {block_type} with invalid signature")
    return valid_blocks


def get_latest_block(
    blockchain: Blockchain,
    block_type: Type[InfoBlockType]
) -> InfoBlockType | None:
    blocks = get_info_blocks(blockchain, block_type)
    if blocks:
        return blocks[-1]
    # print("No valid blocks found")
    return None


def get_latest_did_doc(blockchain: Blockchain) -> dict:
    """Get a DID-Manager's blockchain's newest DID-Document.

    Iterates through the blockchain's blocks to find the latest valid
    DID-document.
    This function lookss so complex because it has to work even if the latest
    valid DID-Doc block was created before the currently valid control key.

    Args:
        blockchain: the identity-control-blockchain of the identity whose
                    DID-doc is to be retrieved
    Returns:
        dict: the currently valid DID-document of the identity
    """
    latest_block = get_latest_block(
        blockchain,
        DidDocBlock
    )
    if not latest_block:
        raise NotValidDidBlockchainError()
    if not isinstance(latest_block, DidDocBlock):
        raise ValueError(
            "Bug: get_latest_block() should've returned a DidDocBlock, "
            f"not {type(latest_block)}"
        )
    return latest_block.info_content


def get_members(blockchain: Blockchain) -> dict[str, dict]:
    blocks: list[
        MemberJoiningBlock | MemberUpdateBlock | MemberLeavingBlock
    ] = get_info_blocks(
        blockchain, {MemberJoiningBlock, MemberUpdateBlock, MemberLeavingBlock}
    )
    members: dict[str, dict] = {}
    for block in blocks:
        member = block.get_member()

        # match this block's type: MemberJoiningBlock, MemberUpdateBlock etc.
        match block.walytis_block_topic:
            case MemberJoiningBlock.walytis_block_topic:
                if member["did"] in members.keys():
                    logger.warning(
                        "Members: Found MemberJoiningBlock for existing member."
                    )
                else:
                    members.update({member["did"]: member})
            case MemberUpdateBlock.walytis_block_topic:
                if member["did"] not in members.keys():
                    logger.warning(
                        "Members: Found MemberUpdateBlock for non-existent member."
                    )
                else:
                    members["did"] = member
            case MemberLeavingBlock.walytis_block_topic:
                if member["did"] not in members.keys():
                    logger.warning(
                        "Members: Found MemberLeavingBlock for non-existent member."
                    )
                else:
                    members.pop(member["did"])
    return members


INFO_BLOCK_TYPES: set[InfoBlockType] = {
    DidDocBlock,
    MemberInvitationBlock,
    MemberJoiningBlock,
    MemberLeavingBlock,
    MemberUpdateBlock,
    SuperRegistrationBlock,
    KeyOwnershipBlock,
}


def get_block_type(topics: list[str] | str) -> InfoBlockType | type(ControlKeyBlock) | None:
    """Get the block's DID-Manager block-type given its IDs.

    Is strict and detects invalid block IDs.
    """
    if isinstance(topics, str):
        topics = [topics]
    block_type: InfoBlockType | None = None
    for _type in set.union(INFO_BLOCK_TYPES, {ControlKeyBlock}):
        if _type.walytis_block_topic in topics:
            if block_type:
                return None
            block_type = _type

    return block_type


# decorate_all_functions(strictly_typed, __name__)
