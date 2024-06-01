"""Machinery for working with Walytis blocks for the DID-Manager."""
import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Type, TypeVar

import walytis_beta_api as walytis_api
from multi_crypt import Crypt, verify_signature
from walytis_beta_api import Blockchain

from .did_objects import Key
from .utils import bytes_from_string, bytes_to_string

PRIBLOCKS_VERSION = (0, 0, 1)


_ControlKeyBlock = TypeVar('_ControlKeyBlock', bound='ControlKeyBlock')


@dataclass
class ControlKeyBlock:
    """Representation of a block that publishes a control key update."""

    old_key: str
    old_key_type: str
    new_key: str
    new_key_type: str
    signature: str

    priblocks_version: tuple

    @classmethod
    def new(
        cls: Type[_ControlKeyBlock],
        old_key: str,
        old_key_type: str,
        new_key: str,
        new_key_type: str
    ) -> _ControlKeyBlock:
        """Prepare a control-key-update block (not yet signed)."""
        return cls(
            old_key=bytes_to_string(old_key),
            old_key_type=bytes_to_string(old_key_type),
            new_key=bytes_to_string(new_key),
            new_key_type=bytes_to_string(new_key_type),
            priblocks_version=PRIBLOCKS_VERSION,
            signature=""
        )

    def get_signature_data(self) -> bytes:
        """Get the portion of this block's content that will be signed."""
        return (
            f"{self.old_key_type}:{self.old_key};"
            f"{self.new_key_type}:{self.new_key}"
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
            key_id=None,
            type=self.old_key_type,
            public_key=self.old_key,
            private_key=None
        )

    def get_new_key(self) -> Key:
        """Get this control-key-update's new key."""
        return Key(
            key_id=None,
            type=self.new_key_type,
            public_key=self.new_key,
            private_key=None
        )


_InfoBlock = TypeVar('_InfoBlock', bound='InfoBlock')


@dataclass
class InfoBlock(ABC):
    """Base class for representing blocks other than the control-key blocks.

    It defines the fields that are encapsulated into a Walytis-Block, and
    includes functionality for serialisation into blocks and content signing.
    """

    # essential content of this block from the perspective of the DidManager
    info_content: dict | list
    signature: str
    priblocks_version: tuple

    @property
    @abstractmethod
    def walytis_block_topic(self) -> str:
        """The Walytis block topic that identifies this type of block."""

    @classmethod
    def new(
            cls: Type[_InfoBlock],
            info_content: dict
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
            key.type,
            bytes_from_string(self.signature),
            self.get_signature_data(),
            bytes_from_string(key.public_key)
        )


@dataclass
class DidDocBlock(InfoBlock):
    """A block containing a DID document."""

    walytis_block_topic = "did_doc"
    info_content: dict

    def get_did_doc(self) -> dict:
        """Get the DID-Document which this block publishes."""
        return self.info_content


@dataclass
class MembersListBlock(InfoBlock):
    """Representation of a block publishing this DID's member-devices."""

    walytis_block_topic = 'members_list'
    info_content: list

    def get_members(self) -> list:
        """Get the member devices published."""
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
            blockchain.get_block(block_id).content
        )
        for block_id in blockchain.block_ids
        if 'control_key' in walytis_api.decode_short_id(block_id)['topics']
    ]

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


def get_latest_block(
    blockchain: Blockchain,
    block_type: Type[InfoBlockType]
) -> InfoBlockType | None:
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
    last_info_block = None

    topic = block_type.walytis_block_topic

    for block_id in blockchain.block_ids:
        # if this block is a control key update block
        if 'control_key' in walytis_api.decode_short_id(block_id)['topics']:
            # load block content
            ctrl_key_block = ControlKeyBlock.load_from_block_content(
                blockchain.get_block(block_id).content
            )
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

            # we've already processed this blockchain's first ctrl key
            # if this block's signaure is validated by the last ctrl key
            elif verify_control_key_update(last_key_block, ctrl_key_block):
                last_key_block = ctrl_key_block
            else:
                print("Found Control Key Block with invalid signature")

        # if this block is of the type we are looking for
        if topic in walytis_api.decode_short_id(block_id)['topics']:
            # load block content
            info_block = block_type.load_from_block_content(
                blockchain.get_block(block_id).content
            )
            # if its signature is validated by the last ctrl key
            if (last_key_block and
                    info_block.verify_signature(last_key_block.get_new_key())):
                # set this to the latest info-block
                last_info_block = info_block
            else:
                print("Found info-block Block with invalid signature")

    # return the DID-document of the last valid DID-Doc block
    if last_info_block:
        return last_info_block
    # print("No valid blocks found")
    return None


def get_latest_did_doc(blockchain: Blockchain) -> dict | None:
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
        return None
    if not isinstance(latest_block, DidDocBlock):
        raise ValueError(
            "Bug: get_latest_block() should've returned a DidDocBlock, "
            f"not {type(latest_block)}"
        )
    return latest_block.info_content


def get_latest_members_list(blockchain: Blockchain) -> list | None:
    """Get a DID-Manager's blockchain's current members-list.

    Iterates through the blockchain's blocks to find the latest valid
    DID-document.
    This function lookss so complex because it has to work even if the latest
    valid DID-Doc block was created before the currently valid control key.

    Args:
        blockchain: the identity-control-blockchain of the
                                identity whose DID-doc is to be retrieved
    Returns:
        dict: the currently valid DID-document of the identity
    """
    latest_block = get_latest_block(
        blockchain,
        MembersListBlock
    )
    if not latest_block:
        return None
    if not isinstance(latest_block, MembersListBlock):
        raise ValueError(
            "Bug: get_latest_block() should've returned a DidDocBlock, "
            f"not {type(latest_block)}"
        )
    return latest_block.info_content
