""""""
from multi_crypt import verify_signature
from .utils import bytes_to_string, bytes_from_string
import json
from dataclasses import dataclass, asdict

import walytis_beta_api as walytis_api
from walytis_beta_api import Blockchain, delete_blockchain
from .did_objects import Key, Service
from abc import ABC, abstractmethod
PRIBLOCKS_VERSION = (0, 0, 1)


@dataclass
class ControlKeyBlock:
    old_key: str
    old_key_type: str
    new_key: str
    new_key_type: str
    signature: str

    priblocks_version: tuple

    @staticmethod
    def new(
        old_key: str,
        old_key_type: str,
        new_key: str,
        new_key_type: str
    ):
        return ControlKeyBlock(
            old_key=bytes_to_string(old_key),
            old_key_type=bytes_to_string(old_key_type),
            new_key=bytes_to_string(new_key),
            new_key_type=bytes_to_string(new_key_type),
            priblocks_version=PRIBLOCKS_VERSION,
            signature=""
        )

    def get_signature_data(self):
        return (
            f"{self.old_key_type}:{self.old_key};"
            f"{self.new_key_type}:{self.new_key}"
        ).encode()

    def sign(self, crypt):
        self.signature = bytes_to_string(crypt.sign(self.get_signature_data()))

    @classmethod
    def load_from_block_content(cls, block_content):
        return cls(**json.loads(block_content.decode()))

    def generate_block_content(self):
        return json.dumps(asdict(self)).encode()

    def get_old_key(self):
        return Key(
            key_id=None,
            type=self.old_key_type,
            public_key=self.old_key,
            private_key=None
        )

    def get_new_key(self) -> Key:
        return Key(
            key_id=None,
            type=self.new_key_type,
            public_key=self.new_key,
            private_key=None
        )


@dataclass
class InfoBlock(ABC):
    """Base class for all blocks published on this blockchain other than the
    control-key blocks.
    It defines the fields that are encapsulated into a Walytis-Block, and
    includes functionality for serialisation into blocks and content signing.
    """
    info_content: any   # the essential content of this block from the perspective of the DidManager
    signature: str
    priblocks_version: tuple

    @classmethod
    def new(cls, info_content):
        """
        Parameters:
            info_content: the essential content of this block from the
                perspective of the DidManager, e.g. DID-doc, members list
        """
        return cls(
            info_content=info_content,
            priblocks_version=PRIBLOCKS_VERSION,
            signature=""
        )

    @classmethod
    def load_from_block_content(cls, block_content):
        return cls(**json.loads(block_content.decode()))

    def generate_block_content(self):
        return json.dumps(asdict(self)).encode()

    def get_signature_data(self):
        return json.dumps(self.info_content).encode()

    def sign(self, crypt):
        self.signature = bytes_to_string(crypt.sign(self.get_signature_data()))

    def verify_signature(self, key):
        return verify_signature(
            key.type,
            bytes_from_string(self.signature),
            self.get_signature_data(),
            bytes_from_string(key.public_key)
        )


@dataclass
class DidDocBlock(InfoBlock):
    walytis_block_topic = "did_doc"

    def get_did(self):
        return self.info_content


@dataclass
class MembersListBlock(InfoBlock):
    walytis_block_topic = 'members_list'

    def get_members(self):
        return self.info_content


def verify_control_key_update(key_block_1: ControlKeyBlock, key_block_2: ControlKeyBlock):
    """Check if the untrusted key_block_2 is a valid successor for the trusted
    key_block_1."""
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


def get_latest_control_key(blockchain: Blockchain):
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


def get_latest_block(blockchain: Blockchain, topic: str) -> InfoBlock | None:
    """Iterates through the blockchain's blocks to find the latest valid
    block of the given topic, except for control-key blocks
    (use get_latest_control_key for control-key blocks).
    This function looks so complex because it has to work even if the latest
    valid block was created before the currently valid control key.

    Parameters:
        blockchain (Blockchain): the identity-control-blockchain of the
                                identity whose DID-doc is to be retrieved
    Returns:
        dict: the currently valid DID-document of the identity
    """
    last_key_block = None
    last_info_block = None
    for block_id in blockchain.block_ids:
        # if this block is a control key update block
        if 'control_key' in walytis_api.decode_short_id(block_id)['topics']:
            # load block content
            ctrl_key_block = ControlKeyBlock.load_from_block_content(
                blockchain.get_block(block_id).content
            )
            # if we haven't processed this blockchain's first ctrl key yet
            if not last_key_block:
                # ensure the first ControlKeyBlock has identical current and new keys
                if not (
                    ctrl_key_block.old_key == ctrl_key_block.new_key
                    and ctrl_key_block.old_key_type
                   == ctrl_key_block.new_key_type
                   ):
                    raise Exception(
                        "First key block doesn't have identical keys!")
                last_key_block = ctrl_key_block
            else:   # we've already processed this blockchain's first ctrl key
                # if this block's signaure is validated by the last ctrl key
                if verify_control_key_update(last_key_block, ctrl_key_block):
                    last_key_block = ctrl_key_block
                else:
                    print("Found Control Key Block with invalid signature")

        # if this block is of the type we are looking for
        if topic in walytis_api.decode_short_id(block_id)['topics']:
            # load block content
            info_block = InfoBlock.load_from_block_content(
                blockchain.get_block(block_id).content
            )
            # if its signature is validated by the last ctrl key
            if last_key_block and info_block.verify_signature(last_key_block.get_new_key()):
                # set this to the latest info-block
                last_info_block = info_block
            else:
                print("Found info-block Block with invalid signature")

    # return the DID-document of the last valid DID-Doc block
    if last_info_block:
        return last_info_block
    else:
        print("No valid blocks found")
        return None


def get_latest_did_doc(blockchain: Blockchain) -> dict | None:
    """Iterates through the blockchain's blocks to find the latest valid
    DID-document.
    This function lookss so complex because it has to work even if the latest
    valid DID-Doc block was created before the currently valid control key.

    Parameters:
        blockchain (Blockchain): the identity-control-blockchain of the
                                identity whose DID-doc is to be retrieved
    Returns:
        dict: the currently valid DID-document of the identity
    """
    latest_block = get_latest_block(
        blockchain,
        DidDocBlock.walytis_block_topic
    )
    if latest_block:
        return latest_block.info_content
    return None


def get_latest_members_list(blockchain: Blockchain) -> dict | None:
    """Iterates through the blockchain's blocks to find the latest valid
    DID-document.
    This function lookss so complex because it has to work even if the latest
    valid DID-Doc block was created before the currently valid control key.

    Parameters:
        blockchain (Blockchain): the identity-control-blockchain of the
                                identity whose DID-doc is to be retrieved
    Returns:
        dict: the currently valid DID-document of the identity
    """
    latest_block = get_latest_block(
        blockchain,
        MembersListBlock.walytis_block_topic
    )
    if latest_block:
        return latest_block.info_content

    return None
