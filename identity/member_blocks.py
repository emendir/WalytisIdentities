""""""
from multi_crypt import verify_signature
from .utils import bytes_to_string, bytes_from_string
import json
from dataclasses import dataclass, asdict

import walytis_beta_api as walytis_api
from walytis_beta_api import Blockchain, delete_blockchain
from .did_objects import Key, Service

PRIBLOCKS_VERSION = (0, 0, 1)


@dataclass
class NewMemberBlock:
    public_key: str
    member_data: dict
    signature: str

    priblocks_version: tuple

    @classmethod
    def load_from_block_content(cls, block_content):
        return cls(**json.loads(block_content.decode()))

    def generate_block_content(self):
        return json.dumps(asdict(self)).encode()


@dataclass
class MemberUpdateBlock:
    creator_id: str
    old_key: str
    new_key: str
    member_data: dict
    signature: str

    priblocks_version: tuple

    @classmethod
    def load_from_block_content(cls, block_content):
        return cls(**json.loads(block_content.decode()))

    def generate_block_content(self):
        return json.dumps(asdict(self)).encode()


@dataclass
class KeyBlock:
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
        return KeyBlock(
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
            id=None,
            type=self.old_key_type,
            public_key=self.old_key,
            private_key=None
        )

    def get_new_key(self):
        return Key(
            id=None,
            type=self.new_key_type,
            public_key=self.new_key,
            private_key=None
        )


def verify_key_update(key_block_1: KeyBlock, key_block_2: KeyBlock):
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


@dataclass
class DidDocBlock:
    did_doc: dict
    signature: str

    priblocks_version: tuple

    @staticmethod
    def new(
        did_doc: dict
    ):
        return DidDocBlock(
            did_doc=did_doc,
            priblocks_version=PRIBLOCKS_VERSION,
            signature=""
        )

    @classmethod
    def load_from_block_content(cls, block_content):
        return cls(**json.loads(block_content.decode()))

    def generate_block_content(self):
        return json.dumps(asdict(self)).encode()

    def get_signature_data(self):
        return json.dumps(self.did_doc).encode()

    def sign(self, crypt):
        self.signature = bytes_to_string(crypt.sign(self.get_signature_data()))

    def verify_signature(self, key):
        return verify_signature(
            key.type,
            bytes_from_string(self.signature),
            self.get_signature_data(),
            bytes_from_string(key.public_key)
        )


def get_latest_control_key(blockchain: Blockchain):
    # get all key blocks from blockchain
    ctrl_key_blocks = [
        KeyBlock.load_from_block_content(
            blockchain.get_block(block_id).content
        )
        for block_id in blockchain.block_ids
        if 'control_key' in walytis_api.decode_short_id(block_id)['topics']
    ]

    # ensure the first KeyBlock has identical current and new keys
    if not (
        ctrl_key_blocks[0].old_key == ctrl_key_blocks[0].new_key
        and ctrl_key_blocks[0].old_key_type == ctrl_key_blocks[0].new_key_type
    ):
        raise Exception("First key block doesn't have identical keys!")

    # iterate through key updates, verifying them
    # to determine the currently valid KeyBlock
    i = 1
    last_key_block = ctrl_key_blocks[0]
    while i < len(ctrl_key_blocks):
        if verify_key_update(last_key_block, ctrl_key_blocks[i]):
            last_key_block = ctrl_key_blocks[i]
        i += 1

    control_key = last_key_block.get_new_key()
    return control_key


def get_latest_did_doc(blockchain: Blockchain):
    last_key_block = None
    last_did_block = None
    for block_id in blockchain.block_ids:
        # if this block is a control key update block
        if 'control_key' in walytis_api.decode_short_id(block_id)['topics']:
            # load block content
            ctrl_key_block = KeyBlock.load_from_block_content(
                blockchain.get_block(block_id).content
            )
            # if we haven't processed this blockchain's first ctrl key yet
            if not last_key_block:
                # ensure the first KeyBlock has identical current and new keys
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
                if verify_key_update(last_key_block, ctrl_key_block):
                    last_key_block = ctrl_key_block
                else:
                    print("Found Control Key Block with invalid signature")

        # if this block is a DID-documement publication
        if 'did_doc' in walytis_api.decode_short_id(block_id)['topics']:
            # load block content
            did_doc_block = DidDocBlock.load_from_block_content(
                blockchain.get_block(block_id).content
            )
            # if its signature is validated by the last ctrl key
            if did_doc_block.verify_signature(last_key_block.get_new_key()):
                # set this to the latest DID-doc-block
                last_did_block = did_doc_block
            else:
                print("Found DID-Doc Block with invalid signature")

    # return the DID-document of the last valid DID-Doc block
    if last_did_block:
        return last_did_block.did_doc
    else:
        print("No valid DID doc blocks found")
