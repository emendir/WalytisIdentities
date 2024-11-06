"""Classes for managing Person and Device identities."""
import json
import os
import time
from datetime import datetime, timedelta
from threading import Thread
from time import sleep
from typing import Callable, Type, TypeVar

import ipfs_api
import ipfs_datatransmission
import walytis_beta_api
import walytis_beta_api as walytis_beta
from brenthy_tools_beta.utils import bytes_to_string, string_to_bytes
from ipfs_datatransmission import (
    Conversation,
    ConversationListener,
    ConvListenTimeout,
)
from loguru import logger
from walytis_beta_api import (
    Block,
    Blockchain,
    BlockchainAlreadyExistsError,
    decode_short_id,
    list_blockchain_ids,
)
import walytis_beta_api as waly
from . import did_manager_blocks
from .did_manager import DidManager, blockchain_id_from_did
from .did_manager_blocks import (
    KeyOwnershipBlock,
    MemberInvitationBlock,
    MemberJoiningBlock,
    MemberLeavingBlock,
    MemberUpdateBlock,
    get_block_type,
    get_info_blocks,
    get_latest_control_key,
    get_latest_did_doc,
    get_members,
)
from .did_objects import Key
from .key_store import KeyStore, UnknownKeyError
from .settings import CTRL_KEY_MAX_RENEWAL_DUR_HR, CTRL_KEY_RENEWAL_AGE_HR
from .utils import validate_did_doc

DID_METHOD_NAME = "wlaytis-contacts"
DID_URI_PROTOCOL_NAME = "waco"  # https://www.rfc-editor.org/rfc/rfc3986#section-3.1

CRYPTO_FAMILY = "EC-secp256k1"


_GroupDidManager = TypeVar(
    '_GroupDidManager', bound='GroupDidManager'
)


class _GroupDidManager(DidManager):
    """DidManager with member-managment functionality.

    Includes functionality for keeping a list of member-DIDs, including
    the cryptographic invitations for independent joining of new members.
    DOES NOT include control-key sharing functionality, that is coded in
    GroupDidManager, which inherits this class.
    """

    def __init__(
        self,
        blockchain_id: str,
        key_store: KeyStore,
        other_blocks_handler: Callable[[Block], None] | None = None,
        appdata_dir: str = "",
    ):
        self._gdm_other_blocks_handler = other_blocks_handler
        DidManager.__init__(
            self,
            blockchain_id=blockchain_id,
            key_store=key_store,
            # we handle member management blocks
            other_blocks_handler=self.on_block_received_members,
            appdata_dir=appdata_dir,
        )
        self.members_list = list(get_members(self.blockchain).values())

    def on_block_received_members(self, block: Block) -> None:
        # logger.debug("DM: Received block!")
        block_type = get_block_type(block.topics)

        match block_type:
            case (
                did_manager_blocks.MemberJoiningBlock
                | did_manager_blocks.MemberUpdateBlock
                | did_manager_blocks.MemberLeavingBlock
            ):
                self.members_list = list(get_members(self.blockchain).values())
            case 0:
                logger.warning(
                    f"DM: Did not recognise block type: {block_type}")
                # if user defined an event-handler for non-DID blocks, call it
                if self._dm_other_blocks_handler:
                    self._dm_other_blocks_handler(block)

    def get_members(self) -> list[dict]:
        """Get the current list of member-members."""
        if not self.members_list:
            self.members_list = list(get_members(self.blockchain).values())
            if self.members_list is None:
                return []

        return self.members_list

    def add_member_invitation(self, member_invitation: dict) -> Block:
        member_invitation_block = MemberInvitationBlock.new(member_invitation)
        return self.add_info_block(member_invitation_block)

    def add_member_update(self, member: dict) -> Block:
        block = MemberUpdateBlock.new(member)
        return self.add_info_block(block)
    def add_member_leaving(self, member: dict) -> Block:
        block = MemberLeavingBlock.new(member)
        return self.add_info_block(block)

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
        member:DidManager
    )->None:
        """Adds an existing DID-Manager as a member to this Group-DID.

        """
        invitation_key = Key.create(CRYPTO_FAMILY)

        group_blockchain_invitation = json.loads(
            self.blockchain.create_invitation(
                one_time=False, shared=True
            )
        )
        member_invitation = {
            "blockchain_invitation": group_blockchain_invitation,
            "invitation_key":invitation_key.get_key_id()
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
        self.add_info_block(joining_block)
        member.key_store.add_key(self.get_control_key())
    @staticmethod
    def create_member(
        invitation: dict,
        blockchain: Blockchain,
        member_keystore_file: str,
        key: Key,
    ) -> DidManager:
        """Creating a new member DID-Manager joining an existing Group-DID.

        Returns the member's DidManager.
        """
        # logger.debug("DM: Member joining a did_manager.")
        invitation_key = Key.from_key_id(invitation["invitation_key"])
        try:
            invitation_key.unlock(invitation["private_key"])
        except:
            raise IdentityJoinError(
                "Invalid invitation: public-private key mismatch"
            )

        # make sure the Group-DID-Manager has the invitation block
        invitation_block = MemberInvitationBlock.load_from_block_content(
            
            blockchain.get_block(
                string_to_bytes(invitation["invitation_block_id"])
            ).content
        )
        if invitation_block.get_member_invitation()["invitation_key"] != invitation["invitation_key"]:
            raise IdentityJoinError("Looks like a corrupt invitation")

        member_keystore = KeyStore(member_keystore_file, key)
        member_did_manager = DidManager.create(member_keystore)

        joining_block = MemberJoiningBlock.new({
            "did": member_did_manager.did,
            "invitation": member_did_manager.blockchain.create_invitation(
                one_time=False, shared=True
            ),  # invitation for other's to join our member DID blockchain
            "invitation_key": invitation["invitation_key"]  # Key object
        })
        joining_block.sign(invitation_key)
        blockchain.add_block(
            joining_block.generate_block_content(),
            joining_block.walytis_block_topic
        )
        return member_did_manager


class GroupDidManager(_GroupDidManager):
    """DidManager controlled by multiple member DIDs.

    Includes functionality for sharing of the Group DID's control key
    among the member DIDs.
    """
    members_list: list | None

    def __init__(
        self,
        config_dir: str,
        key: Key,
        other_blocks_handler: Callable[[Block], None] | None = None,
    ):
        self._terminate = False
        self.config_dir = config_dir
        self.lock_file = os.path.join(config_dir, ".GroupDidManager.lock")
        if os.path.exists(self.lock_file):
            raise Exception(
                "It looks like another application is currently working with "
                "this DID-Manager's appdata!"
            )
        with open(self.lock_file, "w+") as lock_file:
            lock_file.write("Running...")
        self.config_file = os.path.join(self.config_dir, "group_did_metadata.json")
        self.group_appdata_dir = os.path.join(self.config_dir, "group_did")
        self.group_keystore_file = os.path.join(
            self.group_appdata_dir, "group_did_keys.json"
        )
        self.member_appdata_dir = os.path.join(self.config_dir, "member_did")
        self.member_keystore_file = os.path.join(
            self.member_appdata_dir, "member_did_keys.json"
        )

        with open(self.config_file, "r") as file:
            data = json.loads(file.read())

        self.member_did_manager = DidManager(
            blockchain_id=data["member_blockchain"],
            key_store=KeyStore(self.member_keystore_file, key),
        )

        _GroupDidManager.__init__(
            self,
            blockchain_id=data["group_blockchain"],
            key_store=KeyStore(self.group_keystore_file, key),
            other_blocks_handler=other_blocks_handler,
        )

        self.candidate_keys: dict[str, list[str]] = {}
        self.get_published_candidate_keys()

        self.key_requests_listener = ConversationListener(
            f"{self.member_did_manager.did}-KeyRequests",
            self.key_requests_handler
        )
        self._terminate = False
        self.control_key_manager_thr = Thread(
            target=self.manage_control_key
        )
        self.control_key_manager_thr.start()

    @classmethod
    def from_did_managers(
        cls,
        group_did_manager: DidManager,
        member_did_manager: DidManager,
        config_dir: str,
    ):
        return cls(
            group_did_manager.blockchain,
            group_did_manager.key_store,
            config_dir=config_dir,
            member_did_manager=member_did_manager,
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
            return

        logger.debug(f"Not yet control key owner: {control_key.get_key_id()}")
        while not self._terminate:
            for member in self.get_members():
                if self._terminate:
                    return
                did = member["did"]
                if did == self.member_did_manager.did:
                    continue
                # logger.debug(f"Requesting control key from {did}")
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
                # logger.warning("Request for control key failed.")
            sleep(0.5)

        # log.debug("Got control key ownership!")

    def manage_control_key(self):

        while not self._terminate:
            self.assert_ownership()
            time.sleep(1)
            self.check_prepare_control_key_update()
            self.check_apply_control_key_update()

    @classmethod
    def create(
        cls: Type[_GroupDidManager],
        config_dir: str,
        key: Key,   # for unlocking keystores in config dir
        member:DidManager|None=None
    ) -> _GroupDidManager:
        """Create a new GroupDidManager object."""
        
        config_file = os.path.join(config_dir, "group_did_metadata.json")
        group_appdata_dir = os.path.join(config_dir, "group_did")
        group_keystore_file = os.path.join(
            group_appdata_dir, "group_did_keys.json"
        )
        if not os.path.exists(group_appdata_dir):
            os.makedirs(group_appdata_dir)

        key_store = KeyStore(group_keystore_file, key)
        # logger.debug("Creating Person-Did-Manager...")
        g_did_manager = _GroupDidManager.create(key_store)
        # logger.debug("Creating Device-Did-Manager...")

        member_appdata_dir = os.path.join(config_dir, "member_did")
        member_keystore_file = os.path.join(
                member_appdata_dir, "member_did_keys.json"
            )
        if not os.path.exists(member_appdata_dir):
            os.makedirs(member_appdata_dir)
        if member:
            member_did_manager= member
            os.symlink(member.key_store.key_store_path, member_keystore_file)
            g_did_manager.add_member(member)
        else:
            # create member did manager
            member_did_manager = cls.create_member(
                invitation=g_did_manager.invite_member(),
                blockchain=g_did_manager.blockchain,
                member_keystore_file=member_keystore_file,
                key=key,
            )
        cls.init_appdata(config_file, g_did_manager, member_did_manager)

        g_did_manager.terminate()  # group_did_manager will take over
        member_did_manager.terminate()
        # logger.debug("Creating Identity...")
        group_did_manager = cls(
            config_dir,
            key=key,
        )
        group_did_manager.member_did_manager.update_did_doc(
            group_did_manager.generate_member_did_doc())
        return group_did_manager

    @classmethod
    def join(
        cls: Type[_GroupDidManager],
        invitation: str | dict,
        config_dir: str,
        key: Key,
        member:DidManager|None=None
    ) -> _GroupDidManager:
        """Join an exisiting Group-DID-Manager.
        
        Uses the provided DidManager as the member if provided,
        otherwise creates a new member DID.

        Returns an GroupDidManager object.
        """
        if isinstance(invitation, str):
            invitation = json.loads(invitation)
        blockchain_invitation: dict = invitation["blockchain_invitation"]

        # join blockchain
        try:
            # logger.debug(f"Joining blockchain {blockchain_invitation}")
            walytis_beta.log.PRINT_DEBUG = True
            blockchain = Blockchain.join(blockchain_invitation)
        except BlockchainAlreadyExistsError:
            blockchain = Blockchain(blockchain_invitation["blockchain_id"])
            
        member_appdata_dir = os.path.join(config_dir, "member_did")
        member_keystore_file = os.path.join(
                member_appdata_dir, "member_did_keys.json"
            )
        if not os.path.exists(member_appdata_dir):
            os.makedirs(member_appdata_dir)
        if member:
            member_did_manager= member
            os.symlink(member.key_store.key_store_path, member_keystore_file)
        else:
                # create member did manager
                member_did_manager = cls.create_member(
                    invitation=invitation,
                    blockchain=blockchain,
                    member_keystore_file=member_keystore_file,
                    key=key,
                )
        config_file = os.path.join(config_dir, "group_did_metadata.json")
        group_appdata_dir = os.path.join(config_dir, "group_did")
        group_keystore_file = os.path.join(
            group_appdata_dir, "group_did_keys.json"
        )
        if not os.path.exists(group_appdata_dir):
            os.makedirs(group_appdata_dir)
        key_store = KeyStore(group_keystore_file, key)
        blockchain.terminate()
        
        g_did_manager = _GroupDidManager(
            blockchain.blockchain_id,
            key_store,
        )
        cls.init_appdata(config_file, g_did_manager, member_did_manager)
        g_did_manager.terminate()   # group_did_manager will take over from here
        member_did_manager.terminate()
        group_did_manager = cls(
            config_dir,
            key=key,
        )
        
        group_did_manager.member_did_manager.update_did_doc(
            group_did_manager.generate_member_did_doc())

        return group_did_manager

    def serialise(self) -> dict:
        """Generate this Identity's appdata."""
        return {
            "group_blockchain": self.blockchain.blockchain_id,
            "member_blockchain": self.member_did_manager.blockchain.blockchain_id,
        }

    @staticmethod
    def init_appdata(
        config_file,
        group_did_manager: _GroupDidManager,
        member_did_manager: DidManager
    ) -> None:
        """Create appdata file for new GroupDidManager object."""
        data = json.dumps({
            "group_blockchain": group_did_manager.blockchain.blockchain_id,
            "member_blockchain": member_did_manager.blockchain.blockchain_id,
        })
        with open(config_file, "w+") as file:
            file.write(data)

    def save_appdata(self) -> None:
        """Write this identy's appdata to a file."""
        data = json.dumps(self.serialise())
        with open(self.config_file, "w+") as file:
            file.write(data)

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
                {"did": member["did"], "invitation": member["invitation"]}
                for member in self.get_members()
            ]
        }

        # check that components produce valid URIs
        validate_did_doc(did_doc)
        return did_doc

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
            "ipfs_peer_id": ipfs_api.my_id()
        }

        # check that components produce valid URIs
        validate_did_doc(did_doc)
        return did_doc

    def publish_key_ownership(self, key: Key) -> None:
        """Publish a public key and proof that we have it's private key."""
        key_ownership = {
            "owner": self.member_did_manager.did,
            "key_id": key.get_key_id()
        }
        sig = bytes_to_string(key.sign(json.dumps(key_ownership).encode()))
        key_ownership.update({"proof": sig})
        block = KeyOwnershipBlock.new(key_ownership)
        self.add_info_block(block)

    def key_requests_handler(self, conv_name: str, peer_id: str) -> None:
        """Respond to key requests from other members."""
        # logger.debug(f"KRH: Getting key request! {conv_name} {peer_id}")
        conv = Conversation()
        # logger.debug("Joining conv...")
        try:
            conv.join(
                conv_name,
                peer_id,
                conv_name
            )
        except ipfs_datatransmission.CommunicationTimeout:
            logger.warning("KRH: failed to join conversation")
            conv.close()
            return
        # logger.debug("Joined conv!")
        # logger.debug("KRH: Joined conversation.")
        success = conv.say("Hello there!".encode())
        if not success:
            # logger.debug("KRH: failed at salutation.")
            conv.terminate()
            return
        try:
            try:
                message = json.loads(conv.listen(timeout=5).decode())
            except ConvListenTimeout:
                logger.warning("Timeout waiting for key request.")
                conv.close()
                return None
            # logger.debug("KRH: got key request.")
            peer_did = message["did"]
            key_id = message["key_id"]
            sig = bytes.fromhex(message["signature"])

            message.pop("signature")
            try:
                peer_key = self.get_member_control_key(peer_did)
            except NotMemberError as error:
                logger.warning(error)
                # logger.debug(peer_did)
                success = conv.say(json.dumps({
                    "error": "NotMemberError",
                }).encode())
                conv.terminate()
                if not success:
                    logger.warning(
                        "KRH: Failed sending response NotMemberError")
                return
            # logger.debug("KRH: got peer's key.")

            if not peer_key.verify_signature(sig, json.dumps(message).encode()):

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
            private_key = None
            try:
                key = self.key_store.get_key(key_id)
                private_key = key.private_key
            except UnknownKeyError:
                private_key = None
            if not private_key:
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

            success = conv.say(json.dumps({
                "private_key": peer_key.encrypt(private_key).hex()
            }).encode())
            if not success:
                logger.warning("KRH: Failed sending response with key.")
            # else:
                # logger.debug(f"KRH: Shared key!: {key.get_key_id()}")
            conv.terminate()

        except Exception as error:
            import traceback
            traceback.print_exc()
            logger.error(f"Error in key_requests_handler: {error}")
            conv.terminate()

    def get_member_ipfs_id(self, did: str) -> str:
        """Get the IPFS content ID of another member."""
        results = [member for member in self.get_members()
                   if member["did"] == did]

        if not results:
            logger.debug([member["did"] for member in self.get_members()])
            raise NotMemberError(f"This DID is not among our members.\n{did}")
        if len(results) > 1:
            raise Exception(
                "Found more than one entry for did in members list.")
        member = results[0]
        invitation = json.loads(member["invitation"])
        blockchain_id = blockchain_id_from_did(did)
        if not blockchain_id == invitation["blockchain_id"]:
            raise Exception(f"Found corrupt members entry for peer {did}")
        if "blockchain" not in member.keys():
            # logger.debug("Blockchain not cached")
            if invitation["blockchain_id"] in list_blockchain_ids():
                blockchain = Blockchain(blockchain_id)
            else:
                # logger.debug(f"Joining blockchain {invitation}")
                try:
                    blockchain = Blockchain.join(invitation)
                except walytis_beta_api.exceptions.JoinFailureError as error:
                    logger.error(error)
                    logger.debug("Retrying to join")

                    blockchain = Blockchain.join(invitation)
            member.update({"blockchain": blockchain})
        else:
            # logger.debug("USing chached blockchain")
            blockchain = member["blockchain"]

        did_doc = get_latest_did_doc(blockchain)
        blockchain.terminate()
        peer_id = did_doc.get("ipfs_peer_id", None)
        if not peer_id:
            logger.warning(f"Member has no full DID-Doc: {did}")
            logger.warning(did_doc)
            raise IncompletePeerInfoError()
        return peer_id

    def get_member_control_key(self, did: str) -> Key:
        """Get the DID control key of another member."""
        members = [member for member in self.get_members()
                   if member["did"] == did]
        if not members:
            raise NotMemberError("This DID is not among our members.")
        member = members[0]
        blockchain_id = blockchain_id_from_did(did)
        if blockchain_id not in list_blockchain_ids():
            if blockchain_id != json.loads(member["invitation"])["blockchain_id"]:
                logger.error(
                    "Invalid member entry:"
                    f"{blockchain_id}"
                    f"{json.loads(member['invitation'])['blockchain_id']}"
                )
                blockchain = Blockchain(blockchain_id)
            else:
                blockchain = Blockchain.join(member["invitation"])
        else:
            blockchain = Blockchain(blockchain_id)

        ctrl_key = get_latest_control_key(blockchain)
        blockchain.terminate()
        return ctrl_key

    def request_key(self, key_id: str, did: str) -> Key | None:
        """Request a key from another member."""
        key = self.member_did_manager.get_control_key()
        key_request_message = {
            "did": self.member_did_manager.did,
            "key_id": key_id,
        }
        key_request_message.update({"signature": key.sign(
            json.dumps(key_request_message).encode()).hex()})

        peer_id = self.get_member_ipfs_id(did)
        # logger.debug("RK: Requesting key...")
        try:
            conv = Conversation()
            try:
                conv.start(
                    conv_name=f"KeyRequest-{key_id}",
                    peer_id=peer_id,
                    others_req_listener=f"{did}-KeyRequests",
                )
            except ipfs_datatransmission.CommunicationTimeout:
                logger.warning(
                    "RK: Failed at key request (timeout): "
                    f"KeyRequest-{key_id}, "
                    f"{peer_id}, {did}-KeyRequests"
                )
                conv.close()
                return None
            # logger.debug("RK: started conversation")

            try:
                salutation = conv.listen(timeout=5)
            except ConvListenTimeout:
                logger.warning("RK: Timeout waiting for salutation.")
                conv.close()
                return None
            # logger.debug(salutation)
            sleep(0.15)
            success = conv.say(json.dumps(key_request_message).encode(), )
            if not success:
                logger.warning(
                    "RK: Timeout communicating when requesting key.")
                conv.close()
                return None
            try:
                response = json.loads(conv.listen(timeout=5).decode())
            except ConvListenTimeout:
                logger.warning("RK: Timeout waiting for key response.")
                conv.close()
                return None
            # logger.debug("RK: Got Response!")
            conv.close()

        except Exception as error:
            # logger.warning(traceback.format_exc())
            logger.warning(f"RK: Error in request_key: {type(error)} {error}")
            conv.close()
            return None

        if "error" in response.keys():
            logger.warning(response)
            return None
        private_key = key.decrypt(bytes.fromhex(response["private_key"]))
        key = Key.from_key_id(key_id)
        key.unlock(private_key)
        self.key_store.add_key(key)
        self.publish_key_ownership(key)
        # logger.debug(f"RK: Got key!: {key.get_key_id()}")
        return key

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
            self.save_appdata()
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
                        if member == self.member_did_manager.did:
                            continue
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
        self.save_appdata()

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
        self.save_appdata()
        return True

    def delete(self) -> None:
        """Delete this Identity."""
        self.terminate()
        self.member_did_manager.delete()
        DidManager.delete(self)

    def terminate(self) -> None:
        """Stop this Identity object, cleaning up resources."""
        if not self._terminate:
            self._terminate = True
            try:
                self.key_requests_listener.terminate()
            except:
                pass
            try:
                self.member_did_manager.terminate()
            except:
                pass
            try:
                DidManager.terminate(self)
            except:
                pass
            try:
                self.control_key_manager_thr.join()
            except:
                pass
            os.remove(self.lock_file)

    def __del__(self):
        """Stop this Identity object, cleaning up resources."""
        self.terminate()


class IncompletePeerInfoError(Exception):
    """When a peer's DID document doesn't contain all the info we need."""


class NotMemberError(Exception):
    """When a peer isn't among our members."""


class IdentityJoinError(Exception):
    """When `DidManager.create_member()` fails."""

    def __init__(self, message: str):
        self.message = message

    def __str__(self):
        return self.message
# decorate_all_functions(strictly_typed, __name__)
