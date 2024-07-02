"""Classes for managing Person and Device identities."""

import json
import os
import time
from datetime import datetime, timedelta
from threading import Thread
from typing import Type, TypeVar

import brenthy_tools_beta
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
    Blockchain,
    BlockchainAlreadyExistsError,
    decode_short_id,
    list_blockchain_ids,
)

from .did_manager import DidManager, blockchain_id_from_did
from .did_manager_blocks import (
    KeyOwnershipBlock,
    MemberInvitationBlock,
    MemberJoiningBlock,
    get_latest_control_key,
    get_latest_did_doc,
    get_info_blocks,
)
from .did_objects import Key
from .key_store import KeyStore, UnknownKeyError
from .settings import CTRL_KEY_MAX_RENEWAL_DUR_HR, CTRL_KEY_RENEWAL_AGE_HR
from .utils import validate_did_doc

DID_METHOD_NAME = "wlaytis-contacts"
DID_URI_PROTOCOL_NAME = "waco"  # https://www.rfc-editor.org/rfc/rfc3986#section-3.1

CRYPTO_FAMILY = "EC-secp256k1"


_IdentityAccess = TypeVar(
    '_IdentityAccess', bound='IdentityAccess'
)


class IdentityAccess:
    """Class for managing a person's identity."""

    def __init__(
        self,
        person_did_manager: DidManager,
        member_did_manager: DidManager,
        config_dir: str,
        key: Key,
    ):
        self.member_did_manager = member_did_manager
        self.config_dir = config_dir
        self.key = key
        self.person_did_manager = person_did_manager
        self.config_file = os.path.join(config_dir, "person_id.json")
        self.person_keystore_file = os.path.join(
            config_dir, "person_keys.json")
        self.member_keystore_file = os.path.join(
            config_dir, "member_keys.json")
        self.candidate_keys: dict[str, list[str]] = {}
        self.get_published_candidate_keys()

        self.key_requests_listener = ConversationListener(
            f"{self.member_did_manager.get_did()}-KeyRequests",
            self.key_requests_handler
        )
        self._terminate = False
        self.control_key_manager_thr = Thread(
            target=self.manage_control_key
        )
        self.control_key_manager_thr.start()

    def assert_ownership(self) -> None:
        """If we don't yet own the control key, get it."""
        control_key = self.person_did_manager.get_control_key()
        if control_key.private_key:
            return

        logger.debug("Not yet control key owner...")
        while not self._terminate:
            for member in self.get_members():
                if self._terminate:
                    return
                did = member["did"]
                if did == self.member_did_manager.get_did():
                    continue
                # logger.debug(f"Requesting control key from {did}")
                try:
                    key = self.request_key(control_key.get_key_id(), did)
                except IncompletePeerInfoError:
                    continue
                if key:
                    self.person_did_manager.key_store.add_key(key)
                    if self.person_did_manager.get_control_key().private_key:
                        self.person_did_manager.update_did_doc(
                            self.generate_did_doc())
                        return
                    else:
                        logger.warning(
                            "Strange, Control key hasn't unlocked after key reception."
                        )
                # logger.warning("Request for control key failed.")
            time.sleep(0.5)

        # log.debug("Got control key ownership!")

    def manage_control_key(self):

        while not self._terminate:
            self.assert_ownership()
            time.sleep(1)
            self.check_prepare_control_key_update()
            self.check_apply_control_key_update()

    @classmethod
    def create(
        cls: Type[_IdentityAccess],
        config_dir: str,
        key: Key,
    ) -> _IdentityAccess:
        """Create a new IdentityAccess object."""
        person_keystore_file = os.path.join(config_dir, "person_keys.json")
        member_keystore_file = os.path.join(config_dir, "member_keys.json")
        key_store = KeyStore(person_keystore_file, key)
        # logger.debug("Creating Person-Did-Manager...")
        person_did_manager = DidManager.create(key_store)
        # logger.debug("Creating Device-Did-Manager...")

        # create member did manager
        member_did_manager = DidManager.join_as_member(
            invitation=person_did_manager.invite_member(),
            blockchain=person_did_manager.blockchain,
            member_keystore_file=member_keystore_file,
            key=key,
        )

        # logger.debug("Creating Identity...")
        person_id_acc = cls(
            person_did_manager,
            member_did_manager,
            config_dir,
            key,
        )
        person_id_acc.save_appdata()
        person_id_acc.member_did_manager.update_did_doc(
            person_id_acc.generate_member_did_doc())
        return person_id_acc

    @classmethod
    def load_from_appdata(
        cls: Type[_IdentityAccess],
        config_dir: str,
        key: Key,
    ) -> _IdentityAccess:
        """Load a saved IdentityAccess object from appdata."""
        config_file = os.path.join(config_dir, "person_id.json")
        person_keystore_file = os.path.join(config_dir, "person_keys.json")
        member_keystore_file = os.path.join(config_dir, "member_keys.json")

        with open(config_file, "r") as file:
            data = json.loads(file.read())

        person_did_manager = DidManager(
            blockchain=data["person_blockchain"],
            key_store=KeyStore(person_keystore_file, key),
        )
        member_did_manager = DidManager(
            blockchain=data["member_blockchain"],
            key_store=KeyStore(member_keystore_file, key),
        )

        identity_access = cls(
            person_did_manager,
            member_did_manager,
            config_dir,
            key,
        )

        return identity_access

    @classmethod
    def join(
        cls: Type[_IdentityAccess],
        invitation: str | dict,
        config_dir: str,
        key: Key,
    ) -> _IdentityAccess:
        """Create a new IdentityAccess object."""
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

        member_keystore_file = os.path.join(config_dir, "member_keys.json")
        person_keystore_file = os.path.join(config_dir, "person_keys.json")

        # create member did manager
        member_did_manager = DidManager.join_as_member(
            invitation=invitation,
            blockchain=blockchain,
            member_keystore_file=member_keystore_file,
            key=key,
        )
        key_store = KeyStore(person_keystore_file, key)
        person_did_manager = DidManager(
            blockchain,
            key_store
        )

        person_id_acc = cls(
            person_did_manager,
            member_did_manager,
            config_dir,
            key,
        )
        person_id_acc.save_appdata()
        person_id_acc.member_did_manager.update_did_doc(
            person_id_acc.generate_member_did_doc())

        return person_id_acc

    def invite_member(self) -> dict:
        return self.person_did_manager.invite_member()

    def serialise(self) -> dict:
        """Generate this Identity's appdata."""
        return {
            "person_blockchain": self.person_did_manager.blockchain.blockchain_id,
            "member_blockchain": self.member_did_manager.blockchain.blockchain_id,
        }

    def save_appdata(self) -> None:
        """Write this identy's appdata to a file."""
        data = json.dumps(self.serialise())
        with open(self.config_file, "w+") as file:
            file.write(data)

    def get_members(self) -> list:
        """Get the current list of member-members."""
        members = self.person_did_manager.get_members()
        if not members:
            return []
        return members

    def generate_did_doc(self) -> dict:
        """Generate a DID-document."""
        did_doc = {
            "id": self.person_did_manager.get_did(),
            "verificationMethod": [
                self.person_did_manager.get_control_key().generate_key_spec(
                    self.person_did_manager.get_did())

                # key.generate_key_spec(self.person_did_manager.get_did())
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
            "id": self.member_did_manager.get_did(),
            "verificationMethod": [
                self.member_did_manager.get_control_key().generate_key_spec(
                    self.member_did_manager.get_did())
                # key.generate_key_spec(self.person_did_manager.get_did())
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
            "owner": self.member_did_manager.get_did(),
            "key_id": key.get_key_id()
        }
        sig = bytes_to_string(key.sign(json.dumps(key_ownership).encode()))
        key_ownership.update({"proof": sig})
        block = KeyOwnershipBlock.new(key_ownership)
        self.person_did_manager.add_info_block(block)

    def key_requests_handler(self, conv_name: str, peer_id: str) -> None:
        """Respond to key requests from other members."""
        # logger.debug(f"KRH: Getting key request! {conv_name} {peer_id}")
        conv = Conversation()
        conv.join(
            conv_name,
            peer_id,
            conv_name
        )
        # logger.debug("RKH: Joined conversation.")
        success = conv.say("Hello there!".encode())
        if not success:
            # logger.debug("RKH: failed to communicate with peer.")
            conv.terminate()
            return
        try:
            message = json.loads(conv.listen(timeout=10).decode())
            # logger.debug("RKH: got message.")
            peer_did = message["did"]
            key_id = message["key_id"]
            sig = bytes.fromhex(message["signature"])

            message.pop("signature")
            try:
                peer_key = self.get_member_control_key(peer_did)
            except NotMemberError as error:
                logger.warning(error)
                # logger.debug(peer_did)
                conv.say(json.dumps({
                    "error": "NotMemberError",
                }).encode())
                conv.terminate()
                return
            # logger.debug("RKH: got peer's key.")

            if not peer_key.verify_signature(sig, json.dumps(message).encode()):

                conv.say(json.dumps({
                    "error": "authenitcation failed",
                    "peer_public_key": peer_key.get_public_key()
                }).encode())
                conv.terminate()
                logger.warning("KRH: authentication failed.")
                return
            try:
                key = self.person_did_manager.key_store.get_key(key_id)
            except UnknownKeyError:
                conv.say(json.dumps({
                    "error": "I don't own this key.",
                    "peer_public_key": peer_key.get_public_key()
                }).encode())
                conv.terminate()
                logger.warning("KRH: Don't have requested key.")
                return

            conv.say(json.dumps({
                "private_key": peer_key.encrypt(key.private_key).hex()
            }).encode())
            # logger.debug("KRH: Shared key!")

        except Exception as error:
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
                return None
            # logger.debug("RK: started conversation")
            key = self.member_did_manager.get_control_key()
            # logger.debug("RK: Got contrail key")
            message = {
                "did": self.member_did_manager.get_did(),
                "key_id": key_id,
            }
            message.update({"signature": key.sign(
                json.dumps(message).encode()).hex()})
            salutation = conv.listen(timeout=10)
            # logger.debug(salutation)
            success = conv.say(json.dumps(message).encode(), )
            if not success:
                logger.debug("Timeout communicating with peer when getting key.")
                conv.close()
                return None
            try:
                response = json.loads(conv.listen(timeout=10).decode())
            except ConvListenTimeout:
                logger.debug("Timeout communicating with peer.")
                conv.close()
                return None
            # logger.debug("RK: Got Response!")
            conv.close()

        except Exception as error:
            # logger.warning(traceback.format_exc())
            logger.warning(f"Error in request_key: {type(error)} {error}")
            conv.close()
            return None

        if "error" in response.keys():
            logger.warning(response)
            return None
        private_key = key.decrypt(bytes.fromhex(response["private_key"]))
        key = Key.from_key_id(key_id)
        key.unlock(private_key)
        self.person_did_manager.key_store.add_key(key)
        self.publish_key_ownership(key)
        return key

    def get_published_candidate_keys(self) -> dict["str", list[str]]:
        """Update our list of candidate control keys and their owners."""
        candidate_keys: dict[str, list[str]] = {}
        for block_id in self.person_did_manager.blockchain.block_ids[::-1]:
            metadata = decode_short_id(block_id)
            if KeyOwnershipBlock.walytis_block_topic not in metadata["topics"]:
                continue
            key_expiry = (
                self.person_did_manager.get_control_key().creation_time +
                timedelta(hours=CTRL_KEY_RENEWAL_AGE_HR)
            )
            if metadata["creation_time"] < key_expiry:
                key_ownership = KeyOwnershipBlock.load_from_block_content(
                    self.person_did_manager.blockchain.get_block(
                        block_id).content
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
        ctrl_key_timestamp = self.person_did_manager.get_control_key().creation_time
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
                if key_id not in self.person_did_manager.key_store.keys.keys():
                    for member in members:
                        if self._terminate:
                            return True
                        if member == self.member_did_manager.get_did():
                            continue
                        key = self.request_key(key_id, member)
                        if key:
                            self.candidate_keys[key_id] += self.member_did_manager.get_did()
                            break
            return True

        key = Key.create(CRYPTO_FAMILY)
        self.person_did_manager.key_store.add_key(key)
        self.candidate_keys.update(
            {key.get_key_id(): [self.member_did_manager.get_did()]}
        )
        self.save_appdata()

        self.publish_key_ownership(key)
        return True

    def check_apply_control_key_update(self) -> bool:
        """Check if we should renew our DID-manager's control key."""
        # logger.debug("Checking control key update application...")
        if not self.candidate_keys:
            return False

        ctrl_key_timestamp = self.person_did_manager.get_control_key().creation_time
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

        self.person_did_manager.renew_control_key(new_control_key)
        self.candidate_keys = {}
        self.save_appdata()
        return True

    def delete(self) -> None:
        """Delete this Identity."""
        self.terminate()
        self.member_did_manager.delete()
        self.person_did_manager.delete()

    def terminate(self) -> None:
        """Stop this Identity object, cleaning up resources."""
        if not self._terminate:
            self._terminate = True
            self.member_did_manager.terminate()
            self.person_did_manager.terminate()
            self.key_requests_listener.terminate()

            self.control_key_manager_thr.join()

    def __del__(self):
        """Stop this Identity object, cleaning up resources."""
        self.terminate()


class IncompletePeerInfoError(Exception):
    """When a peer's DID document doesn't contain all the info we need."""


class NotMemberError(Exception):
    """When a peer isn't among our members."""


# decorate_all_functions(strictly_typed, __name__)
