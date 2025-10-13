from ipfs_tk_transmission import Conversation
from walytis_identities.key_store import CodePackage
from .utils import generate_random_string
from brenthy_tools_beta.utils import bytes_to_string, string_to_bytes
from multi_crypt import Crypt
import multi_crypt
from threading import Thread
from datetime import datetime
import threading
from time import sleep
import json
from walytis_beta_embedded import ipfs
from walytis_identities.did_manager_with_supers import DidManagerWithSupers
from walytis_identities.did_manager_blocks import MemberJoiningBlock
from typing import Callable
import walytis_beta_api
from walytis_beta_embedded import ipfs

from walytis_identities.did_manager import DidManager
from walytis_identities.group_did_manager import GroupDidManager, Member
from walytis_beta_api import decode_short_id
from walytis_beta_api._experimental.generic_blockchain import (
    GenericBlock,
    GenericBlockchain,
)
from walytis_identities.did_manager import blockchain_id_from_did
from .group_did_manager import GroupDidManager, ipfs, logger
import json

COMMS_TIMEOUT_S = 30
CHALLENGE_STRING_LENGTH = 200


def listen_for_conversations(
    gdm: GroupDidManager, listener_name: str, eventhandler: Callable
):
    def handle_join_request(conv_name, peer_id, salutation_start):
        salutation = json.loads(salutation_start.decode())
        their_one_time_key = Crypt.deserialise(salutation["one_time_key"])
        our_one_time_key = Crypt.new(gdm.get_control_key().family)
        their_challenge = salutation["challenge_data"]
        data = handle_challenge(gdm, their_challenge)
        our_challenge_data = generate_random_string(CHALLENGE_STRING_LENGTH)
        data.update(
            {
                # "member_did": gdm.member_did_manager.did,
                "one_time_key": our_one_time_key.serialise_public(),
                "challenge_data": our_challenge_data,
            }
        )
        salutation_join = json.dumps(data).encode()
        conv = ipfs.join_conversation(
            conv_name,
            peer_id,
            conv_name,
            salutation_message=salutation_join,
        )
        conv.salutation_message_start = salutation_start
        message = json.loads(conv.listen(COMMS_TIMEOUT_S).decode())
        match message["challenge_result"]:
            case "passed":
                pass
            case "failed":
                logger.debug("DataTr: received conversation denied")
                conv.close()
                return
            case _:
                logger.debug(f"DataTr: received unexpected reply: {message}")
                conv.close()
                return

        if verify_challenge(gdm, message, our_challenge_data):
            conv.say(json.dumps({"challenge_result": "passed"}).encode())
            member = gdm.get_members_dict()[message["member_did"]]

            def _encrypt(plaintext: bytearray) -> bytearray:
                return encrypt(
                    plaintext=plaintext,
                    gdm=gdm,
                    member=member,
                    one_time_key=their_one_time_key,
                )

            def _decrypt(cipher: bytearray) -> bytearray:
                return decrypt(
                    cipher=cipher, gdm=gdm, one_time_key=our_one_time_key
                )

            conv._encryption_callback = _encrypt
            conv._decryption_callback = _decrypt
            eventhandler(conv)
        else:
            conv.say(json.dumps({"challenge_result": "failed"}).encode())
            conv.close()

    content_request_listener = ipfs.listen_for_conversations(
        listener_name=f"WalIdenDatatr-{gdm.blockchain_id}-{listener_name}",
        eventhandler=handle_join_request,
    )
    return content_request_listener


def start_conversation(
    gdm: GroupDidManager, conv_name, peer, others_conv_listener
) -> Conversation | None:
    our_one_time_key = Crypt.new(gdm.get_control_key().family)
    our_challenge_data = generate_random_string(CHALLENGE_STRING_LENGTH)
    salutation = json.dumps(
        {
            # "member_did": gdm.member_did_manager.did,
            "one_time_key": our_one_time_key.serialise_public(),
            "challenge_data": our_challenge_data,
        }
    ).encode()

    conv: ipfs.Conversation = ipfs.start_conversation(
        conv_name,
        peer,
        f"WalIdenDatatr-{gdm.blockchain_id}-{others_conv_listener}",
        salutation_message=salutation,
    )
    salutation_join = json.loads(conv.salutation_join.decode())

    if not verify_challenge(gdm, salutation_join, our_challenge_data):
        conv.say(json.dumps({"challenge_result": "failed"}).encode())
        conv.close()
        return None

    message = handle_challenge(gdm, salutation_join["challenge_data"])
    message.update({"challenge_result": "passed"})
    conv.say(json.dumps(message).encode())
    message = json.loads(conv.listen(COMMS_TIMEOUT_S).decode())
    match message["challenge_result"]:
        case "passed":
            pass
        case "failed":
            logger.debug("DataTr: received conversation denied")
            conv.close()
            return
        case _:
            logger.debug(f"DataTr: received unexpected reply: {message}")
            conv.close()
            return
    member = gdm.get_members_dict()[salutation_join["member_did"]]
    their_one_time_key = Crypt.deserialise(salutation_join["one_time_key"])

    def _encrypt(plaintext: bytearray) -> bytearray:
        return encrypt(
            plaintext=plaintext,
            gdm=gdm,
            member=member,
            one_time_key=their_one_time_key,
        )

    def _decrypt(cipher: bytearray) -> bytearray:
        return decrypt(cipher=cipher, gdm=gdm, one_time_key=our_one_time_key)

    conv._encryption_callback = _encrypt
    conv._decryption_callback = _decrypt
    return conv


def encrypt(
    plaintext: bytearray,
    gdm: GroupDidManager,
    member: Member,
    one_time_key: Crypt,
) -> bytearray:
    logger.debug("Encrypting content...")
    latest_member_key = member._get_member_control_key()

    logger.debug("Encrypting with Group Key...")
    # encrypt with Group key (serialised CodePackage)
    cipher_1 = gdm.encrypt(plaintext)

    logger.debug("Encrypting with Member Key...")
    # encrypt with peer's Member key (serialised CodePackage)
    cipher_2 = CodePackage.encrypt(
        data=cipher_1, key=latest_member_key
    ).serialise_bytes()

    logger.debug("Encrypting with OneTime Key...")
    # encrypt with peer's OneTime Key (without CodePackage)

    cipher_3 = one_time_key.encrypt(cipher_2)
    return cipher_3


def decrypt(
    cipher: bytearray, gdm: GroupDidManager, one_time_key: Crypt
) -> bytearray:
    logger.debug("Decrypting content...")

    logger.debug("Decrypting with OneTime Key...")
    # decrypt with our One-Time Key
    layer_2 = one_time_key.decrypt(cipher)

    logger.debug("Decrypting with Member Key...")
    # decrypt with our Member Key (serialised CodePackage)
    layer_1 = gdm.member_did_manager.decrypt(layer_2)

    logger.debug("Decrypting with Group Key...")
    # decrypt with Group Key (serialied CodePackage)
    plaintext = gdm.decrypt(layer_1)

    return plaintext


def handle_challenge(gdm: GroupDidManager, _their_challenge: str):
    their_challenge = _their_challenge.encode()
    signature_group = CodePackage.deserialise_bytes(
        gdm.sign(their_challenge)
    ).serialise()
    signature_member = CodePackage.deserialise_bytes(
        gdm.member_did_manager.sign(their_challenge)
    ).serialise()
    data = {
        "group_key_proof": signature_group,
        "member_key_proof": signature_member,
        "member_did": gdm.member_did_manager.did,
    }
    return data


def verify_challenge(gdm: GroupDidManager, data: dict, _challenge: str):
    group_key_proof = CodePackage.deserialise(data["group_key_proof"])
    member_key_proof = CodePackage.deserialise(data["member_key_proof"])
    challenge = _challenge.encode()
    member_did = data["member_did"]

    # verify the signatures with which peer
    # proves they own this group are their member keys
    # assert group key actually belongs to this GroupDidManager
    gdm.key_store.get_key_from_public(
        group_key_proof.public_key, family=group_key_proof.family
    )
    logger.debug(gdm.get_members_dict())
    member: Member = gdm.get_members_dict().get(member_did)
    if not member:
        logger.debug("Member DID not validated.")
        return False
    logger.debug(member_key_proof.public_key.hex())
    logger.debug(
        [key.get_public_key_str() for key in member._get_member_control_keys()]
    )

    if (
        member_key_proof.public_key.hex()
        != member._get_member_control_key().get_public_key()
        and member_key_proof.public_key.hex()
        not in [
            key.get_public_key_str()
            for key in member._get_member_control_keys()
        ]
    ):
        logger.debug("Member key not validated.")
        return False
    logger.debug("Member key validated.")

    if (
        group_key_proof.public_key.hex()
        != gdm.get_control_key().get_public_key()
        and group_key_proof.public_key.hex()
        not in [key.get_public_key_str() for key in gdm.get_control_keys()]
    ):
        logger.debug("Group key not validated.")
        return False
    logger.debug("Group key validated.")

    if not group_key_proof.verify_signature(challenge):
        logger.debug("Group Key Proof not Validated")
        return False
    logger.debug("Group key proof validated.")

    if not member_key_proof.verify_signature(challenge):
        logger.debug("Member Key Proof not Validated")
        return False
    logger.debug("Verified challenge.")

    return True


def handle_content_request(
    gdm: GroupDidManager, conv_name: str, peer_id: str
) -> None:
    if gdm._terminate:
        return
    logger.debug("Received content request...")
    conv = ipfs.join_conversation(
        conv_name + peer_id,
        peer_id,
        conv_name,
    )
    try:
        _request = conv.listen(timeout=COMMS_TIMEOUT_S)
        request = json.loads(_request.decode())
        block_id = string_to_bytes(request["block_long_id"])
        logger.debug("Processing content request...")

        one_time_key = Crypt.deserialise(request["one_time_key"])
        group_key_proof = CodePackage.deserialise(request["group_key_proof"])
        member_key_proof = CodePackage.deserialise(request["member_key_proof"])
        member_did = request["member_did"]

        # verify the signatures with which peer
        # proves they own this group and their member keys

        # assert group key actually belongs to this GroupDidManager
        gdm.key_store.get_key_from_public(
            group_key_proof.public_key, family=group_key_proof.family
        )
        logger.debug(gdm.get_members_dict())
        member: Member = gdm.get_members_dict()[member_did]
        logger.debug(member_key_proof.public_key.hex())
        logger.debug(
            [
                key.get_public_key_str()
                for key in member._get_member_control_keys()
            ]
        )
        if not member_key_proof.public_key.hex() in [
            key.get_public_key_str()
            for key in member._get_member_control_keys()
        ]:
            raise Exception("Member key not validated.")
        logger.debug("Member key validated.")
        if not group_key_proof.verify_signature(their_challenge):
            raise Exception("Group Key Proof not Validated")
        logger.debug("Group key proof validated.")
        if not member_key_proof.verify_signature(their_challenge):
            raise Exception("Member Key Proof not Validated")
        logger.debug("Verified content request. Getting content...")
        content = gdm.get_block_content(block_id)
        logger.debug("Got content.")
        if content:
            logger.debug("Encrypting content...")
            latest_member_key = member._get_member_control_key()

            logger.debug("Encrypting with Group Key...")
            # encrypt with Group key (serialised CodePackage)
            cipher_1 = gdm.encrypt(content)

            logger.debug("Encrypting with Member Key...")
            # encrypt with peer's Member key (serialised CodePackage)
            cipher_2 = CodePackage.encrypt(
                data=cipher_1, key=latest_member_key
            ).serialise_bytes()

            logger.debug("Encrypting with OneTime Key...")
            # encrypt with peer's OneTime Key (without CodePackage)

            cipher_3 = one_time_key.encrypt(cipher_2)
            logger.debug("Transmitting content...")
            conv.say(cipher_3, timeout_sec=COMMS_TIMEOUT_S)
        else:
            logger.debug("Didn't find requested content.")
        conv.close()
    except Exception as e:
        logger.error("Failed to handle content request:")
        logger.error(e)
        conv.close()
