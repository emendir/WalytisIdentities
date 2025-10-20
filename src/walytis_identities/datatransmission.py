from .did_objects import Key
from ipfs_tk_transmission import Conversation
from walytis_identities.key_store import CodePackage
from .utils import generate_random_string
from multi_crypt import Crypt
import json
from walytis_beta_embedded import ipfs
from typing import Callable
from walytis_beta_embedded import ipfs

from walytis_beta_api._experimental.generic_blockchain import (
    GenericBlock,
    GenericBlockchain,
)
from .log import logger_datatr as logger
import json

from .utils import NUM_ACTIVE_CONTROL_KEYS, NUM_NEW_CONTROL_KEYS

COMMS_TIMEOUT_S = 30
CHALLENGE_STRING_LENGTH = 200


def listen_for_conversations(
    gdm: "GroupDidManager", listener_name: str, eventhandler: Callable
):
    def handle_join_request(conv_name, peer_id, salutation_start):
        logger.debug("Received join request")
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

        if not verify_challenge(gdm, message, our_challenge_data):
            conv.say(json.dumps({"challenge_result": "failed"}).encode())
            conv.close()
            return

        conv.say(json.dumps({"challenge_result": "passed"}).encode())
        group_key_proof = CodePackage.deserialise(message["group_key_proof"])
        member_key_proof = CodePackage.deserialise(message["member_key_proof"])
        # already validated as active by verify_challenge
        group_key = group_key_proof.get_key()
        member_key = member_key_proof.get_key()

        def _encrypt(plaintext: bytearray) -> bytearray:
            return encrypt(
                plaintext=plaintext,
                group_key=group_key,
                member_key=member_key,
                one_time_key=their_one_time_key,
            )

        def _decrypt(cipher: bytearray) -> bytearray:
            return decrypt(
                cipher=cipher, gdm=gdm, one_time_key=our_one_time_key
            )

        conv.set_encryption_functions(_encrypt, _decrypt)
        logger.debug("Starting joined converstation.")
        eventhandler(conv)

    def _handle_join_request(conv_name, peer_id, salutation_start):
        try:
            handle_join_request(conv_name, peer_id, salutation_start)
        except Exception as e:
            import traceback

            logger.error(traceback.format_exc())
            logger.error(e)

    content_request_listener = ipfs.listen_for_conversations(
        listener_name=f"WalIdenDatatr-{gdm.blockchain_id}-{listener_name}",
        eventhandler=_handle_join_request,
    )
    return content_request_listener


def start_conversation(
    gdm: "GroupDidManager",
    conv_name: str,
    peer_id: str,
    others_req_listener: str,
) -> Conversation | None:
    logger.debug("Starting conversation...")
    our_one_time_key = Crypt.new(gdm.get_control_key().family)
    our_challenge_data = generate_random_string(CHALLENGE_STRING_LENGTH)
    salutation = json.dumps(
        {
            # "member_did": gdm.member_did_manager.did,
            "one_time_key": our_one_time_key.serialise_public(),
            "challenge_data": our_challenge_data,
        }
    ).encode()

    logger.debug("Contacting peer...")
    conv: ipfs.Conversation = ipfs.start_conversation(
        conv_name,
        peer_id,
        f"WalIdenDatatr-{gdm.blockchain_id}-{others_req_listener}",
        salutation_message=salutation,
    )
    logger.debug("Conversation started!")
    salutation_join = json.loads(conv.salutation_join.decode())

    if not verify_challenge(gdm, salutation_join, our_challenge_data):
        conv.say(json.dumps({"challenge_result": "failed"}).encode())
        conv.close()
        logger.debug("Challenge verification failed.")
        raise HandshakeFailed()

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
            raise HandshakeFailed()
        case _:
            logger.debug(f"DataTr: received unexpected reply: {message}")
            conv.close()
            raise HandshakeFailed()
    member = gdm.get_members_dict()[salutation_join["member_did"]]
    their_one_time_key = Crypt.deserialise(salutation_join["one_time_key"])

    group_key_proof = CodePackage.deserialise(
        salutation_join["group_key_proof"]
    )
    member_key_proof = CodePackage.deserialise(
        salutation_join["member_key_proof"]
    )
    # already validated as active by verify_challenge
    group_key = group_key_proof.get_key()
    member_key = member_key_proof.get_key()

    def _encrypt(plaintext: bytearray) -> bytearray:
        return encrypt(
            plaintext=plaintext,
            group_key=group_key,
            member_key=member_key,
            one_time_key=their_one_time_key,
        )

    def _decrypt(cipher: bytearray) -> bytearray:
        return decrypt(cipher=cipher, gdm=gdm, one_time_key=our_one_time_key)

    conv.set_encryption_functions(_encrypt, _decrypt)
    logger.debug("Starting conversation.")
    return conv


def encrypt(
    plaintext: bytearray,
    group_key: Key,
    member_key: Key,
    one_time_key: Crypt,
) -> bytearray:
    logger.debug("Encrypting content...")

    logger.debug("Encrypting with Group Key...")
    # encrypt with Group key (serialised CodePackage)
    cipher_1 = CodePackage.encrypt(plaintext, group_key).serialise_bytes()

    logger.debug("Encrypting with Member Key...")
    # encrypt with peer's Member key (serialised CodePackage)
    cipher_2 = CodePackage.encrypt(
        data=cipher_1, key=member_key
    ).serialise_bytes()

    logger.debug("Encrypting with OneTime Key...")
    # encrypt with peer's OneTime Key (without CodePackage)

    cipher_3 = one_time_key.encrypt(cipher_2)
    return cipher_3


def decrypt(
    cipher: bytearray, gdm: "GroupDidManager", one_time_key: Crypt
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


def handle_challenge(gdm: "GroupDidManager", _their_challenge: str):
    their_challenge = _their_challenge.encode()
    group_key = gdm.get_active_unlocked_control_keys()[-1]
    signature_group = CodePackage.sign(their_challenge, group_key).serialise()
    signature_member = CodePackage.deserialise_bytes(
        gdm.member_did_manager.sign(their_challenge)
    ).serialise()
    data = {
        "group_key_proof": signature_group,
        "member_key_proof": signature_member,
        "member_did": gdm.member_did_manager.did,
    }
    return data


def verify_challenge(gdm: "GroupDidManager", data: dict, _challenge: str):
    group_key_proof = CodePackage.deserialise(data["group_key_proof"])
    member_key_proof = CodePackage.deserialise(data["member_key_proof"])
    challenge = _challenge.encode()
    member_did = data["member_did"]

    group_key = group_key_proof.get_key()
    member_key = member_key_proof.get_key()
    if not gdm.is_control_key_active(group_key.get_key_id()):
        logger.debug("Group key not validated.")
        return False
    logger.debug("Group key validated.")

    logger.debug(member_did)
    logger.debug(gdm.get_members_dict())
    member = gdm.get_members_dict().get(member_did)
    if not member:
        logger.debug("Member DID not validated.")
        return False

    logger.debug(member_key_proof.public_key.hex())
    logger.debug(
        [key.get_public_key_str() for key in member._get_member_control_keys()]
    )
    logger.debug(member._get_control_key_age(member_key.get_key_id()))
    logger.debug(member.is_control_key_active(member_key.get_key_id()))
    if not member.is_control_key_active(member_key.get_key_id()):
        logger.debug("Member key not validated.")
        return False

    logger.debug("Member key validated.")

    if not group_key_proof.verify_signature(challenge):
        logger.debug("Group Key Proof not Validated")
        return False
    logger.debug("Group key proof validated.")

    if not member_key_proof.verify_signature(challenge):
        logger.debug("Member Key Proof not Validated")
        return False
    logger.debug("Verified challenge.")

    return True


class HandshakeFailed(Exception):
    pass
