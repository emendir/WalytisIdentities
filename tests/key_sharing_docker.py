from walytis_identities.log import logger_datatr, logger_gdm_join
import logging
from emtest import get_thread_names
import json
import os
from time import sleep

from emtest import are_we_in_docker, delete_path, make_dir
from testing_utils import CRYPTO_FAMILY, KEY
from walid_docker.walid_docker import (
    WalytisIdentitiesDocker,
)

from walytis_identities.did_manager import DidManager
from walytis_identities.group_did_manager import (
    GroupDidManager,
    InvitationManager,
    InvitationCode,
)
import walytis_identities.settings
from walytis_identities.key_store import KeyStore
from walytis_identities.utils import logger

from walytis_identities.log import (
    logger_datatr,
    logger_gdm_join,
    file_handler,
    logger_gdm,
)
import logging

logger_gdm.setLevel(logging.DEBUG)
logger_datatr.setLevel(logging.DEBUG)
logger_gdm_join.setLevel(logging.DEBUG)
logger_gdm_join.setLevel(logging.DEBUG)
file_handler.setLevel(logging.DEBUG)
logger.setLevel(logging.DEBUG)


logger_datatr.setLevel(logging.DEBUG)
logger_gdm_join.setLevel(logging.DEBUG)

walytis_identities.settings.CTRL_KEY_MGMT_PERIOD = 0.1
JOIN_DUR = 10
SHARE_DUR = 20


class SharedData:
    def __init__(self):
        # the cryptographic family to use for the tests
        self.CRYPTO_FAMILY = CRYPTO_FAMILY
        # self.KEY = Key.create(self.CRYPTO_FAMILY)
        self.KEY = KEY

        self.group_1 = None
        self.group_2 = None
        self.group_3 = None
        self.group_4 = None
        self.member_3 = None
        self.member_4 = None
        self.group_1_config_dir = "/tmp/group_1"
        self.group_2_config_dir = "/tmp/group_2"
        self.group_3_config_dir = "/tmp/group_3"
        self.group_4_config_dir = "/tmp/group_4"
        self.member_3_keystore_file = os.path.join("/tmp/member_3", "ks.json")
        self.member_4_keystore_file = os.path.join("/tmp/member_4", "ks.json")
        # self.join_key = KEY
        # self.join_code =InvitationCode(self.join_key)

        self.containers: list[WalytisIdentitiesDocker] = []
        self.invitation = None
        if not are_we_in_docker():
            delete_path(self.group_1_config_dir)
            delete_path(self.group_2_config_dir)
            delete_path(self.group_3_config_dir)
            delete_path(self.group_4_config_dir)
            delete_path(self.member_3_keystore_file)
            delete_path(self.member_4_keystore_file)
        make_dir(self.group_1_config_dir)
        make_dir(self.group_2_config_dir)
        make_dir(self.group_3_config_dir)
        make_dir(self.group_4_config_dir)
        make_dir(self.member_3_keystore_file)
        make_dir(self.member_4_keystore_file)


shared_data = SharedData()


def docker_create_identity_and_invitation():
    """Create an identity and invitation for it.

    TO BE RUN IN DOCKER CONTAINER.
    """
    logger.debug("DockerTest: creating identity...")

    device_keystore_path = os.path.join(
        shared_data.group_1_config_dir, "device_keystore.json"
    )
    profile_keystore_path = os.path.join(
        shared_data.group_1_config_dir, "profile_keystore.json"
    )

    device_did_keystore = KeyStore(device_keystore_path, shared_data.KEY)
    profile_did_keystore = KeyStore(profile_keystore_path, shared_data.KEY)
    device_did_manager = DidManager.create(device_did_keystore)

    shared_data.group_1 = GroupDidManager.create(
        profile_did_keystore, device_did_manager
    )
    logger.debug("DockerTest: creating invitation...")
    # invitation = shared_data.group_1.invite_member()
    shared_data.group_1.load_invitation(KEY)
    # docker_be_online_30s()
    logger.debug("DockerTest: waiting...")
    sleep(JOIN_DUR)
    shared_data.group_1.terminate()
    device_did_manager.terminate()
    print("Terminated objects, remaining threads:", get_thread_names())
    # print(json.dumps(invitation))

    # mark(isinstance(shared_data.group_1, GroupDidManager), "Created GroupDidManager")


def docker_check_new_member(did: str):
    """Check that the given member DID manager is part of the group_1 group

    TO BE RUN IN DOCKER CONTAINER.
    """
    logger.debug("CND: Loading GroupDidManager...")

    device_keystore_path = os.path.join(
        shared_data.group_1_config_dir, "device_keystore.json"
    )
    profile_keystore_path = os.path.join(
        shared_data.group_1_config_dir, "profile_keystore.json"
    )

    device_did_keystore = KeyStore(device_keystore_path, shared_data.KEY)
    profile_did_keystore = KeyStore(profile_keystore_path, shared_data.KEY)
    shared_data.group_1 = GroupDidManager(
        profile_did_keystore, device_did_keystore
    )

    logger.debug("CND: Getting members...")
    success = did in [
        member.did for member in shared_data.group_1.get_members()
    ] and did in [member.did for member in shared_data.group_1.get_members()]
    logger.debug("CND: got data, exiting...")

    if success:
        print("Member has joined!")
    else:
        print("\nDocker: Members:\n", shared_data.group_1.get_members())

    shared_data.group_1.terminate()


def docker_be_online_30s():
    logger.debug("CND: Loading GroupDidManager...")

    device_keystore_path = os.path.join(
        shared_data.group_1_config_dir, "device_keystore.json"
    )
    profile_keystore_path = os.path.join(
        shared_data.group_1_config_dir, "profile_keystore.json"
    )

    device_did_keystore = KeyStore(device_keystore_path, shared_data.KEY)
    profile_did_keystore = KeyStore(profile_keystore_path, shared_data.KEY)
    shared_data.group_1 = GroupDidManager(
        profile_did_keystore, device_did_keystore
    )
    for i in range(SHARE_DUR // 10):
        sleep(10)
        logger.debug("waiting...")
    shared_data.group_1.terminate()


def docker_renew_control_key():
    """Renew the control key of shared_data.group_1.

    TO BE RUN IN DOCKER CONTAINER.
    """
    logger.debug("CND: Loading GroupDidManager...")

    device_keystore_path = os.path.join(
        shared_data.group_1_config_dir, "device_keystore.json"
    )
    profile_keystore_path = os.path.join(
        shared_data.group_1_config_dir, "profile_keystore.json"
    )

    device_did_keystore = KeyStore(device_keystore_path, shared_data.KEY)
    profile_did_keystore = KeyStore(profile_keystore_path, shared_data.KEY)
    shared_data.group_1 = GroupDidManager(
        profile_did_keystore, device_did_keystore
    )
    old_key = shared_data.group_1.get_control_key()
    num_ck = len(shared_data.group_1.candidate_keys)
    # shared_data.group_1.initiate_control_key_update()

    # make GroupDidManager propose a new control key
    walytis_identities.settings.CTRL_KEY_RENEWAL_AGE_HR = 0
    walytis_identities.settings.CTRL_KEY_RENEWAL_RANDOMISER_MAX = 0
    walytis_identities.group_did_manager.CTRL_KEY_RENEWAL_AGE_HR = 0
    walytis_identities.group_did_manager.CTRL_KEY_RENEWAL_RANDOMISER_MAX = 0
    shared_data.group_1.CTRL_KEY_RENEWAL_RANDOMISER = 0
    for i in range(SHARE_DUR):
        if len(shared_data.group_1.candidate_keys) > num_ck:
            break
        sleep(1)
    logger.info("Initiated Key renewal!")
    for i in range(SHARE_DUR // 10):
        sleep(10)
        logger.debug("waiting...")
    shared_data.group_1.terminate()
    import threading
    import time

    while len(threading.enumerate()) > 1:
        print(threading.enumerate())
        time.sleep(1)
    new_key = shared_data.group_1.get_control_key()
    print(f"{old_key.get_key_id()} {new_key.get_key_id()}")
