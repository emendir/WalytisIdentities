
import json
import os
from time import sleep

from emtest import are_we_in_docker
from testing_utils import CRYPTO_FAMILY,KEY
from walid_docker.walid_docker import (
    WalytisIdentitiesDocker,
)

from walytis_identities.did_manager import DidManager
from walytis_identities.did_objects import Key
from walytis_identities.group_did_manager import GroupDidManager
from walytis_identities.key_store import KeyStore
from walytis_identities.utils import logger
from emtest import make_dir, delete_path

wait_dur_s = 30

class SharedData:
    def __init__(self):

        # the cryptographic family to use for the tests
        self.CRYPTO_FAMILY = CRYPTO_FAMILY
        # self.KEY = Key.create(self.CRYPTO_FAMILY)
        self.KEY=KEY

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

from emtest import get_thread_names

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
    invitation = shared_data.group_1.invite_member()
    shared_data.group_1.terminate()
    device_did_manager.terminate()
    print("Terminated objects, remaining threads:",get_thread_names())
    print(json.dumps(invitation))

    # mark(isinstance(shared_data.group_1, GroupDidManager), "Created GroupDidManager")


def docker_check_new_member(did: str):
    """Check that the given member DID manager is part of the group_1 group

    TO BE RUN IN DOCKER CONTAINER.
    """
    logger.debug("CND: Loading GroupDidManager...")

    device_keystore_path = os.path.join(
        shared_data.group_1_config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(
        shared_data.group_1_config_dir, "profile_keystore.json")

    device_did_keystore = KeyStore(device_keystore_path, shared_data.KEY)
    profile_did_keystore = KeyStore(profile_keystore_path, shared_data.KEY)
    shared_data.group_1 = GroupDidManager(
        profile_did_keystore, device_did_keystore
    )


    logger.debug("CND: Getting members...")
    success = (
        did in [
            member.did
            for member in shared_data.group_1.get_members()
        ]
        and did in [
            member.did
            for member in shared_data.group_1.get_members()
        ]
    )
    logger.debug("CND: got data, exiting...")

    if success:
        print("Member has joined!")
    else:
        print("\nDocker: Members:\n", shared_data.group_1.get_members())

    shared_data.group_1.terminate()


def docker_be_online_30s():
    logger.debug("CND: Loading GroupDidManager...")

    device_keystore_path = os.path.join(
        shared_data.group_1_config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(
        shared_data.group_1_config_dir, "profile_keystore.json")

    device_did_keystore = KeyStore(device_keystore_path, shared_data.KEY)
    profile_did_keystore = KeyStore(profile_keystore_path, shared_data.KEY)
    shared_data.group_1 = GroupDidManager(
        profile_did_keystore, device_did_keystore
    )
    for i in range(wait_dur_s // 10):
        sleep(10)
        logger.debug('waiting...')
    shared_data.group_1.terminate()


def docker_renew_control_key():
    """Renew the control key of shared_data.group_1.

    TO BE RUN IN DOCKER CONTAINER.
    """
    logger.debug("CND: Loading GroupDidManager...")

    device_keystore_path = os.path.join(
        shared_data.group_1_config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(
        shared_data.group_1_config_dir, "profile_keystore.json")

    device_did_keystore = KeyStore(device_keystore_path, shared_data.KEY)
    profile_did_keystore = KeyStore(profile_keystore_path, shared_data.KEY)
    shared_data.group_1 = GroupDidManager(
        profile_did_keystore, device_did_keystore
    )
    old_key = shared_data.group_1.get_control_key()
    shared_data.group_1.renew_control_key()
    new_key = shared_data.group_1.get_control_key()
    logger.info(f"Renewed control key! {new_key.get_key_id()}")
    logger.info(f"Old key: {old_key.get_key_id()}")
    logger.info(f"New key: {new_key.get_key_id()}")
    shared_data.group_1.terminate()
    import threading
    import time
    while len(threading.enumerate()) > 1:
        print(threading.enumerate())
        time.sleep(1)
    print(f"{old_key.get_key_id()} {new_key.get_key_id()}")

