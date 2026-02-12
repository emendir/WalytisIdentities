import traceback
import os
from time import sleep

from testing_utils import (
    CORRESP_JOIN_TIMEOUT_S,
    KEY,
    PROFILE_JOIN_TIMEOUT_S,
    dm_config_dir,
)

from walytis_identities.did_manager import DidManager
from walytis_identities.did_manager_with_supers import (
    DidManagerWithSupers,
    GroupDidManager,
)
from walytis_identities.key_store import KeyStore
import logging
from walytis_identities.log import (
    logger_dmws,
    file_handler,
    console_handler,
    logger_gdm_join,
)
from conftest import logger_tests

# ipfs_tk_conv_logger = logging.getLogger("IPFS-TK-Conversations")
# ipfs_tk_conv_logger.addHandler(file_handler)
# ipfs_tk_conv_logger.addHandler(console_handler)
# ipfs_tk_conv_logger.setLevel(logging.DEBUG)

file_handler.setLevel(logging.DEBUG)
console_handler.setLevel(logging.DEBUG)
logger_tests.setLevel(logging.DEBUG)
logger_gdm_join.setLevel(logging.DEBUG)

if not os.path.exists(dm_config_dir):
    os.makedirs(dm_config_dir)


class SharedData:
    pass


shared_data = SharedData()


def docker_create_dm():
    logger_tests.info("DOCKER: Creating DidManagerWithSupers...")
    try:
        config_dir = dm_config_dir
        key = KEY

        device_keystore_path = os.path.join(config_dir, "device_keystore.json")
        profile_keystore_path = os.path.join(
            config_dir, "profile_keystore.json"
        )

        device_did_keystore = KeyStore(device_keystore_path, key)
        profile_did_keystore = KeyStore(profile_keystore_path, key)
        device_did_manager = DidManager.create(device_did_keystore)
        profile_did_manager = GroupDidManager.create(
            profile_did_keystore, device_did_manager
        )
        profile_did_manager.terminate()
        group_did_manager = GroupDidManager(
            profile_did_keystore,
            device_did_manager,
            auto_load_missed_blocks=False,
        )
        dmws = DidManagerWithSupers(
            did_manager=group_did_manager,
        )
        shared_data.dm = dmws
    except Exception as e:
        logger_tests.error(traceback.format_exc())
        logger_tests.error(e)


def docker_load_dm():
    logger_tests.info("DOCKER: Loading DidManagerWithSupers...")
    try:
        config_dir = dm_config_dir
        key = KEY

        device_keystore_path = os.path.join(config_dir, "device_keystore.json")
        profile_keystore_path = os.path.join(
            config_dir, "profile_keystore.json"
        )

        device_did_keystore = KeyStore(device_keystore_path, key)
        profile_did_keystore = KeyStore(profile_keystore_path, key)
        group_did_manager = GroupDidManager(
            profile_did_keystore,
            device_did_keystore,
            auto_load_missed_blocks=False,
        )
        dmws = DidManagerWithSupers(
            did_manager=group_did_manager,
        )
        logger_tests.info("DOCKER: Loaded DidManagerWithSupers!")
        shared_data.dm = dmws
    except Exception as e:
        logger_tests.error(traceback.format_exc())
        logger_tests.error(e)


def docker_join_dm(invitation: str):
    logger_tests.info("Joining dm...")
    device_did_keystore = None
    profile_did_keystore = None
    device_did_manager = None
    profile_did_manager = None
    dmws = None
    try:
        config_dir = dm_config_dir
        key = KEY
        device_keystore_path = os.path.join(config_dir, "device_keystore.json")
        profile_keystore_path = os.path.join(
            config_dir, "profile_keystore.json"
        )
        device_did_keystore = KeyStore(device_keystore_path, key)
        profile_did_keystore = KeyStore(profile_keystore_path, key)
        device_did_manager = DidManager.create(device_did_keystore)

        profile_did_manager = GroupDidManager.join(
            invitation, profile_did_keystore, device_did_manager
        )

        dmws = DidManagerWithSupers(
            did_manager=profile_did_manager,
        )
        shared_data.dm = dmws
        logger_tests.info(
            "DOCKER: Joined Endra dm, waiting to get control key..."
        )

        sleep(PROFILE_JOIN_TIMEOUT_S)
        ctrl_key = shared_data.dm.get_control_keys()
        if ctrl_key.is_unlocked():
            print("DOCKER: Got control key!")
        else:
            print("DOCKER: Haven't got control key...")
    except Exception as e:
        logger_tests.error(traceback.format_exc())
        logger_tests.error(e)
        if device_did_keystore:
            device_did_keystore.terminate()
        if profile_did_keystore:
            profile_did_keystore.terminate()
        if device_did_manager:
            device_did_manager.terminate()
        if profile_did_manager:
            profile_did_manager.terminate()
        if dmws:
            dmws.terminate()


def docker_create_super() -> GroupDidManager:
    logger_tests.info("DOCKER: Creating GroupDidManager...")
    try:
        super = shared_data.dm.create_super()
        print("DOCKER: ", super.did)
        return super
    except Exception as e:
        logger_tests.error(traceback.format_exc())
        logger_tests.error(e)


def docker_join_super(invitation: str | dict):
    logger_tests.info("DOCKER: Joining GroupDidManager...")
    try:
        super = shared_data.dm.join_super(invitation)
        print(super.did)
        logger_tests.info(
            "DOCKER: Joined Endra GroupDidManager, waiting to get control key..."
        )

        sleep(CORRESP_JOIN_TIMEOUT_S)
        ctrl_key = super.get_control_keys()
        logger_tests.info(f"DOCKER: Joined: {type(ctrl_key)}")
        if ctrl_key.is_unlocked():
            print("DOCKER: Got control key!")
        return super
    except Exception as e:
        logger_tests.error(traceback.format_exc())
        logger_tests.error(e)
