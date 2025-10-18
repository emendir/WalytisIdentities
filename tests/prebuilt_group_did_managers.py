import conftest  # noqa

from threading import Thread
import os
import shutil
import tarfile
import tempfile
from datetime import datetime

import walytis_beta_api as waly
from walytis_identities.did_manager import (
    KEYSTORE_DID,
    DidManager,
    blockchain_id_from_did,
)
from walytis_identities.did_manager_blocks import get_all_control_keys
from walytis_identities.did_objects import Key
from walytis_identities.group_did_manager import GroupDidManager, logger
from walytis_identities.key_store import KeyStore

import logging
from walytis_identities.log import logger_dm, logger_gdm

logger_dm.setLevel(logging.DEBUG)
logger_gdm.setLevel(logging.DEBUG)
os.chdir(os.path.dirname(__file__))
config_dir_1 = tempfile.mkdtemp()
config_dir_2 = tempfile.mkdtemp()
CRYPTO_FAMILY = "EC-secp256k1"

private_key = (
    "984f4581356d5d5c69f8461ae96ec300e0bf74d5e43050751d4f3ce92d0aeee7"
)
public_key = "04736e3bfcadc1ca5b099e566003f92a1f04379c5b626ab62a52aaf85bc3a14f2c782a9961a946bc7e72f99952b00bab52fe10f9b7dfd45fc01d551b74dd7eb94b"

key = Key(
    CRYPTO_FAMILY,
    public_key=public_key,
    private_key=private_key,
    creation_time=datetime(2024, 11, 9, 8, 30, 58, 719382),
)


def create_tar_from_directory(source_dir, tar_path):
    """Create a tar file from the source directory, placing its contents in the root of the tar file.

    Parameters:
    source_dir (str): The directory to be archived.
    tar_path (str): The path where the tar file will be saved.
    """
    with tarfile.open(tar_path, "w:gz") as tar:
        # Iterate through all the files and directories in the source directory
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                file_path = os.path.join(root, file)
                # Calculate the relative path to store in the tar file
                arcname = os.path.relpath(file_path, start=source_dir)
                tar.add(file_path, arcname=arcname)
            for dir in dirs:
                dir_path = os.path.join(root, dir)
                arcname = os.path.relpath(dir_path, start=source_dir)
                tar.add(dir_path, arcname=arcname)


def extract_tar_to_directory(tar_path, dest_dir):
    """Extract a tar file to the destination directory.

    Parameters:
    tar_path (str): The path to the tar file.
    dest_dir (str): The directory where the tar contents will be extracted.
    """
    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(path=dest_dir)


def create_did_managers():
    print("Creating KeyStores...")
    member_1_keystore = KeyStore(
        os.path.join(config_dir_1, "member_keys.json"), key
    )
    member_2_keystore = KeyStore(
        os.path.join(config_dir_2, "member_keys.json"), key
    )

    print("Creating DidManager 1...")
    member_1_did_manager = DidManager.create(member_1_keystore)
    print("Creating DidManager 2    ...")
    member_2_did_manager = DidManager.create(member_2_keystore)

    print("Creating GroupDidManagers...")
    group_1_keystore = KeyStore(
        os.path.join(config_dir_1, "group_keys.json"), key
    )
    group_2_keystore = group_1_keystore.clone(
        os.path.join(config_dir_2, "group_keys.json"), key
    )
    group_did_manager_1 = GroupDidManager.create(
        group_1_keystore, member_1_did_manager
    )
    logger.debug(group_did_manager_1.blockchain.blockchain_id)
    logger.debug(group_did_manager_1.get_active_control_keys())
    logger.debug(get_all_control_keys(group_did_manager_1.blockchain))
    assert isinstance(group_did_manager_1.get_control_keys(), list)

    from time import sleep

    print("Inviting member...")
    group_did_manager_1.add_member(member_2_did_manager)
    group_did_manager_2 = GroupDidManager(
        group_2_keystore, member_2_did_manager
    )
    group_did_manager_2.unlock(
        group_did_manager_1.get_control_key().private_key
    )
    assert isinstance(group_did_manager_2.get_control_keys(), list)

    print("Copying blockchain data...")
    shutil.copy(
        group_did_manager_1.blockchain.get_blockchain_data(),
        os.path.join(config_dir_1, "group_blockchain.zip"),
    )
    shutil.copy(
        group_did_manager_1.member_did_manager.blockchain.get_blockchain_data(),
        os.path.join(config_dir_1, "member1_blockchain.zip"),
    )
    shutil.copy(
        group_did_manager_2.member_did_manager.blockchain.get_blockchain_data(),
        os.path.join(config_dir_1, "member2_blockchain.zip"),
    )
    with open(
        os.path.join(config_dir_1, "member1_blockchain_id.txt"), "w+"
    ) as file:
        file.write(
            group_did_manager_1.member_did_manager.blockchain.blockchain_id
        )
    with open(
        os.path.join(config_dir_1, "member2_blockchain_id.txt"), "w+"
    ) as file:
        file.write(
            group_did_manager_2.member_did_manager.blockchain.blockchain_id
        )

    shutil.copy(
        group_did_manager_2.blockchain.get_blockchain_data(),
        os.path.join(config_dir_2, "group_blockchain.zip"),
    )
    shutil.copy(
        group_did_manager_2.member_did_manager.blockchain.get_blockchain_data(),
        os.path.join(config_dir_2, "member2_blockchain.zip"),
    )
    shutil.copy(
        group_did_manager_1.member_did_manager.blockchain.get_blockchain_data(),
        os.path.join(config_dir_2, "member1_blockchain.zip"),
    )
    with open(
        os.path.join(config_dir_2, "member1_blockchain_id.txt"), "w+"
    ) as file:
        file.write(
            group_did_manager_1.member_did_manager.blockchain.blockchain_id
        )
    with open(
        os.path.join(config_dir_2, "member2_blockchain_id.txt"), "w+"
    ) as file:
        file.write(
            group_did_manager_2.member_did_manager.blockchain.blockchain_id
        )
    print("Terminating...")
    group_did_manager_1.terminate()
    group_did_manager_2.terminate()
    print("Terminated!")
    # Create the tar file
    create_tar_from_directory(config_dir_1, "group_did_manager_1.tar")
    create_tar_from_directory(config_dir_2, "group_did_manager_2.tar")
    print("Created appdata tar files.")


def load_did_manager(tarfile: str):
    """Load some of the"""
    appdata_path = tempfile.mkdtemp()

    extract_tar_to_directory(tarfile, appdata_path)

    # join the group_did_manager' blockchains
    group_keystore = KeyStore(
        os.path.join(appdata_path, "group_keys.json"), key
    )
    member_keystore = KeyStore(
        os.path.join(appdata_path, "member_keys.json"), key
    )
    group_blockchain_id = blockchain_id_from_did(
        group_keystore.get_custom_metadata()[KEYSTORE_DID]
    )

    with open(
        os.path.join(appdata_path, "member1_blockchain_id.txt"), "r"
    ) as file:
        member_1_bc_id = file.readline().strip()
    with open(
        os.path.join(appdata_path, "member2_blockchain_id.txt"), "r"
    ) as file:
        member_2_bc_id = file.readline().strip()

    def del_1():
        if member_1_bc_id in waly.list_blockchain_ids():
            waly.delete_blockchain(member_1_bc_id)

    def del_2():
        if member_2_bc_id in waly.list_blockchain_ids():
            waly.delete_blockchain(member_2_bc_id)

    thr_1 = Thread(target=del_1)
    thr_2 = Thread(target=del_2)
    thr_1.start()
    thr_2.start()
    thr_1.join()
    thr_2.join()
    try:
        waly.join_blockchain_from_zip(
            member_1_bc_id,
            os.path.join(appdata_path, "member1_blockchain.zip"),
        )
    except waly.BlockchainAlreadyExistsError:
        pass
        # raise Exception("Delete this blockchain first")
    try:
        waly.join_blockchain_from_zip(
            member_2_bc_id,
            os.path.join(appdata_path, "member2_blockchain.zip"),
        )
    except waly.BlockchainAlreadyExistsError:
        pass
        # raise Exception("Delete this blockchain first")

    if group_blockchain_id in waly.list_blockchain_ids():
        waly.delete_blockchain(group_blockchain_id)
    try:
        waly.join_blockchain_from_zip(
            group_blockchain_id,
            os.path.join(appdata_path, "group_blockchain.zip"),
        )
    except waly.BlockchainAlreadyExistsError:
        raise Exception("Delete this blockchain first")
        pass

    group_did_manager = GroupDidManager(group_keystore, member_keystore)

    assert isinstance(group_did_manager.get_control_keys(), list), (
        "control keys available"
    )
    assert isinstance(
        get_all_control_keys(group_did_manager.blockchain), list
    ), "control keys available"
    return group_did_manager


if __name__ == "__main__":
    create_did_managers()
