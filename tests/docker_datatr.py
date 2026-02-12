from threading import Event
from emtest import are_we_in_docker
from termcolor import colored as coloured
import os

from walytis_identities.datatransmission import (
    listen_for_conversations,
    Conversation,
    COMMS_TIMEOUT_S,
)
from prebuilt_group_did_managers import (
    load_did_manager,
)
from time import sleep
import threading
import logging

from walytis_identities.group_did_manager import GroupDidManager
from walid_docker.walid_docker import (
    WalytisIdentitiesDocker,
    delete_containers,
)
from conftest import logger_tests

from walytis_identities.log import logger_datatr, file_handler, console_handler

logger_datatr.setLevel(logging.DEBUG)
logger_tests.setLevel(logging.DEBUG)

CONV_NAME = "WalIdDataTransTest"
SYNC_DUR = 60


class SharedData:
    pass


shared_data = SharedData()
logger_tests.info("Initialised shared_data.")


def test_preparations_docker():
    shared_data.group_did_manager = None
    shared_data.pri_blockchain = None
    shared_data.containers: list[WalytisIdentitiesDocker] = []

    # Load pre-created GroupDidManager objects for testing:

    logger_tests.info("Loading GDMs from tar files...")
    tarfile = "group_did_manager_1.tar"
    shared_data.group_did_manager = load_did_manager(
        os.path.join(os.path.dirname(__file__), tarfile)
    )

    # in docker, update the MemberJoiningBlock to include the new
    logger_tests.debug("Updating MemberJoiningBlock")
    shared_data.group_did_manager.add_member(
        shared_data.group_did_manager.member_did_manager
    )


HI = "Hi!".encode()
HELLO_THERE = "Hello there!".encode()
FILE_METADATA = "File for you.".encode()


def docker_part():
    finished = Event()

    def eventhandler(conv: Conversation):
        logger_tests.debug("Received transmission!")
        data = conv.listen(SYNC_DUR)
        logger_tests.debug("Received message!")
        # logger_tests.debug(f"Received data: {data}")
        if data == HELLO_THERE:
            logger_tests.debug("Sending response...")
            conv.say(HI)
            conv.transmit_file(__file__, FILE_METADATA)
        else:
            conv.say("TEST FAILED".encode())
            logger_tests.error(f"WRONG MESSAGE: {data}")
        logger_tests.debug("Done! Cleaning up...")
        conv.terminate()
        finished.set()

    logger_tests.debug("Starting listening for transmissions...")
    listener = listen_for_conversations(
        shared_data.group_did_manager,
        CONV_NAME,
        eventhandler,
    )
    finished.wait(SYNC_DUR)
    logger_tests.debug("Cleaning up...")
    listener.terminate()
    shared_data.group_did_manager.terminate()
    shared_data.group_did_manager.member_did_manager.terminate()
    # test_block_sharing.cleanup()
    logger_tests.debug("Finished cleanup.")
    while len(threading.enumerate()) > 1:
        logger_tests.debug(threading.enumerate())
        sleep(1)
