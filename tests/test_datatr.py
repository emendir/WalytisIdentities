import _auto_run_with_pytest  # noqa
from conftest import cleanup_walytis_ipfs
from time import sleep
from ipfs_tk_transmission.errors import CommunicationTimeout
import logging
import os
from walytis_identities.datatransmission import (
    start_conversation,
    COMMS_TIMEOUT_S,
)


from docker_datatr import HELLO_THERE, HI, CONV_NAME, FILE_METADATA
from emtest import await_thread_cleanup, env_vars
from prebuilt_group_did_managers import (
    load_did_manager,
)
from termcolor import colored as coloured
from walytis_identities.group_did_manager import logger, GroupDidManager
from walid_docker.walid_docker import (
    WalytisIdentitiesDocker,
    delete_containers,
)

from walytis_identities.log import logger_datatr

logger_datatr.setLevel(logging.DEBUG)
print(
    coloured(
        "Ensure GroupDidManager tar files were created with the same IPFS node "
        "used for this test",
        "yellow",
    )
)


REBUILD_DOCKER = True
REBUILD_DOCKER = env_vars.bool("TESTS_REBUILD_DOCKER", default=REBUILD_DOCKER)
DOCKER_NAME = "walid_datatr_test"


class SharedData:
    pass


shared_data = SharedData()
logger.info("Initialised shared_data.")


def test_preparations():
    logger.info("Deleting old docker containers...")
    delete_containers(image="local/walid_testing")

    if REBUILD_DOCKER:
        from walid_docker.build_docker import build_docker_image

        build_docker_image(verbose=False)
    shared_data.group_did_manager = None
    shared_data.containers: list[WalytisIdentitiesDocker] = []



def test_create_docker_containers():
    logger.info("Creating docker containers...")
    for i in range(1):
        shared_data.containers.append(
            WalytisIdentitiesDocker(container_name=f"{DOCKER_NAME}0{i}")
        )

    # shared_data.containers[0].run_python_code(
    #     python_code, print_output=False, background=True
    # )

    def run_py():
        shared_data.containers[0].run_python_code(
            python_code, print_output=True, background=False
        )

    from threading import Thread

    Thread(target=run_py).start()
    logger.debug("Continuing...")


def cleanup():
    for container in shared_data.containers:
        container.delete()

    shared_data.group_did_manager.terminate()
    if shared_data.group_did_manager:
        shared_data.group_did_manager.delete()
    cleanup_walytis_ipfs()



def test_load_blockchain():
    """Test that we can load the prebuilt GroupDidManager."""
    logger.info("Loading GDMs from tar files...")
    # choose which group_did_manager to load
    tarfile = "group_did_manager_2.tar"
    shared_data.group_did_manager = load_did_manager(
        os.path.join(os.path.dirname(__file__), tarfile)
    )
    logger.debug("Loaded prebuilt GDM!")
    assert isinstance(shared_data.group_did_manager, GroupDidManager), (
        "Load prebuilt GDM"
    )


python_code = """
import sys
sys.path.insert(0, '/opt/walytis_identities/src')
sys.path.insert(0, '/opt/walytis_identities/tests')

import conftest
import docker_datatr
import walytis_beta_api as waly
import threading

import docker_datatr
from docker_datatr import shared_data


docker_datatr.test_preparations_docker()
docker_datatr.docker_part()
"""


def test_datatransmission():
    """Test that the previously created block is available in the container."""

    # give docker container more time to initialise
    sleep(10)
    logger.debug("Starting datatransmission...")
    conv = start_conversation(
        shared_data.group_did_manager,
        CONV_NAME,
        shared_data.containers[0].ipfs_id,
        CONV_NAME,
    )
    logger.debug("Sending message...")
    conv.say(HELLO_THERE)
    logger.debug("Awaiting response...")
    reply = conv.listen(COMMS_TIMEOUT_S)
    assert conv and reply == HI, "Datatransmission failed"

    logger.debug("Got response!")
    file_transmission = conv.listen_for_file()

    assert file_transmission["metadata"] == FILE_METADATA
    assert os.path.exists(file_transmission["filepath"])

    if conv:
        conv.terminate()


def test_threads_cleanup() -> None:
    """Test that no threads are left running."""
    cleanup()
    assert await_thread_cleanup(timeout=10)
