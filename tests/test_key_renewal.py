import _auto_run_with_pytest  # noqa
from datetime import datetime
from emtest.func_utils import get_function_name
from testing_utils import collect_all_test_logs
from threading import Thread
import pytest
import json
import os
import shutil
from time import sleep

from conftest import cleanup_walytis_ipfs
import walytis_beta_api as walytis_api
from emtest import (
    await_thread_cleanup,
    env_vars,
    polite_wait,
    ensure_dir_exists,
    get_pytest_report_dirs,
)
from docker_key_renewal import SharedData, JOIN_DUR, SHARE_DUR
from walid_docker.build_docker import build_docker_image
from walid_docker.walid_docker import (
    WalytisIdentitiesDocker,
    delete_containers,
)

from walytis_identities.did_manager import DidManager
from walytis_identities.key_objects import Key
from walytis_identities.group_did_manager import (
    GroupDidManager,
    InvitationCode,
)
from walytis_identities.key_store import KeyStore
from walytis_identities.log import (
    logger_dm,
    logger_gdm_join,
    file_handler,
    logger_gdm,
    LOG_TIMESTAMP_FORMAT,
)
import logging
from conftest import logger_tests

logger_gdm.setLevel(logging.DEBUG)
# logger_datatr.setLevel(logging.DEBUG)
logger_dm.setLevel(logging.DEBUG)
logger_gdm_join.setLevel(logging.DEBUG)
logger_gdm_join.setLevel(logging.DEBUG)
file_handler.setLevel(logging.DEBUG)

REBUILD_DOCKER = True
REBUILD_DOCKER = env_vars.bool("TESTS_REBUILD_DOCKER", default=REBUILD_DOCKER)

# automatically remove all docker containers after failed tests
DELETE_ALL_BRENTHY_DOCKERS = True


shared_data = SharedData()

# Boilerplate python code when for running python tests in a docker container
DOCKER_PYTHON_LOAD_TESTING_CODE = """
import sys
import threading
import json
from time import sleep
sys.path.append('/opt/walytis_identities/tests')
import conftest # configure Walytis API
import docker_key_renewal
from docker_key_renewal import shared_data
from docker_key_renewal import logger_tests
"""


@pytest.mark.dependency()
def test_preparations(delete_files: bool = False):
    logger_tests.debug(get_function_name())
    if DELETE_ALL_BRENTHY_DOCKERS:
        delete_containers(image="local/walid_testing")

    if REBUILD_DOCKER:
        build_docker_image(verbose=False)


N_DOCKER_CONTAINERS = 1

CONTAINER_NAME_PREFIX = "test_walid_keys_"


@pytest.mark.dependency(depends=["test_preparations"])
def test_create_docker_containers():
    logger_tests.debug(get_function_name())
    shared_data.containers: list[WalytisIdentitiesDocker] = [
        None
    ] * N_DOCKER_CONTAINERS

    threads = []
    delete_containers(container_name_substr=CONTAINER_NAME_PREFIX)
    for i in range(N_DOCKER_CONTAINERS):

        def task(number):
            shared_data.containers[number] = WalytisIdentitiesDocker(
                container_name=f"{CONTAINER_NAME_PREFIX}{number}"
            )

        thread = Thread(target=task, args=(i,))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    for i in range(N_DOCKER_CONTAINERS):
        print(shared_data.containers[i].ipfs_id)
    print("Set up docker containers.")


@pytest.mark.dependency(depends=["test_create_docker_containers"])
def test_member_joined():
    logger_tests.debug(get_function_name())
    print("Creating identity and invitation on docker...")
    python_code = "\n".join(
        [
            DOCKER_PYTHON_LOAD_TESTING_CODE,
            "docker_key_renewal.docker_create_identity_and_invitation();",
        ]
    )
    print(python_code)

    # breakpoint()
    def run_on_docker():
        shared_data.containers[0].run_python_code(
            python_code,
            print_output=True,
            background=False,
            timeout=JOIN_DUR + 10,
        )

    peer_id = shared_data.containers[0].ipfs_id
    multi_addrs = shared_data.containers[0].get_multi_addrs()

    multi_addrs = [
        addr.split("/p2p/")[0]
        for addr in multi_addrs
        if not addr.startswith("/dns")
        and "127.0.0.1" not in addr
        and "webrtc" not in addr
    ]
    invitation = InvitationCode(shared_data.KEY, peer_id, multi_addrs)
    group_keystore = KeyStore(
        os.path.join(shared_data.group_2_config_dir, "group_2.json"),
        shared_data.KEY,
    )
    logger_tests.debug("Creating member...")
    member = DidManager.create(shared_data.group_2_config_dir)

    # Creating the member above can take a lot of time, sometimes,
    # so it's best to do it before running the docker process
    logger_tests.debug("Created member, starting process in docker...")
    Thread(
        target=run_on_docker, name="docker_create_identity_and_invitation"
    ).start()
    sleep(5)  # wait for GDMs to load in docker

    logger_tests.debug("Member joining GDM...")
    shared_data.group_2 = GroupDidManager.join(
        invitation, group_keystore, member
    )
    logger_tests.debug("Member joined GDM.")
    shared_data.group_2_did = shared_data.group_2.member_did_manager.did

    # wait a short amount to allow the docker container to learn of the new member
    logger_tests.debug("Waiting for new membership to sync to docker...")
    polite_wait(JOIN_DUR)

    sleep(5)  # wait for GDMs terminate in docker
    logger_tests.debug("Checking new member on docker...")
    python_code = "\n".join(
        [
            DOCKER_PYTHON_LOAD_TESTING_CODE,
            f"docker_key_renewal.docker_check_new_member('{member.did}');",
        ]
    )
    # print(f"\n{python_code}\n")
    output = shared_data.containers[0].run_python_code(
        python_code, print_output=True
    )

    success = "Member has joined!" in output
    if not success:
        logger_tests.error("Member wasn't synchronised to docker.")
    assert success


@pytest.mark.dependency(depends=["test_member_joined"])
def test_get_control_key():
    logger_tests.debug(get_function_name())
    if not shared_data.group_2:
        pytest.skip("Test aborted due to previous failures.")
    # create an GroupDidManager object to run on the docker container in the
    # background to handle a key request from shared_data.group_2
    # python_code = "\n".join(
    #     [
    #         DOCKER_PYTHON_LOAD_TESTING_CODE,
    #         "docker_key_renewal.docker_be_online_30s()",
    #     ]
    # )
    # shared_data.containers[0].run_python_code(
    #     python_code, background=True, print_output=True
    # )
    # # print(bash_code)
    # print("Waiting for key sharing...")
    # polite_wait(SHARE_DUR)

    assert shared_data.group_2.get_control_keys().is_unlocked(), (
        "Got control key ownership"
    )

    # wait a little to allow proper resources cleanup on docker container
    # sleep(15)


@pytest.mark.dependency(depends=["test_get_control_key"])
def test_renew_control_key():
    logger_tests.debug(get_function_name())
    if not shared_data.group_2:
        pytest.skip("Test aborted due to previoud failures.")
    old_keys = shared_data.group_2.get_control_keys()
    python_code = "\n".join(
        [
            DOCKER_PYTHON_LOAD_TESTING_CODE,
            "logger_tests.info('DOCKER: Testing control key renewal part 1...');",
            "docker_key_renewal.docker_renew_control_key();",
            # "docker_key_renewal.docker_be_online_30s();",
            "logger_tests.info('DOCKER: Finished control key renewal part 1!');",
        ]
    )

    def docker_renew_keys():
        shared_data.containers[0].run_python_code(
            python_code, background=False, print_output=True
        )

    Thread(target=docker_renew_keys, name="docker_renew_keys").start()

    success = False
    logger_tests.debug("Waiting for key sharing...")
    polite_wait(SHARE_DUR)
    new_keys = shared_data.group_2.get_control_keys()

    key_renewed = new_keys.get_id() != old_keys.get_id()
    key_unlocked = new_keys.is_unlocked()
    success = key_renewed and key_unlocked

    if not key_renewed:
        logger_tests.debug("Key not renewed.")
    if not key_unlocked:
        logger_tests.debug("New key is locked.")

    if not key_renewed:
        logger_tests.error("Key not renewed.")
    if not key_unlocked:
        logger_tests.error("New key is locked.")

    assert success


def test_cleanup(test_name, test_module_start_time, test_report_dirs) -> None:
    """Ensure all resources used by tests are cleaned up."""
    logger_tests.debug(get_function_name())
    if shared_data.group_2:
        shared_data.group_2.delete()
        # shared_data.group_2.member_did_manager.delete()
    if shared_data.group_1:
        shared_data.group_1.delete()
    if shared_data.group_3:
        shared_data.group_3.delete()
    if shared_data.group_4:
        shared_data.group_4.delete()
    if shared_data.member_3:
        shared_data.member_3.delete()
    if shared_data.member_4:
        shared_data.member_4.delete()
    shutil.rmtree(shared_data.group_1_config_dir)
    shutil.rmtree(shared_data.group_2_config_dir)
    shutil.rmtree(shared_data.group_3_config_dir)
    shutil.rmtree(shared_data.group_4_config_dir)
    shutil.rmtree(os.path.dirname(shared_data.member_3_keystore_file))
    shutil.rmtree(os.path.dirname(shared_data.member_4_keystore_file))
    collect_all_test_logs(
        test_name,
        shared_data.containers,
        test_report_dirs,
        test_module_start_time,
    )
    cleanup_walytis_ipfs()


def test_threads_cleanup() -> None:
    """Test that no threads are left running."""
    assert await_thread_cleanup(timeout=10)
