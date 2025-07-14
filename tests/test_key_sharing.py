import json
import os
import shutil
from time import sleep

import _auto_run_with_pytest  # noqa
import walytis_beta_api as walytis_api
from emtest import await_thread_cleanup, env_vars, polite_wait
from key_sharing_docker import SharedData, wait_dur_s
from walid_docker.build_docker import build_docker_image
from walid_docker.walid_docker import (
    WalytisIdentitiesDocker,
    delete_containers,
)

from walytis_identities.did_manager import DidManager
from walytis_identities.did_objects import Key
from walytis_identities.group_did_manager import GroupDidManager
from walytis_identities.key_store import KeyStore
from walytis_identities.utils import logger

REBUILD_DOCKER = True
REBUILD_DOCKER = env_vars.bool("TESTS_REBUILD_DOCKER", default=REBUILD_DOCKER)

# automatically remove all docker containers after failed tests
DELETE_ALL_BRENTHY_DOCKERS = True


shared_data = SharedData()

# Boilerplate python code when for running python tests in a docker container
DOCKER_PYTHON_LOAD_TESTING_CODE = '''
import sys
import threading
import json
from time import sleep
sys.path.append('/opt/walytis_identities/tests')
import conftest # configure Walytis API
import key_sharing_docker
from key_sharing_docker import shared_data
from key_sharing_docker import logger
'''


def test_preparations(delete_files: bool = False):
    if DELETE_ALL_BRENTHY_DOCKERS:
        delete_containers(image="local/walid_testing")

    if REBUILD_DOCKER:

        build_docker_image(verbose=False)


N_DOCKER_CONTAINERS = 1


def test_create_docker_containers():
    for i in range(N_DOCKER_CONTAINERS):
        shared_data.containers.append(WalytisIdentitiesDocker())


def cleanup():
    for container in shared_data.containers:
        container.delete()
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


def test_create_identity_and_invitation():
    print("Creating identity and invitation on docker...")
    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "key_sharing_docker.docker_create_identity_and_invitation();",
    ])
    output = None
    # print(python_code)
    # breakpoint()
    output = shared_data.containers[0].run_python_code(
        python_code, print_output=True, timeout=10
    )
    # print("Got output!")
    # print(output)
    try:

        shared_data.invitation = [json.loads(line) for line in output.split(
            "\n") if line.startswith('{"blockchain_invitation":')][-1]
    except:
        print(f"\n{python_code}\n")
        pass

    assert (
        shared_data.invitation is not None
    ),    "created identity and invitation on docker"


def test_add_member_identity():
    """Test that a new member can be added to an existing group DID manager."""
    group_keystore = KeyStore(
        os.path.join(shared_data.group_2_config_dir, "group_2.json"),
        shared_data.KEY
    )
    member = DidManager.create(shared_data.group_2_config_dir)
    try:
        shared_data.group_2 = GroupDidManager.join(
            shared_data.invitation, group_keystore, member
        )
    except walytis_api.JoinFailureError:
        try:
            shared_data.group_2 = GroupDidManager.join(
                shared_data.invitation, group_keystore, member
            )
        except walytis_api.JoinFailureError as error:
            print(error)
            breakpoint()
    shared_data.group_2_did = shared_data.group_2.member_did_manager.did

    # wait a short amount to allow the docker container to learn of the new member
    polite_wait(2)

    print("Adding member on docker...")
    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        f"key_sharing_docker.docker_check_new_member('{member.did}');",
    ])
    # print(f"\n{python_code}\n")
    output = shared_data.containers[0].run_python_code(
        python_code, print_output=True
    )

    # print(output)

    assert ("Member has joined!" in output
            ),    "Added member"


def test_get_control_key():
    # create an GroupDidManager object to run on the docker container in the
    # background to handle a key request from shared_data.group_2
    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "key_sharing_docker.docker_be_online_30s()",
    ])
    shared_data.containers[0].run_python_code(
        python_code, background=True, print_output=True)
    # print(bash_code)
    print("Waiting for key sharing...")
    polite_wait(wait_dur_s)

    assert (
        shared_data.group_2.get_control_key().private_key
    ),        "Got control key ownership"

    # wait a little to allow proper resources cleanup on docker container
    sleep(15)


def test_renew_control_key():
    success = True
    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "logger.info('DOCKER: Testing control key renewal part 1...');",
        "key_sharing_docker.docker_renew_control_key();",
        "logger.info('DOCKER: Finished control key renewal part 1!');",

    ])
    output = shared_data.containers[0].run_python_code(
        python_code, print_output=True
    ).split("\n")
    old_key = ""
    new_key = ""
    if output and output[-1]:
        keys = [
            line.strip("\r") for line in output if shared_data.CRYPTO_FAMILY in line
        ][-1].split(" ")
        if len(keys) == 2 and keys[0] != keys[1]:
            try:
                old_key = Key.from_key_id(keys[0])
                new_key = Key.from_key_id(keys[1])
            except:
                pass
    if not old_key and new_key:
        logger.error(output)
        print("Failed to renew keys in docker container.")
        success = False
    else:
        print("Renewed keys in docker container.")

    if success:
        python_code = "\n".join([
            DOCKER_PYTHON_LOAD_TESTING_CODE,
            "logger.info('DOCKER: Testing control key renewal part 2...');",
            "key_sharing_docker.docker_be_online_30s();",
            "logger.info('DOCKER: Finished Control Key Renewal test part 2.');",

        ])
        shared_data.containers[0].run_python_code(
            python_code, background=True, print_output=True
        )

        print("Waiting for key sharing...")
        polite_wait(wait_dur_s)
        private_key = shared_data.group_2.get_control_key().private_key
        try:
            new_key.unlock(private_key)
        except:
            success = False

    assert (success
            ),        "Shared key on renewal."


def test_threads_cleanup() -> None:
    """Test that no threads are left running."""
    cleanup()
    assert await_thread_cleanup(timeout=5)


def run_tests():
    print("\nRunning tests for Key Sharing:")
    prepare(delete_files=True)

    test_create_docker_containers()

    # on docker container, create identity
    test_create_identity_and_invitation()
    if not shared_data.invitation:
        print("Skipped remaining tests because first test failed.")
        cleanup()
        return

    # locally join the identity created on docker
    test_add_member_identity()
    test_get_control_key()
    test_renew_control_key()

    cleanup()
    test_threads_cleanup()
