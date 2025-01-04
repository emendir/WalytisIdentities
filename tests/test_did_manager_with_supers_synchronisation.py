from threading import Thread
from walidentity.did_manager import did_from_blockchain_id
from time import sleep
from termcolor import colored as coloured
from brenthy_tools_beta.utils import function_name
from datetime import datetime
import walytis_beta_api as waly
import os
import shutil
import tempfile
from walidentity.utils import logger, LOG_PATH
import json
from brenthy_docker import DockerShellError
import _testing_utils
import walidentity
import pytest
import walytis_beta_api as walytis_api
from _testing_utils import mark, test_threads_cleanup
from walidentity.did_objects import Key
from walidentity import did_manager_with_supers
from walidentity.did_manager_with_supers import DidManagerWithSupers, GroupDidManager

from walytis_auth_docker.walytis_auth_docker import (
    WalIdentityDocker,
    delete_containers,
)
from walytis_auth_docker.build_docker import build_docker_image


walytis_api.log.PRINT_DEBUG = False

_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.dirname(os.path.dirname(__file__)), module=did_manager_with_supers
)
REBUILD_DOCKER = True

# automatically remove all docker containers after failed tests
DELETE_ALL_BRENTHY_DOCKERS = True

CONTAINER_NAME_PREFIX = "walidentity_tests_device_"

# Boilerplate python code when for running python tests in a docker container
DOCKER_PYTHON_LOAD_TESTING_CODE = '''
import sys
import threading
import json
from time import sleep
sys.path.append('/opt/WalIdentity/tests')
import test_did_manager_with_supers_synchronisation
import pytest
from test_did_manager_with_supers_synchronisation import logger
logger.info('DOCKER: Preparing tests...')
test_did_manager_with_supers_synchronisation.REBUILD_DOCKER=False
test_did_manager_with_supers_synchronisation.DELETE_ALL_BRENTHY_DOCKERS=False
test_did_manager_with_supers_synchronisation.test_preparations()
logger.info('DOCKER: Ready to test!')
'''
DOCKER_PYTHON_FINISH_TESTING_CODE = '''
'''

N_DOCKER_CONTAINERS = 4

pytest.corresp = None
pytest.profile = None
pytest.profile_config_dir = "/tmp/wali_test_did_manager_with_supers_synchronisation"
pytest.containers: list[WalIdentityDocker] = []


def test_preparations():
    if DELETE_ALL_BRENTHY_DOCKERS:
        delete_containers(container_name_substr=CONTAINER_NAME_PREFIX,
                          image="local/walytis_auth_testing")

    if REBUILD_DOCKER:

        build_docker_image(verbose=False)

    if not os.path.exists(pytest.profile_config_dir):
        os.makedirs(pytest.profile_config_dir)

    pytest.key_store_path = os.path.join(
        pytest.profile_config_dir, "keystore.json")

    # the cryptographic family to use for the tests
    pytest.CRYPTO_FAMILY = "EC-secp256k1"
    pytest.KEY = Key(
        family=pytest.CRYPTO_FAMILY,
        public_key=b'\x04\xa6#\x1a\xcf\xa7\xbe\xa8\xbf\xd9\x7fd\xa7\xab\xba\xeb{Wj\xe2\x8fH\x08*J\xda\xebS\x94\x06\xc9\x02\x8c9>\xf45\xd3=Zg\x92M\x84\xb3\xc2\xf2\xf4\xe6\xa8\xf9i\x82\xdb\xd8\x82_\xcaIT\x14\x9cA\xd3\xe1',
        private_key=b'\xd9\xd1\\D\x80\xd7\x1a\xe6E\x0bt\xdf\xd0z\x88\xeaQ\xe8\x04\x91\x11\xaf\\%wC\x83~\x0eGP\xd8',
        creation_time=datetime(2024, 11, 6, 19, 17, 45, 713000)
    )


def test_create_docker_containers():
    print("Setting up docker containers...")
    threads = []
    pytest.containers = [None]*N_DOCKER_CONTAINERS
    for i in range(N_DOCKER_CONTAINERS):
        def task(number):
            pytest.containers[number]=WalIdentityDocker(
                container_name=f"{CONTAINER_NAME_PREFIX}{number}"
            )
            
        thread = Thread(target=task, args=(i,))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    print("Set up docker containers.")


def test_cleanup():
    if os.path.exists(pytest.profile_config_dir):
        shutil.rmtree(pytest.profile_config_dir)
    for container in pytest.containers:
        try:
            container.delete()
        except:
            pass
    pytest.containers = []
    if pytest.corresp:
        pytest.corresp.delete()
    if pytest.profile:
        pytest.profile.delete()


def docker_create_profile():
    logger.info("DOCKER: Creating DidManagerWithSupers...")
    pytest.profile = DidManagerWithSupers.create(pytest.profile_config_dir, pytest.KEY)


def docker_load_profile():
    logger.info("DOCKER: Loading DidManagerWithSupers...")
    pytest.profile = DidManagerWithSupers.load(pytest.profile_config_dir, pytest.KEY)


def test_setup_profile(docker_container: WalIdentityDocker):
    """In a docker container, create an Endra profile."""
    print(coloured(f"\n\nRunning {function_name()}", "blue"))

    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_did_manager_with_supers_synchronisation.docker_create_profile()",
        "print(f'DOCKER: Created DidManagerWithSupers: {type(pytest.profile)}')",
        "pytest.profile.terminate()",
    ])
    output_lines = docker_container.run_python_code(
        python_code, print_output=True, timeout=PROFILE_CREATE_TIMEOUT_S,
        background=False
    ).split("\n")
    last_line = output_lines[-1] if len(output_lines) > 0 else None
    mark(
        last_line == "DOCKER: Created DidManagerWithSupers: <class 'walidentity.did_manager_with_supers.DidManagerWithSupers'>",
        function_name()
    )


def test_load_profile(docker_container: WalIdentityDocker) -> dict | None:
    """In a docker container, load an Endra profile & create an invitation.

    The docker container must already have had the Endra profile set up.

    Args:
        docker_container: the docker container in which to load the profile
    Returns:
        dict: an invitation to allow another device to join the profile
    """
    print(coloured(f"\n\nRunning {function_name()}", "blue"))
    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_did_manager_with_supers_synchronisation.docker_load_profile()",
        "invitation=pytest.profile.invite_member()",
        "print(json.dumps(invitation))",
        "print(f'DOCKER: Loaded DidManagerWithSupers: {type(pytest.profile)}')",
        "pytest.profile.terminate()",
    ])
    # breakpoint()
    output_lines = docker_container.run_python_code(
        python_code, print_output=True,
        timeout=PROFILE_CREATE_TIMEOUT_S, background=False
    ).split("\n")
    if len(output_lines) < 2:
        mark(
            False,
            function_name()
        )
        return None
    last_line = output_lines[-1].strip()
    try:
        invitation = json.loads(output_lines[-2].strip().replace("'", '"'))
    except json.decoder.JSONDecodeError:
        logger.warning(f"Error getting invitation: {output_lines[-2]}")
        invitation = None
    mark(
        last_line == "DOCKER: Loaded DidManagerWithSupers: <class 'walidentity.did_manager_with_supers.DidManagerWithSupers'>",
        function_name()
    )

    return invitation


# used for creation, first loading test, and invitation creation
PROFILE_CREATE_TIMEOUT_S = 10
PROFILE_JOIN_TIMEOUT_S = 15
CORRESP_JOIN_TIMEOUT_S = 15


def docker_join_profile(invitation: str):
    logger.info("Joining Endra profile...")
    pytest.profile = DidManagerWithSupers.join(
        invitation, pytest.profile_config_dir, pytest.KEY
    )
    logger.info("Joined Endra profile, waiting to get control key...")

    sleep(PROFILE_JOIN_TIMEOUT_S)
    ctrl_key = pytest.profile.profile_did_manager.get_control_key()
    logger.info(f"Joined: {type(ctrl_key)}")
    if ctrl_key.private_key:
        print("Got control key!")


def test_add_device(
    docker_container_new: WalIdentityDocker,
    docker_container_old: WalIdentityDocker,
    invitation: dict
) -> None:
    """
    Join an existing Endra profile on a new docker container.

    Args:
        docker_container_new: the container on which to set up Endra, joining
            the existing Endra profile
        docker_container_old; the container on which the Endra profile is
            already set up
        invitation: the invitation that allows the new docker container to join
            the Endra profile
    """
    print(coloured(f"\n\nRunning {function_name()}", "blue"))

    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_did_manager_with_supers_synchronisation.docker_load_profile()",
        "logger.info('Waiting to allow new device to join...')",
        f"sleep({PROFILE_JOIN_TIMEOUT_S})",
        "logger.info('Finished waiting, terminating...')",
        "pytest.profile.terminate()",
        "logger.info('Exiting after waiting.')",

    ])
    docker_container_old.run_python_code(
        python_code, background=True
    )
    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        f"test_did_manager_with_supers_synchronisation.docker_join_profile('{
            json.dumps(invitation)}')",
        "pytest.profile.terminate()",
    ])
    output_lines = docker_container_new.run_python_code(
        python_code, timeout=PROFILE_JOIN_TIMEOUT_S + 5, print_output=True,
        background=False
    ).split("\n")
    last_line = output_lines[-1].strip()
    last_line
    mark(
        last_line == "Got control key!",
        function_name()
    )


def docker_create_super() -> GroupDidManager:
    logger.info("DOCKER: Creating GroupDidManager...")
    corresp = pytest.profile.add()
    print(corresp.did)
    return corresp


def docker_join_super(invitation: str | dict):
    logger.info("DOCKER: Joining GroupDidManager...")
    corresp = pytest.profile.join_super(invitation)
    print(corresp.did)
    logger.info("Joined Endra GroupDidManager, waiting to get control key...")

    sleep(CORRESP_JOIN_TIMEOUT_S)
    ctrl_key = corresp.get_control_key()
    logger.info(f"Joined: {type(ctrl_key)}")
    if ctrl_key.private_key:
        print("Got control key!")
    return corresp


def test_create_super(docker_container: WalIdentityDocker) -> dict | None:
    print(coloured(f"\n\nRunning {function_name()}", "blue"))
    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_did_manager_with_supers_synchronisation.docker_load_profile()",
        "corresp=test_did_manager_with_supers_synchronisation.docker_create_super()",
        "invitation = corresp.invite_member()",
        "print(json.dumps(invitation))",
        "print(f'DOCKER: Created GroupDidManager: {type(corresp)}')",
        "pytest.profile.terminate()",
    ])
    output_lines = docker_container.run_python_code(
        python_code, print_output=True,
        timeout=PROFILE_CREATE_TIMEOUT_S, background=False
    ).split("\n")
    if len(output_lines) < 2:
        mark(
            False,
            function_name()
        )
        return None
    last_line = output_lines[-1].strip()
    invitation = json.loads(output_lines[-2].strip().replace("'", '"'))

    mark(
        last_line == "DOCKER: Created GroupDidManager: <class 'walidentity.group_did_manager.GroupDidManager'>",
        function_name()
    )

    return invitation


def test_device_loaded_super(docker_container: WalIdentityDocker, corresp_id: str) -> None:
    pass


def test_join_super(
    docker_container_old: WalIdentityDocker,
    docker_container_new: WalIdentityDocker,
    invitation: dict
) -> None:
    print(coloured(f"\n\nRunning {function_name()}", "blue"))
    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_did_manager_with_supers_synchronisation.docker_load_profile()",
        "logger.info('Waiting to allow conversation join...')",
        f"sleep({CORRESP_JOIN_TIMEOUT_S})",
        "logger.info('Finished waiting, terminating...')",
        "pytest.profile.terminate()",
        "logger.info('Exiting after waiting.')",

    ])
    docker_container_old.run_python_code(
        python_code, background=True
    )
    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_did_manager_with_supers_synchronisation.docker_load_profile()",
        f"corresp = test_did_manager_with_supers_synchronisation.docker_join_super('{
            json.dumps(invitation)}')",
        "print(corresp.did)",
        "pytest.profile.terminate()",
        "corresp.terminate()",
    ])
    output_lines = docker_container_new.run_python_code(
        python_code, timeout=CORRESP_JOIN_TIMEOUT_S + 5,
        print_output=True, background=False
    ).split("\n")
    second_last_line = output_lines[-2].strip()
    corresp_id = output_lines[-1].strip()
    expected_corresp_id = did_from_blockchain_id(
        invitation['blockchain_invitation']['blockchain_id'])

    mark(
        second_last_line == "Got control key!" and
        corresp_id == expected_corresp_id,
        function_name()
    )


def test_auto_join_super(
    docker_container_old: WalIdentityDocker,
    docker_container_new: WalIdentityDocker,
    correspondence_id: str
) -> None:
    print(coloured(f"\n\nRunning {function_name()}", "blue"))
    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_did_manager_with_supers_synchronisation.docker_load_profile()",
        "logger.info('Waiting to allow auto conversation join...')",
        f"sleep({CORRESP_JOIN_TIMEOUT_S})",
        "logger.info('Finished waiting, terminating...')",
        "pytest.profile.terminate()",
        "logger.info('Exiting after waiting.')",

    ])
    docker_container_old.run_python_code(
        python_code, background=True
    )
    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_did_manager_with_supers_synchronisation.docker_load_profile()",
        f"sleep({CORRESP_JOIN_TIMEOUT_S})",
        "print('GroupDidManager DIDs:')",
        "for c in pytest.profile.get_active_ids():",
        "    print(c)",
        "pytest.profile.terminate()",
    ])
    try:
        output = docker_container_new.run_python_code(
            python_code, timeout=CORRESP_JOIN_TIMEOUT_S + 5,
            print_output=True, background=False
        ).split("GroupDidManager DIDs:")
    except DockerShellError as e:
        print(e)
        breakpoint()
    c_ids: list[str] = []
    if len(output) == 2:
        _, c_id_text = output
        c_ids = [line.strip() for line in c_id_text.split("\n")]
        c_ids = [c_id for c_id in c_ids if c_id != ""]

    mark(
        correspondence_id in c_ids,
        function_name()
    )


def test_conv_add_third_partner():
    print(coloured(f"\n\nRunning {function_name()}", "blue"))


def run_tests():
    print("\nRunning tests for Endra:")
    test_cleanup()
    test_preparations()
    test_create_docker_containers()

    # create first profile with multiple devices
    test_setup_profile(pytest.containers[0])
    invitation = test_load_profile(pytest.containers[0])
    if invitation:
        test_add_device(pytest.containers[1], pytest.containers[0], invitation)
        test_load_profile(pytest.containers[1])
    # create second profile with multiple devices
    test_setup_profile(pytest.containers[2])
    invitation = test_load_profile(pytest.containers[2])
    if invitation:
        test_add_device(pytest.containers[3], pytest.containers[2], invitation)
        test_load_profile(pytest.containers[3])

    # create correspondence & share accross profiles
    invitation = test_create_super(pytest.containers[0])
    if invitation:
        corresp_id = did_from_blockchain_id(
            invitation['blockchain_invitation']['blockchain_id'])
        # check that profile1's second device automatically joins the correspondence
        test_auto_join_super(
            pytest.containers[0], pytest.containers[1], corresp_id)

        # test that profile2 can join the correspondence given an invitation
        test_join_super(
            pytest.containers[0], pytest.containers[2], invitation
        )
        test_auto_join_super(
            pytest.containers[2],
            pytest.containers[3],
            corresp_id
        )

    # create second profile with multiple devices
    test_cleanup()
    test_threads_cleanup()


if __name__ == "__main__":
    _testing_utils.PYTEST = False
    _testing_utils.BREAKPOINTS = True
    run_tests()
