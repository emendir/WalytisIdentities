import _testing_utils
from walytis_identities.key_store import KeyStore
from walytis_identities.did_manager import DidManager
from threading import Thread
from walytis_identities.did_manager import did_from_blockchain_id
from time import sleep
from termcolor import colored as coloured
from brenthy_tools_beta.utils import function_name
from datetime import datetime
import walytis_beta_embedded._walytis_beta.walytis_beta_api as waly
import os
import shutil
import tempfile
from walytis_identities.utils import logger, LOG_PATH
import json
from brenthy_docker import DockerShellError
import walytis_identities
import pytest
from walytis_beta_embedded._walytis_beta import walytis_beta_api
from _testing_utils import mark, test_threads_cleanup
from walytis_identities.did_objects import Key
from walytis_identities import did_manager_with_supers
from walytis_identities.did_manager_with_supers import DidManagerWithSupers, GroupDidManager

from walytis_auth_docker.walytis_auth_docker import (
    walytis_identitiesDocker,
    delete_containers,
)
from walytis_auth_docker.build_docker import build_docker_image


walytis_beta_api.log.PRINT_DEBUG = False

_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.dirname(os.path.dirname(__file__)), module=did_manager_with_supers
)
REBUILD_DOCKER = True

# automatically remove all docker containers after failed tests
DELETE_ALL_BRENTHY_DOCKERS = True

CONTAINER_NAME_PREFIX = "walytis_identities_tests_device_"


# used for creation, first loading test, and invitation creation
PROFILE_CREATE_TIMEOUT_S = 10
PROFILE_JOIN_TIMEOUT_S = 60
CORRESP_JOIN_TIMEOUT_S = 60


# Boilerplate python code when for running python tests in a docker container
DOCKER_PYTHON_LOAD_TESTING_CODE = '''
import sys
import threading
import json
from time import sleep
sys.path.append('/opt/walytis_identities/tests')
import test_dmws_synchronisation
import pytest
from test_dmws_synchronisation import logger
logger.info('DOCKER: Preparing tests...')
test_dmws_synchronisation.REBUILD_DOCKER=False
test_dmws_synchronisation.DELETE_ALL_BRENTHY_DOCKERS=False
test_dmws_synchronisation.test_preparations()
logger.info('DOCKER: Ready to test!')
'''
DOCKER_PYTHON_FINISH_TESTING_CODE = '''
'''

N_DOCKER_CONTAINERS = 4

pytest.super = None
pytest.dm = None
pytest.dm_config_dir = "/tmp/wali_test_dmws_synchronisation"
pytest.containers: list[walytis_identitiesDocker] = []


def test_preparations():
    if DELETE_ALL_BRENTHY_DOCKERS:
        delete_containers(container_name_substr=CONTAINER_NAME_PREFIX,
                          image="local/walytis_auth_testing")

    if REBUILD_DOCKER:

        build_docker_image(verbose=False)

    if not os.path.exists(pytest.dm_config_dir):
        os.makedirs(pytest.dm_config_dir)

    pytest.key_store_path = os.path.join(
        pytest.dm_config_dir, "keystore.json")

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
    pytest.containers = [None] * N_DOCKER_CONTAINERS
    for i in range(N_DOCKER_CONTAINERS):
        def task(number):
            pytest.containers[number] = walytis_identitiesDocker(
                container_name=f"{CONTAINER_NAME_PREFIX}{number}"
            )

        thread = Thread(target=task, args=(i,))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    print("Set up docker containers.")


def test_cleanup():
    if os.path.exists(pytest.dm_config_dir):
        shutil.rmtree(pytest.dm_config_dir)
    for container in pytest.containers:
        try:
            container.delete()
        except:
            pass
    pytest.containers = []
    if pytest.super:
        pytest.super.delete()
    if pytest.dm:
        pytest.dm.delete()


def docker_create_dm():
    logger.info("DOCKER: Creating DidManagerWithSupers...")
    config_dir = pytest.dm_config_dir
    key = pytest.KEY

    device_keystore_path = os.path.join(config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(config_dir, "profile_keystore.json")

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
        auto_load_missed_blocks=False
    )
    dmws = DidManagerWithSupers(
        did_manager=group_did_manager,
    )
    pytest.dm = dmws


def docker_load_dm():
    logger.info("DOCKER: Loading DidManagerWithSupers...")
    config_dir = pytest.dm_config_dir
    key = pytest.KEY

    device_keystore_path = os.path.join(config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(config_dir, "profile_keystore.json")

    device_did_keystore = KeyStore(device_keystore_path, key)
    profile_did_keystore = KeyStore(profile_keystore_path, key)
    group_did_manager = GroupDidManager(
        profile_did_keystore,
        device_did_keystore,
        auto_load_missed_blocks=False
    )
    dmws = DidManagerWithSupers(
        did_manager=group_did_manager,
    )
    logger.info("DOCKER: Loaded DidManagerWithSupers!")
    pytest.dm = dmws


def test_setup_dm(docker_container: walytis_identitiesDocker):
    """In a docker container, create an Endra dm."""
    print(coloured(f"\n\nRunning {function_name()}", "blue"))

    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_dmws_synchronisation.docker_create_dm()",
        "print(f'DOCKER: Created DidManagerWithSupers: {type(pytest.dm)}')",
        "pytest.dm.terminate()",
    ])
    output_lines = docker_container.run_python_code(
        python_code, print_output=False, timeout=PROFILE_CREATE_TIMEOUT_S,
        background=False
    ).split("\n")
    docker_lines = [
        line.replace("DOCKER: ", "").strip()
        for line in output_lines if line.startswith("DOCKER: ")
    ]
    last_line = docker_lines[-1] if len(docker_lines) > 0 else None
    mark(
        last_line == "Created DidManagerWithSupers: <class 'walytis_identities.did_manager_with_supers.DidManagerWithSupers'>",
        function_name()
    )


def test_load_dm(docker_container: walytis_identitiesDocker) -> dict | None:
    """In a docker container, load an Endra dm & create an invitation.

    The docker container must already have had the Endra dm set up.

    Args:
        docker_container: the docker container in which to load the dm
    Returns:
        dict: an invitation to allow another device to join the dm
    """
    print(coloured(f"\n\nRunning {function_name()}", "blue"))
    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_dmws_synchronisation.docker_load_dm()",
        "invitation=pytest.dm.did_manager.invite_member()",
        "print('DOCKER: ', json.dumps(invitation))",
        "print(f'DOCKER: Loaded DidManagerWithSupers: {type(pytest.dm)}')",
        "pytest.dm.terminate()",
    ])
    # breakpoint()
    output_lines = docker_container.run_python_code(
        python_code, print_output=False,
        timeout=PROFILE_CREATE_TIMEOUT_S, background=False
    ).split("\n")


    docker_lines = [
        line.replace("DOCKER: ", "").strip()
        for line in output_lines if line.startswith("DOCKER: ")
    ]
    
    if len(docker_lines) < 2:
        mark(
            False,
            function_name()
        )
        return None
            
    last_line = docker_lines[-1] if len(docker_lines) > 0 else None

    try:
        invitation = json.loads(docker_lines[-2].strip().replace("'", '"'))
    except json.decoder.JSONDecodeError:
        logger.warning(f"Error getting invitation: {docker_lines[-2]}")
        invitation = None
    mark(
        last_line == "Loaded DidManagerWithSupers: <class 'walytis_identities.did_manager_with_supers.DidManagerWithSupers'>",
        function_name()
    )

    return invitation





def docker_join_dm(invitation: str):
    logger.info("Joining Endra dm...")

    config_dir = pytest.dm_config_dir
    key = pytest.KEY
    device_keystore_path = os.path.join(config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(config_dir, "profile_keystore.json")
    device_did_keystore = KeyStore(device_keystore_path, key)
    profile_did_keystore = KeyStore(profile_keystore_path, key)
    device_did_manager = DidManager.create(device_did_keystore)

    profile_did_manager = GroupDidManager.join(
        invitation,
        profile_did_keystore,
        device_did_manager
    )

    dmws = DidManagerWithSupers(
        did_manager=profile_did_manager,
    )
    pytest.dm = dmws
    logger.info("DOCKER: Joined Endra dm, waiting to get control key...")

    sleep(PROFILE_JOIN_TIMEOUT_S)
    ctrl_key = pytest.dm.get_control_key()
    if ctrl_key.private_key:
        print("DOCKER: Got control key!")
    else:
        print("DOCKER: Haven't got control key...")


def test_add_sub(
    docker_container_new: walytis_identitiesDocker,
    docker_container_old: walytis_identitiesDocker,
    invitation: dict
) -> None:
    """
    Join an existing Endra dm on a new docker container.

    Args:
        docker_container_new: the container on which to set up Endra, joining
            the existing Endra dm
        docker_container_old; the container on which the Endra dm is
            already set up
        invitation: the invitation that allows the new docker container to join
            the Endra dm
    """
    print(coloured(f"\n\nRunning {function_name()}", "blue"))

    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_dmws_synchronisation.docker_load_dm()",
        "logger.info('Waiting to allow new device to join...')",
        f"sleep({PROFILE_JOIN_TIMEOUT_S})",
        "logger.info('Finished waiting, terminating...')",
        "pytest.dm.terminate()",
        "logger.info('Exiting after waiting.')",

    ])
    docker_container_old.run_python_code(
        python_code, background=True, print_output=False,
    )
    invit_json= json.dumps(invitation)

    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        f"test_dmws_synchronisation.docker_join_dm('{invit_json}')",
        "pytest.dm.terminate()",
    ])
    output_lines = docker_container_new.run_python_code(
        python_code, timeout=PROFILE_JOIN_TIMEOUT_S + 5, print_output=False,
        background=False
    ).split("\n")

    docker_lines = [
        line.replace("DOCKER: ", "").strip()
        for line in output_lines if line.startswith("DOCKER: ")
    ]
    last_line = docker_lines[-1] if len(docker_lines) > 0 else None

    mark(
        last_line == "Got control key!",
        function_name()
    )


def docker_create_super() -> GroupDidManager:
    logger.info("DOCKER: Creating GroupDidManager...")
    super = pytest.dm.create_super()
    print("DOCKER: ", super.did)
    return super


def docker_join_super(invitation: str | dict):
    logger.info("DOCKER: Joining GroupDidManager...")
    super = pytest.dm.join_super(invitation)
    print(super.did)
    logger.info(
        "DOCKER: Joined Endra GroupDidManager, waiting to get control key...")

    sleep(CORRESP_JOIN_TIMEOUT_S)
    ctrl_key = super.get_control_key()
    logger.info(f"DOCKER: Joined: {type(ctrl_key)}")
    if ctrl_key.private_key:
        print("DOCKER: Got control key!")
    return super


def test_create_super(docker_container: walytis_identitiesDocker) -> dict | None:
    print(coloured(f"\n\nRunning {function_name()}", "blue"))
    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_dmws_synchronisation.docker_load_dm()",
        "super=test_dmws_synchronisation.docker_create_super()",
        "invitation = super.invite_member()",
        "print('DOCKER: ',json.dumps(invitation))",
        "print(f'DOCKER: Created super: {type(super)}')",
        "pytest.dm.terminate()",
    ])
    output_lines = docker_container.run_python_code(
        python_code, print_output=False,
        timeout=PROFILE_CREATE_TIMEOUT_S, background=False
    ).split("\n")


    docker_lines = [
        line.replace("DOCKER: ", "").strip()
        for line in output_lines if line.startswith("DOCKER: ")
    ]
    
    if len(docker_lines) < 2:
        mark(
            False,
            function_name()
        )
        return None
            
    last_line = docker_lines[-1] if len(docker_lines) > 0 else None

    invitation = json.loads(docker_lines[-2].strip().replace("'", '"'))

    mark(
        last_line == "Created super: <class 'walytis_identities.group_did_manager.GroupDidManager'>",
        function_name()
    )

    return invitation


def test_device_loaded_super(docker_container: walytis_identitiesDocker, super_id: str) -> None:
    pass


def test_join_super(
    docker_container_old: walytis_identitiesDocker,
    docker_container_new: walytis_identitiesDocker,
    invitation: dict
) -> None:
    print(coloured(f"\n\nRunning {function_name()}", "blue"))
    python_code_1 = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_dmws_synchronisation.docker_load_dm()",
        "logger.info('test_join_super: Waiting to allow conversation join...')",
        f"sleep({CORRESP_JOIN_TIMEOUT_S})",
        "logger.info('Finished waiting, terminating...')",
        "pytest.dm.terminate()",
        "logger.info('Exiting after waiting.')",

    ])
    docker_container_old.run_python_code(python_code_1, background=True)
    invit_json = json.dumps(invitation)

    python_code_2 = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_dmws_synchronisation.docker_load_dm()",
        f"super = test_dmws_synchronisation.docker_join_super('{invit_json}')",
        "print('DOCKER: ', super.did)",
        "pytest.dm.terminate()",
        "super.terminate()",
    ])
    
    output_lines = docker_container_new.run_python_code(
        python_code_2, timeout=CORRESP_JOIN_TIMEOUT_S + 5, print_output=False, background=False).split("\n")
    docker_lines = [
        line.replace("DOCKER: ", "").strip()
        for line in output_lines if line.startswith("DOCKER: ")
    ]
    
    second_last_line = docker_lines[-2] if len(docker_lines) > 1 else None
    super_id = docker_lines[-1].strip()
    
    expected_super_id = did_from_blockchain_id(
        invitation['blockchain_invitation']['blockchain_id'])

    mark(
        second_last_line == "Got control key!" and
        super_id == expected_super_id,
        function_name()
    )


def test_auto_join_super(
    docker_container_old: walytis_identitiesDocker,
    docker_container_new: walytis_identitiesDocker,
    superondence_id: str
) -> None:
    print(coloured(f"\n\nRunning {function_name()}", "blue"))
    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_dmws_synchronisation.docker_load_dm()",
        "logger.info('Waiting to allow auto conversation join...')",
        f"sleep({CORRESP_JOIN_TIMEOUT_S})",
        "logger.info('Finished waiting, terminating...')",
        "pytest.dm.terminate()",
        "logger.info('Exiting after waiting.')",

    ])
    docker_container_old.run_python_code(
        python_code, print_output=False, background=True
    )
    python_code = "\n".join([
        DOCKER_PYTHON_LOAD_TESTING_CODE,
        "test_dmws_synchronisation.docker_load_dm()",
        f"sleep({CORRESP_JOIN_TIMEOUT_S})",
        "print('GroupDidManager DIDs:')",
        "for c in pytest.dm.get_active_supers():",
        "    print(c)",
        "pytest.dm.terminate()",
    ])
    try:
        output = docker_container_new.run_python_code(
            python_code, timeout=CORRESP_JOIN_TIMEOUT_S + 5,
            print_output=False, background=False
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
        superondence_id in c_ids,
        function_name()
    )


def run_tests():
    print("\nRunning tests for DidManagerWithSupers Synchronisation:")
    test_cleanup()
    test_preparations()
    test_create_docker_containers()

    # create first dm with multiple devices
    test_setup_dm(pytest.containers[0])
    invitation = test_load_dm(pytest.containers[0])
    if invitation:
        test_add_sub(pytest.containers[1], pytest.containers[0], invitation)
        test_load_dm(pytest.containers[1])
    else:
        mark(False, "No invitation")
    # create second dm with multiple devices
    test_setup_dm(pytest.containers[2])
    invitation = test_load_dm(pytest.containers[2])
    if invitation:
        test_add_sub(pytest.containers[3], pytest.containers[2], invitation)
        test_load_dm(pytest.containers[3])
    else:
        mark(False, "No invitation")

    # create superondence & share accross dms
    invitation = test_create_super(pytest.containers[0])
    if invitation:
        super_id = did_from_blockchain_id(
            invitation['blockchain_invitation']['blockchain_id']
        )

        # test that dm1's second device automatically joins the correspondence
        # after dm1's first device creates it
        test_auto_join_super(
            pytest.containers[0], pytest.containers[1], super_id
        )

        # test that dm2 can join the superondence given an invitation
        test_join_super(
            pytest.containers[0], pytest.containers[2], invitation
        )

        # test that dm2's second device automatically joins the correspondence
        # after dm2's first device joins it
        test_auto_join_super(
            pytest.containers[2], pytest.containers[3], super_id
        )
    else:
        mark(False, "No invitation")
    # create second dm with multiple devices
    test_cleanup()
    test_threads_cleanup()


if __name__ == "__main__":
    _testing_utils.PYTEST = False
    _testing_utils.BREAKPOINTS = True
    run_tests()
    _testing_utils.terminate()
