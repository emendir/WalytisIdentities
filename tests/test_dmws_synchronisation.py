import json
import os
import shutil
from threading import Thread

import _auto_run_with_pytest  # noqa
from conftest import cleanup_walytis_ipfs
import pytest
from brenthy_docker import DockerShellError, DockerShellTimeoutError
from brenthy_tools_beta.utils import function_name
from emtest import are_we_in_docker, await_thread_cleanup, env_vars
from termcolor import colored as coloured
from testing_utils import (
    CORRESP_JOIN_TIMEOUT_S,
    CRYPTO_FAMILY,
    KEY,
    PROFILE_CREATE_TIMEOUT_S,
    PROFILE_JOIN_TIMEOUT_S,
    dm_config_dir,
)
from walid_docker.build_docker import build_docker_image
from walid_docker.walid_docker import (
    WalytisIdentitiesDocker,
    delete_containers,
)

from walytis_identities.log import (
    logger_dmws as logger,
    file_handler,
    console_handler,
    logger_gdm_join,
)
import logging

file_handler.setLevel(logging.DEBUG)
console_handler.setLevel(logging.DEBUG)
logger_gdm_join.setLevel(logging.DEBUG)
logger.setLevel(logging.DEBUG)

REBUILD_DOCKER = True
REBUILD_DOCKER = env_vars.bool("TESTS_REBUILD_DOCKER", default=REBUILD_DOCKER)

CONTAINER_NAME_PREFIX = "walytis_identities_tests_device_"


# Boilerplate python code when for running python tests in a docker container
DOCKER_PYTHON_LOAD_TESTING_CODE = """
import sys
import threading
import json
from time import sleep
sys.path.append('/opt/walytis_identities/tests')
import conftest # configure Walytis API & logging
import docker_dmws_sync
from docker_dmws_sync import shared_data
import pytest
from docker_dmws_sync import logger
logger.info('DOCKER: Preparing tests...')
docker_dmws_sync.REBUILD_DOCKER=False
docker_dmws_sync.DELETE_ALL_BRENTHY_DOCKERS=False
logger.info('DOCKER: Ready to test!')
"""
DOCKER_PYTHON_FINISH_TESTING_CODE = """
"""

N_DOCKER_CONTAINERS = 4


class SharedData:
    def __init__(self):
        self.abort = False
        self.super = None
        self.dm = None
        self.key_store_path = os.path.join(dm_config_dir, "keystore.json")

        # the cryptographic family to use for the tests
        self.CRYPTO_FAMILY = CRYPTO_FAMILY
        self.KEY = KEY
        print("Setting up docker containers...")

        self.containers: list[WalytisIdentitiesDocker] = [
            None
        ] * N_DOCKER_CONTAINERS

    def init_dockers(self):
        threads = []
        delete_containers(container_name_substr=CONTAINER_NAME_PREFIX)
        for i in range(N_DOCKER_CONTAINERS):

            def task(number):
                self.containers[number] = WalytisIdentitiesDocker(
                    container_name=f"{CONTAINER_NAME_PREFIX}{number}"
                )

            thread = Thread(target=task, args=(i,))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
        print("Set up docker containers.")


shared_data = SharedData()


@pytest.fixture(scope="module", autouse=True)
def setup_and_teardown() -> None:
    """Wrap around tests, running preparations and cleaning up afterwards.

    A module-level fixture that runs once for all tests in this file.
    """
    # Setup: code here runs before tests that uses this fixture
    print(f"\nRunning tests for {__name__}\n")
    prepare()

    yield  # This separates setup from teardown

    # Teardown: code here runs after the tests
    print(f"\nFinished tests for {__name__}\n")
    cleanup()


def prepare():
    if not os.path.exists(dm_config_dir):
        os.makedirs(dm_config_dir)
    if are_we_in_docker():
        return
    if REBUILD_DOCKER:
        build_docker_image(verbose=False)

    shared_data.init_dockers()


def cleanup():
    if os.path.exists(dm_config_dir):
        shutil.rmtree(dm_config_dir)
    for container in shared_data.containers:
        try:
            container.delete()
        except:
            pass
    shared_data.containers = []
    if shared_data.super:
        shared_data.super.delete()
    if shared_data.dm:
        shared_data.dm.delete()
    cleanup_walytis_ipfs()


def setup_dm(docker_container: WalytisIdentitiesDocker):
    """In a docker container, create an Endra dm."""
    print(coloured(f"\n\nRunning {function_name()}", "blue"))

    python_code = "\n".join(
        [
            DOCKER_PYTHON_LOAD_TESTING_CODE,
            "docker_dmws_sync.docker_create_dm()",
            "print(f'DOCKER: Created DidManagerWithSupers: {type(shared_data.dm)}')",
            "shared_data.dm.terminate()",
            "print('Terminated!')",
        ]
    )
    try:
        output_lines = docker_container.run_python_code(
            python_code,
            print_output=True,
            timeout=PROFILE_CREATE_TIMEOUT_S,
            background=False,
        ).split("\n")

    except DockerShellError as e:
        print(e)
        output_lines = []
        breakpoint()
    except DockerShellTimeoutError as e:
        print(f"Docker shell timeout reached after {e.timeout}s")
        output_lines = e.output.split("\n")
    docker_lines = [
        line.replace("DOCKER: ", "").strip()
        for line in output_lines
        if line.startswith("DOCKER: ")
    ]
    last_line = docker_lines[-1] if len(docker_lines) > 0 else None
    assert (
        last_line
        == "Created DidManagerWithSupers: <class 'walytis_identities.did_manager_with_supers.DidManagerWithSupers'>"
    ), function_name()


def load_dm(docker_container: WalytisIdentitiesDocker) -> dict | None:
    """In a docker container, load an Endra dm & create an invitation.

    The docker container must already have had the Endra dm set up.

    Args:
        docker_container: the docker container in which to load the dm
    Returns:
        dict: an invitation to allow another device to join the dm
    """
    print(coloured(f"\n\nRunning {function_name()}", "blue"))
    python_code = "\n".join(
        [
            DOCKER_PYTHON_LOAD_TESTING_CODE,
            "docker_dmws_sync.docker_load_dm()",
            "invitation=shared_data.dm.did_manager.invite_member()",
            "print('DOCKER: ', json.dumps(invitation))",
            "print(f'DOCKER: Loaded DidManagerWithSupers: {type(shared_data.dm)}')",
            "shared_data.dm.terminate()",
        ]
    )
    # breakpoint()
    try:
        output_lines = docker_container.run_python_code(
            python_code,
            print_output=True,
            timeout=PROFILE_CREATE_TIMEOUT_S,
            background=False,
        ).split("\n")
    except DockerShellError as e:
        print(e)
        output_lines = []
        breakpoint()
    except DockerShellTimeoutError as e:
        print(f"Docker shell timeout reached after {e.timeout}s")
        output_lines = e.output.split("\n")

    docker_lines = [
        line.replace("DOCKER: ", "").strip()
        for line in output_lines
        if line.startswith("DOCKER: ")
    ]

    if len(docker_lines) < 2:
        assert False, function_name()

    last_line = docker_lines[-1] if len(docker_lines) > 0 else None

    try:
        invitation = json.loads(docker_lines[-2].strip().replace("'", '"'))
    except json.decoder.JSONDecodeError:
        logger.warning(f"Error getting invitation: {docker_lines[-2]}")
        invitation = None
    assert (
        last_line
        == "Loaded DidManagerWithSupers: <class 'walytis_identities.did_manager_with_supers.DidManagerWithSupers'>"
    ), function_name()

    return invitation


def add_sub(
    docker_container_new: WalytisIdentitiesDocker,
    docker_container_old: WalytisIdentitiesDocker,
    invitation: dict,
) -> None:
    """Join an existing Endra dm on a new docker container.

    Args:
        docker_container_new: the container on which to set up Endra, joining
            the existing Endra dm
        docker_container_old; the container on which the Endra dm is
            already set up
        invitation: the invitation that allows the new docker container to join
            the Endra dm
    """
    print(coloured(f"\n\nRunning {function_name()}", "blue"))

    python_code = "\n".join(
        [
            DOCKER_PYTHON_LOAD_TESTING_CODE,
            "docker_dmws_sync.docker_load_dm()",
            "logger.info('Waiting to allow new device to join...')",
            f"sleep({PROFILE_JOIN_TIMEOUT_S})",
            "logger.info('Finished waiting, terminating...')",
            "shared_data.dm.terminate()",
            "logger.info('Exiting after waiting.')",
        ]
    )
    docker_container_old.run_python_code(
        python_code,
        background=True,
        print_output=True,
    )
    invit_json = json.dumps(invitation)

    python_code = "\n".join(
        [
            DOCKER_PYTHON_LOAD_TESTING_CODE,
            f"docker_dmws_sync.docker_join_dm('{invit_json}')",
            "shared_data.dm.terminate()",
        ]
    )
    try:
        output_lines = docker_container_new.run_python_code(
            python_code,
            timeout=PROFILE_JOIN_TIMEOUT_S + 5,
            print_output=True,
            background=False,
        ).split("\n")
    except DockerShellError as e:
        print(e)
        output_lines = []
        breakpoint()
    except DockerShellTimeoutError as e:
        print(f"Docker shell timeout reached after {e.timeout}s")
        output_lines = e.output.split("\n")

    docker_lines = [
        line.replace("DOCKER: ", "").strip()
        for line in output_lines
        if line.startswith("DOCKER: ")
    ]
    last_line = docker_lines[-1] if len(docker_lines) > 0 else None

    assert last_line == "Got control key!", function_name()


def create_super(docker_container: WalytisIdentitiesDocker) -> dict | None:
    print(coloured(f"\n\nRunning {function_name()}", "blue"))
    python_code = "\n".join(
        [
            DOCKER_PYTHON_LOAD_TESTING_CODE,
            "docker_dmws_sync.docker_load_dm()",
            "super=docker_dmws_sync.docker_create_super()",
            "invitation = super.invite_member()",
            "invitation.update({'did':super.did})",
            "print('DOCKER: ',json.dumps(invitation))",
            "print(f'DOCKER: Created super: {type(super)}')",
            "shared_data.dm.terminate()",
        ]
    )
    try:
        output_lines = docker_container.run_python_code(
            python_code,
            print_output=True,
            timeout=PROFILE_CREATE_TIMEOUT_S,
            background=False,
        ).split("\n")
    except DockerShellError as e:
        print(e)
        output_lines = []
        breakpoint()
    except DockerShellTimeoutError as e:
        print(f"Docker shell timeout reached after {e.timeout}s")
        output_lines = e.output.split("\n")

    docker_lines = [
        line.replace("DOCKER: ", "").strip()
        for line in output_lines
        if line.startswith("DOCKER: ")
    ]

    if len(docker_lines) < 2:
        assert False, function_name()
        return None

    last_line = docker_lines[-1] if len(docker_lines) > 0 else None

    invitation = json.loads(docker_lines[-2].strip().replace("'", '"'))

    assert (
        last_line
        == "Created super: <class 'walytis_identities.group_did_manager.GroupDidManager'>"
    ), function_name()

    return invitation


def join_super(
    docker_container_old: WalytisIdentitiesDocker,
    docker_container_new: WalytisIdentitiesDocker,
    invitation: dict,
) -> None:
    print(coloured(f"\n\nRunning {function_name()}", "blue"))
    python_code_1 = "\n".join(
        [
            DOCKER_PYTHON_LOAD_TESTING_CODE,
            "docker_dmws_sync.docker_load_dm()",
            "logger.info('join_super: Waiting to allow conversation join...')",
            f"sleep({CORRESP_JOIN_TIMEOUT_S})",
            "logger.info('Finished waiting, terminating...')",
            "shared_data.dm.terminate()",
            "logger.info('Exiting after waiting.')",
        ]
    )
    docker_container_old.run_python_code(python_code_1, background=True)
    invit_json = json.dumps(invitation)

    python_code_2 = "\n".join(
        [
            DOCKER_PYTHON_LOAD_TESTING_CODE,
            "docker_dmws_sync.docker_load_dm()",
            f"super = docker_dmws_sync.docker_join_super('{invit_json}')",
            "print('DOCKER: ', super.did)",
            "shared_data.dm.terminate()",
            "super.terminate()",
        ]
    )

    try:
        output_lines = docker_container_new.run_python_code(
            python_code_2,
            timeout=CORRESP_JOIN_TIMEOUT_S + 5,
            print_output=True,
            background=False,
        ).split("\n")
    except DockerShellError as e:
        print(e)
        output_lines = []
        breakpoint()
    except DockerShellTimeoutError as e:
        print(f"Docker shell timeout reached after {e.timeout}s")
        output_lines = e.output.split("\n")

    docker_lines = [
        line.replace("DOCKER: ", "").strip()
        for line in output_lines
        if line.startswith("DOCKER: ")
    ]

    second_last_line = docker_lines[-2] if len(docker_lines) > 1 else None
    super_id = docker_lines[-1].strip() if len(docker_lines) > 0 else None
    expected_super_id = invitation["did"]

    assert (
        second_last_line == "Got control key!"
        and super_id == expected_super_id
    ), function_name()


def auto_join_super(
    docker_container_old: WalytisIdentitiesDocker,
    docker_container_new: WalytisIdentitiesDocker,
    superondence_id: str,
) -> None:
    print(coloured(f"\n\nRunning {function_name()}", "blue"))
    python_code = "\n".join(
        [
            DOCKER_PYTHON_LOAD_TESTING_CODE,
            "docker_dmws_sync.docker_load_dm()",
            "logger.info('Waiting to allow auto conversation join...')",
            f"sleep({CORRESP_JOIN_TIMEOUT_S})",
            "logger.info('Finished waiting, terminating...')",
            "shared_data.dm.terminate()",
            "logger.info('Exiting after waiting.')",
        ]
    )

    docker_container_old.run_python_code(
        python_code, print_output=True, background=True
    )
    python_code = "\n".join(
        [
            DOCKER_PYTHON_LOAD_TESTING_CODE,
            "docker_dmws_sync.docker_load_dm()",
            f"sleep({CORRESP_JOIN_TIMEOUT_S})",
            "print('GroupDidManager DIDs:')",
            "for c in shared_data.dm.get_active_supers():",
            "    print(c)",
            "shared_data.dm.terminate()",
        ]
    )
    try:
        output = docker_container_new.run_python_code(
            python_code,
            timeout=CORRESP_JOIN_TIMEOUT_S + 15,
            print_output=True,
            background=False,
        )
    except DockerShellError as e:
        print(e)
        output = ""
        breakpoint()
    except DockerShellTimeoutError as e:
        print(f"Docker shell timeout reached after {e.timeout}s")
        output = e.output
    output_lines = output.split("GroupDidManager DIDs:")
    c_ids: list[str] = []
    if len(output_lines) == 2:
        none, c_id_text = output_lines  # noqa
        c_ids = [line.strip() for line in c_id_text.split("\n")]
        c_ids = [c_id for c_id in c_ids if c_id != ""]

    assert superondence_id in c_ids, function_name()


def test_setup_dm():
    # create first dm with multiple devices
    setup_dm(shared_data.containers[0])


def test_load_dm0():
    shared_data.invitation = load_dm(shared_data.containers[0])


def test_add_sub():
    if not shared_data.invitation:
        shared_data.abort = True
    if shared_data.abort:
        pytest.skip("Test aborted due to failures.")
    add_sub(
        shared_data.containers[1],
        shared_data.containers[0],
        shared_data.invitation,
    )


def test_load_dm():
    if shared_data.abort:
        pytest.skip("Test aborted due to failures.")
    load_dm(shared_data.containers[1])


def test_setup_dm_2():
    if shared_data.abort:
        pytest.skip("Test aborted due to failures.")
    # create second dm with multiple devices
    setup_dm(shared_data.containers[2])


def test_load_dm2():
    shared_data.invitation2 = load_dm(shared_data.containers[2])


def test_add_sub2():
    if not shared_data.invitation2:
        shared_data.abort = True
    if shared_data.abort:
        pytest.skip("Test aborted due to failures.")
    add_sub(
        shared_data.containers[3],
        shared_data.containers[2],
        shared_data.invitation2,
    )


def test_load_dm3():
    if shared_data.abort:
        pytest.skip("Test aborted due to failures.")
    load_dm(shared_data.containers[3])


def test_super_3():
    # create superondence & share accross dms
    shared_data.invitation3 = create_super(shared_data.containers[0])


def test_auto_join_super_1():
    if not shared_data.invitation3:
        shared_data.abort = True
    if shared_data.abort:
        pytest.skip("Test aborted due to failures.")
    shared_data.super_id = shared_data.invitation3["did"]

    # test that dm1's second device automatically joins the correspondence
    # after dm1's first device creates it
    auto_join_super(
        shared_data.containers[0],
        shared_data.containers[1],
        shared_data.super_id,
    )


def test_join_super_1():
    if shared_data.abort:
        pytest.skip("Test aborted due to failures.")
    # test that dm2 can join the superondence given an invitation
    join_super(
        shared_data.containers[0],
        shared_data.containers[2],
        shared_data.invitation3,
    )


def test_auto_join_super_2():
    if shared_data.abort:
        pytest.skip("Test aborted due to failures.")
    # test that dm2's second device automatically joins the correspondence
    # after dm2's first device joins it
    auto_join_super(
        shared_data.containers[2],
        shared_data.containers[3],
        shared_data.super_id,
    )
    # create second dm with multiple devices


def test_threads_cleanup() -> None:
    """Test that no threads are left running."""
    cleanup()
    assert await_thread_cleanup(timeout=10)
