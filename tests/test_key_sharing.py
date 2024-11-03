import json
import os
import shutil
import tempfile
from time import sleep

import _testing_utils
import pytest
import walidentity
import walytis_beta_api as walytis_api
from _testing_utils import mark, polite_wait, test_threads_cleanup
from multi_crypt import Crypt
from walidentity.did_manager import DidManager
from walidentity.did_objects import Key
from walidentity.group_did_manager import GroupDidManager
from walidentity.key_store import KeyStore
from walidentity.utils import logger
from walytis_auth_docker.walytis_auth_docker import (
    ContactsDocker,
    delete_containers,
)

walytis_api.log.PRINT_DEBUG = False
print((os.path.dirname(__file__)))
_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    module=walidentity
)

REBUILD_DOCKER = True

# automatically remove all docker containers after failed tests
DELETE_ALL_BRENTHY_DOCKERS = True


def test_preparations():
    if DELETE_ALL_BRENTHY_DOCKERS:
        delete_containers(image="local/walytis_auth_testing")

    if REBUILD_DOCKER:
        from walytis_auth_docker.build_docker import build_docker_image

        build_docker_image(verbose=False)
    pytest.group_1 = None
    pytest.group_2 = None
    pytest.group_3 = None
    pytest.member_3 = None
    pytest.member_4 = None
    pytest.group_1_config_dir = tempfile.mkdtemp()
    pytest.group_2_config_dir = tempfile.mkdtemp()
    pytest.group_3_config_dir = tempfile.mkdtemp()
    pytest.group_4_config_dir = tempfile.mkdtemp()
    pytest.member_3_keystore_file = os.path.join(tempfile.mkdtemp(), "ks.json")
    pytest.member_4_keystore_file = os.path.join(tempfile.mkdtemp(), "ks.json")

    # the cryptographic family to use for the tests
    pytest.CRYPTO_FAMILY = "EC-secp256k1"
    pytest.CRYPT = Crypt(
        pytest.CRYPTO_FAMILY, b"\'\n%\xa3\xca\x0c\xc9\x97\xfd\xb3D$\x16\x06\xebrv\xc2\xb2\x15\'\xc5\xc1\x04\xe7\xf6i\xf4\xd53W\xc7")
    pytest.containers: list[ContactsDocker] = []
    pytest.invitation = None


def test_create_docker_containers():
    for i in range(1):
        pytest.containers.append(ContactsDocker())


def cleanup():
    for container in pytest.containers:
        container.delete()
    if pytest.group_2:
        pytest.group_2.delete()
        # pytest.group_2.member_did_manager.delete()
    if pytest.group_1:
        pytest.group_1.delete()
    if pytest.group_3:
        pytest.group_3.delete()
    if pytest.group_4:
        pytest.group_4.delete()
    if pytest.member_3:
        pytest.member_3.delete()
    if pytest.member_4:
        pytest.member_4.delete()
    shutil.rmtree(pytest.group_1_config_dir)
    shutil.rmtree(pytest.group_2_config_dir)
    shutil.rmtree(pytest.group_3_config_dir)
    shutil.rmtree(pytest.group_4_config_dir)
    shutil.rmtree(os.path.dirname(pytest.member_3_keystore_file))
    shutil.rmtree(os.path.dirname(pytest.member_4_keystore_file))


def docker_create_identity_and_invitation():
    """Create an identity and invitation for it.

    TO BE RUN IN DOCKER CONTAINER.
    """
    logger.debug("DockerTest: creating identity...")
    pytest.group_1 = GroupDidManager.create(
        "/opt",
        pytest.CRYPT,
    )
    logger.debug("DockerTest: creating invitation...")
    invitation = pytest.group_1.invite_member()
    pytest.group_1.terminate()
    print(json.dumps(invitation))
    # mark(isinstance(pytest.group_1, GroupDidManager), "Created GroupDidManager")


def docker_check_new_member(did: str):
    """Add a new member to pytest.group_1.

    TO BE RUN IN DOCKER CONTAINER.
    """
    logger.debug("CND: Loading GroupDidManager...")
    pytest.group_1 = GroupDidManager(
        "/opt",
        pytest.CRYPT,
    )
    # pytest.group_1.add_member(
    #     did,
    #     invitation
    # )

    logger.debug("CND: Getting members...")
    members = pytest.group_1.get_members()
    success = (
        did in [
            member["did"]
            for member in pytest.group_1.get_members()
        ]
        and did in [
            member["did"]
            for member in pytest.group_1.get_members()
        ]
    )
    logger.debug("CND: got data, exiting...")

    if success:
        print("Member has joined!")
    else:
        print("\nDocker: DID-MAnager Members:\n",
              pytest.group_1.get_members())
        print("\nDocker: Person Members:\n", pytest.group_1.get_members())

    pytest.group_1.terminate()


def docker_renew_control_key():
    """Renew the control key of pytest.group_1.

    TO BE RUN IN DOCKER CONTAINER.
    """
    pytest.group_1 = GroupDidManager(
        "/opt",
        pytest.CRYPT,
    )
    old_key = pytest.group_1.get_control_key()
    pytest.group_1.renew_control_key()
    new_key = pytest.group_1.get_control_key()
    logger.info(f"Renewed control key! {new_key.get_key_id()}")
    logger.info(f"Old key: {old_key.get_key_id()}")
    logger.info(f"New key: {new_key.get_key_id()}")
    pytest.group_1.terminate()
    import threading
    import time
    while len(threading.enumerate()) > 1:
        print(threading.enumerate())
        time.sleep(1)
    print(f"{old_key.get_key_id()} {new_key.get_key_id()}")


def test_create_identity_and_invitation():
    print("Creating identity and invitation on docker...")
    python_code = "\n".join([
        "import sys;",
        "sys.path.append('/opt/WalIdentity/tests');",
        "import test_key_sharing;",
        "test_key_sharing.REBUILD_DOCKER=False;",
        "test_key_sharing.DELETE_ALL_BRENTHY_DOCKERS=False;",
        "test_key_sharing.test_preparations();",
        "test_key_sharing.docker_create_identity_and_invitation();",
    ])
    output = None
    # print(python_code)
    # breakpoint()
    output = pytest.containers[0].run_python_code(
        python_code, print_output=False
    )
    # print("Got output!")
    # print(output)
    try:

        pytest.invitation = [json.loads(line) for line in output.split(
            "\n") if line.startswith('{"blockchain_invitation":')][-1]
    except:
        print(f"\n{python_code}\n")
        pass
    mark(
        pytest.invitation is not None,
        "created identity and invitation on docker"
    )


def test_add_member_identity():
    try:
        pytest.group_2 = GroupDidManager.join(
            pytest.invitation, pytest.group_2_config_dir, pytest.CRYPT
        )
    except walytis_api.JoinFailureError:
        try:
            pytest.group_2 = GroupDidManager.join(
                pytest.invitation, pytest.group_2_config_dir, pytest.CRYPT)
        except walytis_api.JoinFailureError as error:
            print(error)
            breakpoint()
    pytest.group_2_did = pytest.group_2.member_did_manager.did

    # wait a short amount to allow the docker container to learn of the new member
    polite_wait(2)

    print("Adding member on docker...")
    python_code = (
        "import sys;"
        "sys.path.append('/opt/WalIdentity/tests');"
        "import test_key_sharing;"
        "import threading;"
        "from test_key_sharing import logger;"
        "test_key_sharing.REBUILD_DOCKER=False;"
        "test_key_sharing.DELETE_ALL_BRENTHY_DOCKERS=False;"
        "test_key_sharing.test_preparations();"
        f"test_key_sharing.docker_check_new_member('{pytest.group_2_did}');"
        f"logger.debug(threading.enumerate());"


    )
    # print(f"\n{python_code}\n")
    output = pytest.containers[0].run_python_code(
        python_code, print_output=False
    )

    # print(output)

    mark(
        "Member has joined!" in output,
        "Added member"
    )


def test_get_control_key():
    # create an GroupDidManager object to run on the docker container in the
    # background to handle a key request from pytest.group_2
    wait_dur_s = 30
    python_code = (
        "import sys;"
        "sys.path.append('/opt/WalIdentity/tests');"
        "import test_key_sharing;"
        "from test_key_sharing import logger;"
        "logger.info('DOCKER: Testing control key sharing...');"
        "test_key_sharing.REBUILD_DOCKER=False;"
        "test_key_sharing.DELETE_ALL_BRENTHY_DOCKERS=False;"
        "test_key_sharing.test_preparations();"
        "dev = test_key_sharing.GroupDidManager("
        "    '/opt',"
        "    test_key_sharing.pytest.CRYPT,"
        ");"
        "from time import sleep;"
        "[(sleep(10), logger.debug('waiting...')) "
        f"for i in range({wait_dur_s // 10})];"
        "dev.terminate();"
    )
    bash_code = (f'/bin/python -c "{python_code}"')
    pytest.containers[0].run_shell_command(
        bash_code, background=True, print_output=False)
    # print(bash_code)
    print("Waiting for key sharing...")
    polite_wait(wait_dur_s)
    mark(
        pytest.group_2.get_control_key().private_key,
        "Got control key ownership"
    )
    # wait a little to allow proper resources cleanup on docker container
    sleep(5)


def test_renew_control_key():
    success = True
    wait_dur_s = 30
    python_code = "\n".join([
        "import sys;",
        "sys.path.append('/opt/WalIdentity/tests');",
        "import test_key_sharing;",
        "from test_key_sharing import logger;",
        "logger.info('DOCKER: Testing control key renewal part 1...');",
        "test_key_sharing.REBUILD_DOCKER=False;",
        "test_key_sharing.DELETE_ALL_BRENTHY_DOCKERS=False;",
        "test_key_sharing.test_preparations();",
        "test_key_sharing.docker_renew_control_key();",
        "logger.info('DOCKER: Finished control key renewal part 1!');",

    ])
    output = pytest.containers[0].run_python_code(
        python_code, print_output=True
    ).split("\n")
    old_key = ""
    new_key = ""
    if output and output[-1]:
        keys = [
            line.strip("\r") for line in output if pytest.CRYPTO_FAMILY in line
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
        python_code = (
            "import sys;"
            "sys.path.append('/opt/WalIdentity/tests');"
            "import test_key_sharing;"
            "from test_key_sharing import logger;"
            "logger.info('DOCKER: Testing control key renewal part 2...');"
            "test_key_sharing.REBUILD_DOCKER=False;"
            "test_key_sharing.DELETE_ALL_BRENTHY_DOCKERS=False;"
            "test_key_sharing.test_preparations();"
            "dev = test_key_sharing.GroupDidManager("
            "    '/opt',"
            "    test_key_sharing.pytest.CRYPT,"
            ");"
            "logger.info('DOCKER: Loaded GroupDidManager.');"
            "from time import sleep;"
            "[(sleep(10), logger.debug('waiting...')) "
            f"for i in range({wait_dur_s // 10})];"
            "dev.terminate();"
            "logger.info('DOCKER: Finished Control Key Renewal test part 2.');"

        )
        shell_command = (f'/bin/python -c "{python_code}"')
        pytest.containers[0].run_shell_command(
            shell_command, background=True, print_output=False
        )

        print("Waiting for key sharing...")
        polite_wait(wait_dur_s)
        private_key = pytest.group_2.get_control_key().private_key
        try:
            new_key.unlock(private_key)
        except:
            success = False
    mark(
        success,
        "Shared key on renewal."
    )


def test_join_with_existing_member() -> None:
    key_store = KeyStore(pytest.member_3_keystore_file, pytest.CRYPT)
    pytest.member_3 = DidManager.create(key_store)
    pytest.group_3 = GroupDidManager.join(
        pytest.invitation, pytest.group_3_config_dir, pytest.CRYPT,
        member=pytest.member_3
    )
    mark(
        pytest.group_3.member_did_manager.get_control_key().private_key == pytest.member_3.get_control_key().private_key !=None,
        "Joined Group DID-Manager with existing member DID-Manager"
    )


def test_create_group_with_existing_member() -> None:
    key_store = KeyStore(pytest.member_4_keystore_file, pytest.CRYPT)
    pytest.member_4 = DidManager.create(key_store)
    pytest.group_4 = GroupDidManager.join(
        pytest.invitation, pytest.group_4_config_dir, pytest.CRYPT,
        member=pytest.member_4
    )
    mark(
        pytest.group_4.member_did_manager.get_control_key().private_key == pytest.member_4.get_control_key().private_key !=None,
        "Created Group DID-Manager with existing member DID-Manager"
    )
    pytest.group_4.terminate()

def run_tests():
    print("\nRunning tests for Key Sharing:")
    test_preparations()
    test_create_docker_containers()

    # on docker container, create identity
    test_create_identity_and_invitation()
    if not pytest.invitation:
        print("Skipped remaining tests because first test failed.")
        cleanup()
        return

    # locally join the identity created on docker
    test_add_member_identity()
    test_get_control_key()
    # test_renew_control_key()

    test_join_with_existing_member()
    test_create_group_with_existing_member()
    
    cleanup()
    test_threads_cleanup()


if __name__ == "__main__":
    _testing_utils.PYTEST = False
    _testing_utils.BREAKPOINTS = True
    run_tests()
