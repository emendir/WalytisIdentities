import json
import os
import shutil
import tempfile
from time import sleep
from datetime import datetime
import _testing_utils
import pytest
import walytis_identities
import walytis_beta_embedded._walytis_beta.walytis_beta_api as walytis_api
from _testing_utils import mark, polite_wait, test_threads_cleanup
from walytis_identities.did_manager import DidManager
from walytis_identities.did_objects import Key
from walytis_identities.group_did_manager import GroupDidManager
from walytis_identities.key_store import KeyStore
from walytis_identities.utils import logger
from walytis_auth_docker.walytis_auth_docker import (
    walytis_identitiesDocker,
    delete_containers,
)
from walytis_auth_docker.build_docker import build_docker_image


walytis_api.log.PRINT_DEBUG = False
print((os.path.dirname(__file__)))
_testing_utils.assert_is_loaded_from_source(
    source_dir=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    module=walytis_identities
)

REBUILD_DOCKER = True

# automatically remove all docker containers after failed tests
DELETE_ALL_BRENTHY_DOCKERS = True


def make_dir(dir_path: str) -> str:
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)
    return dir_path


def delete_path(path):
    if os.path.isdir(path):
        shutil.rmtree(path)
    elif os.path.exists(path):
        os.remove(path)


def test_preparations(delete_files: bool = False):
    if DELETE_ALL_BRENTHY_DOCKERS:
        delete_containers(image="local/walytis_auth_testing")

    if REBUILD_DOCKER:

        build_docker_image(verbose=False)
    pytest.group_1 = None
    pytest.group_2 = None
    pytest.group_3 = None
    pytest.group_4 = None
    pytest.member_3 = None
    pytest.member_4 = None
    pytest.group_1_config_dir = "/tmp/group_1"
    pytest.group_2_config_dir = "/tmp/group_2"
    pytest.group_3_config_dir = "/tmp/group_3"
    pytest.group_4_config_dir = "/tmp/group_4"
    pytest.member_3_keystore_file = os.path.join("/tmp/member_3", "ks.json")
    pytest.member_4_keystore_file = os.path.join("/tmp/member_4", "ks.json")

    if delete_files:
        delete_path(pytest.group_1_config_dir)
        delete_path(pytest.group_2_config_dir)
        delete_path(pytest.group_3_config_dir)
        delete_path(pytest.group_4_config_dir)
        delete_path(pytest.member_3_keystore_file)
        delete_path(pytest.member_4_keystore_file)
    make_dir(pytest.group_1_config_dir)
    make_dir(pytest.group_2_config_dir)
    make_dir(pytest.group_3_config_dir)
    make_dir(pytest.group_4_config_dir)
    make_dir(pytest.member_3_keystore_file)
    make_dir(pytest.member_4_keystore_file)
    # the cryptographic family to use for the tests
    pytest.CRYPTO_FAMILY = "EC-secp256k1"
    pytest.KEY = Key(
        family=pytest.CRYPTO_FAMILY,
        public_key=b'\x04\xa6#\x1a\xcf\xa7\xbe\xa8\xbf\xd9\x7fd\xa7\xab\xba\xeb{Wj\xe2\x8fH\x08*J\xda\xebS\x94\x06\xc9\x02\x8c9>\xf45\xd3=Zg\x92M\x84\xb3\xc2\xf2\xf4\xe6\xa8\xf9i\x82\xdb\xd8\x82_\xcaIT\x14\x9cA\xd3\xe1',
        private_key=b'\xd9\xd1\\D\x80\xd7\x1a\xe6E\x0bt\xdf\xd0z\x88\xeaQ\xe8\x04\x91\x11\xaf\\%wC\x83~\x0eGP\xd8',
        creation_time=datetime(2024, 11, 6, 19, 17, 45, 713000)
    )
    pytest.containers: list[walytis_identitiesDocker] = []
    pytest.invitation = None


N_DOCKER_CONTAINERS = 1


def test_create_docker_containers():
    for i in range(N_DOCKER_CONTAINERS):
        pytest.containers.append(walytis_identitiesDocker())


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

    device_keystore_path = os.path.join(
        pytest.group_1_config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(
        pytest.group_1_config_dir, "profile_keystore.json")

    device_did_keystore = KeyStore(device_keystore_path, pytest.KEY)
    profile_did_keystore = KeyStore(profile_keystore_path, pytest.KEY)
    device_did_manager = DidManager.create(device_did_keystore)

    pytest.group_1 = GroupDidManager.create(
        profile_did_keystore, device_did_manager
    )
    logger.debug("DockerTest: creating invitation...")
    invitation = pytest.group_1.invite_member()
    pytest.group_1.terminate()
    device_did_manager.terminate()
    print(json.dumps(invitation))

    # mark(isinstance(pytest.group_1, GroupDidManager), "Created GroupDidManager")


def docker_check_new_member(did: str):
    """Check that the given member DID manager is part of the group_1 group

    TO BE RUN IN DOCKER CONTAINER.
    """
    logger.debug("CND: Loading GroupDidManager...")

    device_keystore_path = os.path.join(
        pytest.group_1_config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(
        pytest.group_1_config_dir, "profile_keystore.json")

    device_did_keystore = KeyStore(device_keystore_path, pytest.KEY)
    profile_did_keystore = KeyStore(profile_keystore_path, pytest.KEY)
    pytest.group_1 = GroupDidManager(
        profile_did_keystore, device_did_keystore
    )


    logger.debug("CND: Getting members...")
    success = (
        did in [
            member.did
            for member in pytest.group_1.get_members()
        ]
        and did in [
            member.did
            for member in pytest.group_1.get_members()
        ]
    )
    logger.debug("CND: got data, exiting...")

    if success:
        print("Member has joined!")
    else:
        print("\nDocker: Members:\n", pytest.group_1.get_members())

    pytest.group_1.terminate()


def docker_be_online_30s():
    logger.debug("CND: Loading GroupDidManager...")

    device_keystore_path = os.path.join(
        pytest.group_1_config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(
        pytest.group_1_config_dir, "profile_keystore.json")

    device_did_keystore = KeyStore(device_keystore_path, pytest.KEY)
    profile_did_keystore = KeyStore(profile_keystore_path, pytest.KEY)
    pytest.group_1 = GroupDidManager(
        profile_did_keystore, device_did_keystore
    )
    from time import sleep
    for i in range(wait_dur_s // 10):
        sleep(10)
        logger.debug('waiting...')
    pytest.group_1.terminate()


def docker_renew_control_key():
    """Renew the control key of pytest.group_1.

    TO BE RUN IN DOCKER CONTAINER.
    """
    logger.debug("CND: Loading GroupDidManager...")

    device_keystore_path = os.path.join(
        pytest.group_1_config_dir, "device_keystore.json")
    profile_keystore_path = os.path.join(
        pytest.group_1_config_dir, "profile_keystore.json")

    device_did_keystore = KeyStore(device_keystore_path, pytest.KEY)
    profile_did_keystore = KeyStore(profile_keystore_path, pytest.KEY)
    pytest.group_1 = GroupDidManager(
        profile_did_keystore, device_did_keystore
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
        "sys.path.append('/opt/walytis_identities/tests');",
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
    """Test that a new member can be added to an existing group DID manager."""
    group_keystore = KeyStore(
        os.path.join(pytest.group_2_config_dir, "group_2.json"),
        pytest.KEY
    )
    member = DidManager.create(pytest.group_2_config_dir)
    try:
        pytest.group_2 = GroupDidManager.join(
            pytest.invitation, group_keystore, member
        )
    except walytis_api.JoinFailureError:
        try:
            pytest.group_2 = GroupDidManager.join(
                pytest.invitation, group_keystore, member
            )
        except walytis_api.JoinFailureError as error:
            print(error)
            breakpoint()
    pytest.group_2_did = pytest.group_2.member_did_manager.did

    # wait a short amount to allow the docker container to learn of the new member
    polite_wait(2)

    print("Adding member on docker...")
    python_code = (
        "import sys;"
        "sys.path.append('/opt/walytis_identities/tests');"
        "import test_key_sharing;"
        "import threading;"
        "from test_key_sharing import logger;"
        "test_key_sharing.REBUILD_DOCKER=False;"
        "test_key_sharing.DELETE_ALL_BRENTHY_DOCKERS=False;"
        "test_key_sharing.test_preparations();"
        f"test_key_sharing.docker_check_new_member('{member.did}');"
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
    python_code = (
        "import sys;"
        "sys.path.append('/opt/walytis_identities/tests');"
        "import test_key_sharing;"
        "from test_key_sharing import logger;"
        "logger.info('DOCKER: Testing control key sharing...');"
        "test_key_sharing.REBUILD_DOCKER=False;"
        "test_key_sharing.DELETE_ALL_BRENTHY_DOCKERS=False;"
        "test_key_sharing.test_preparations();"
        "test_key_sharing.docker_be_online_30s()"
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
    sleep(15)


wait_dur_s = 30


def test_renew_control_key():
    success = True
    python_code = "\n".join([
        "import sys;",
        "sys.path.append('/opt/walytis_identities/tests');",
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
        python_code, print_output=False
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
            "sys.path.append('/opt/walytis_identities/tests');"
            "import test_key_sharing;"
            "from test_key_sharing import logger;"
            "logger.info('DOCKER: Testing control key renewal part 2...');"
            "test_key_sharing.REBUILD_DOCKER=False;"
            "test_key_sharing.DELETE_ALL_BRENTHY_DOCKERS=False;"
            "test_key_sharing.test_preparations();"
            "test_key_sharing.docker_be_online_30s();"
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


def run_tests():
    print("\nRunning tests for Key Sharing:")
    test_preparations(delete_files=True)

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
    test_renew_control_key()

    cleanup()
    test_threads_cleanup()


if __name__ == "__main__":
    _testing_utils.PYTEST = False
    _testing_utils.BREAKPOINTS = False
    run_tests()
    _testing_utils.terminate()
    