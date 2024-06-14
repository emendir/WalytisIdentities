import testing_utils
import tempfile
import walytis_beta_api as walytis_api
import pytest
import sys
import os
from testing_utils import mark, polite_wait
from walytis_auth_docker.walytis_auth_docker import (
    ContactsDocker, delete_containers
)
import json
from multi_crypt import Crypt
import shutil


if True:
    sys.path.insert(0, os.path.join(
        os.path.abspath(os.path.dirname(os.path.dirname(__file__))), "src"
    ))

    from identity.did_objects import Key
    from identity.key_store import KeyStore
    from identity.identity import IdentityAccess
    from identity.did_manager import DidManager

REBUILD_DOCKER = True

# automatically remove all docker containers after failed tests
DELETE_ALL_BRENTHY_DOCKERS = True


def test_preparations():
    if DELETE_ALL_BRENTHY_DOCKERS:
        delete_containers()

    if REBUILD_DOCKER:
        from walytis_auth_docker.build_docker import build_docker_image

        build_docker_image(verbose=False)
    pytest.device_1_config_dir = tempfile.mkdtemp()
    pytest.device_2_config_dir = tempfile.mkdtemp()
    pytest.key_store_path = os.path.join(pytest.device_1_config_dir, "keystore.json")

    pytest.CRYPTO_FAMILY = "EC-secp256k1"  # the cryptographic family to use for the tests
    pytest.CRYPT = Crypt.new(pytest.CRYPTO_FAMILY)

    pytest.containers: list[ContactsDocker] = []
    pytest.invitation = None


def test_create_dockker_containers():
    for i in range(3):
        pytest.containers.append(ContactsDocker())


def cleanup():
    for container in pytest.containers:
        container.delete()

    pytest.device_2.terminate()
    pytest.device_2.device_did_manager.delete()
    pytest.device_1.delete()
    shutil.rmtree(pytest.device_1_config_dir)
    shutil.rmtree(pytest.device_2_config_dir)


def create_identity_and_invitation():
    pytest.device_1 = IdentityAccess.create(
        "/opt",
        pytest.CRYPT,
    )
    invitation = pytest.device_1.create_invitation()
    print(invitation)
    # mark(isinstance(pytest.device_1, IdentityAccess), "Created IdentityAccess")


def add_device(did: str):
    pytest.device_1 = IdentityAccess.load_from_appdata(
        "/opt",
        pytest.CRYPT,
    )
    pytest.device_1.add_member(did)

    members = pytest.device_1.get_members()
    success = (
        {"did": pytest.device_2_did} in pytest.device_1.person_did_manager.get_members()
        and {"did": pytest.device_2_did} in pytest.device_1.get_members()
    )
    if success:
        print(success)
    else:
        print("DID-MAnager Members:", pytest.device_1.person_did_manager.get_members())
        print("Person Members:", pytest.device_1.get_members())


def test_create_identity_and_invitation():
    print("Creating identiy and invitation on docker...")
    output = pytest.containers[0].run_python_command(
        "import sys;"
        "sys.path.append('/opt/WalytisAuth/tests');"
        "import test_key_sharing;"
        "test_key_sharing.REBUILD_DOCKER=False;"
        "test_key_sharing.DELETE_ALL_BRENTHY_DOCKERS=False;"
        "test_key_sharing.test_preparations();"
        "test_key_sharing.create_identity_and_invitation();"
        "test_key_sharing.pytest.device_1.terminate()"
    )
    print("Got output!")
    try:
        pytest.invitation = json.loads(output)
    except:
        pass
    mark(
        pytest.invitation is not None,
        "created identity and invitation on docker"
    )


def test_add_device_identity():
    pytest.device_2 = IdentityAccess.join(
        pytest.invitation, pytest.device_2_config_dir, pytest.CRYPT)

    pytest.device_2_did = pytest.device_2.device_did_manager.get_did()

    print("Adding device on docker...")
    output = pytest.containers[0].run_python_command(
        "import sys;"
        "sys.path.append('/opt/WalytisAuth/tests');"
        "import test_key_sharing;"
        "test_key_sharing.REBUILD_DOCKER=False;"
        "test_key_sharing.DELETE_ALL_BRENTHY_DOCKERS=False;"
        "test_key_sharing.test_preparations();"
        f"test_key_sharing.add_device('{pytest.device_2_did}');"
        "test_key_sharing.pytest.device_1.terminate()"
    )
    print("Got output!")

    mark(
        output == "True",
        "Added member"
    )


def test_get_control_key():
    pytest.device_1.add_member(pytest.device_2_did)
    polite_wait(20)
    mark(
        pytest.device_2.person_did_manager.get_control_key().private_key,
        "Got control key ownership"
    )


def run_tests():
    print("\nRunning tests for Key Sharing:")
    test_preparations()
    test_create_dockker_containers()

    test_create_identity_and_invitation()
    if pytest.invitation:
        test_add_device_identity()
        test_get_control_key()
    cleanup()


if __name__ == "__main__":
    testing_utils.PYTEST = False
    testing_utils.BREAKPOINTS = True
    run_tests()
