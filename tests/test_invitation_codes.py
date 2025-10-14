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
from walytis_identities.group_did_manager import (
    GroupDidManager,
    InvitationCode,
    InvitationManager,
)
from walytis_identities.key_store import KeyStore
from walytis_identities.utils import logger
from walytis_identities.log import logger_datatr
import logging


def test_invitation_code():
    invitation_manager = InvitationManager.create(None)
    invitation_code = invitation_manager.generate_code()
    invitation_code2 = InvitationCode.deserialise(invitation_code.serialise())
    assert (
        invitation_code2.key.get_public_key()
        == invitation_code.key.get_public_key()
        and invitation_code2.key.family == invitation_code.key.family
        and invitation_code2.ipfs_id == invitation_code.ipfs_id
        and invitation_code2.ipfs_addresses == invitation_code.ipfs_addresses
    ), "InvitationCode Serialisation"
    assert (
        invitation_code2.key.get_public_key()
        == invitation_manager.key.get_public_key()
    )
    invitation_manager.terminate()


def test_threads_cleanup() -> None:
    """Test that no threads are left running."""
    assert await_thread_cleanup(timeout=5)
