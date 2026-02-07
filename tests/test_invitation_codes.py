import os
import pytest
import _auto_run_with_pytest  # noqa
from emtest import await_thread_cleanup, env_vars, polite_wait
from conftest import cleanup_walytis_ipfs
from walytis_identities.group_did_manager import (
    InvitationCode,
    InvitationManager,
)


from datetime import datetime
from testing_utils import collect_all_test_logs

test_name = os.path.basename(__file__).split(".")[0]


class SharedData:
    pass


shared_data = SharedData()


def test_preparations():
    shared_data.start_time = datetime.now()


def test_invitation_code():
    invitation_manager = InvitationManager.create(None)
    invitation_code = invitation_manager.generate_code()
    invitation_code2 = InvitationCode.deserialise(invitation_code.serialise())
    assert (
        invitation_code2.key.get_id() == invitation_code.key.get_id()
        and invitation_code2.ipfs_id == invitation_code.ipfs_id
        and invitation_code2.ipfs_addresses == invitation_code.ipfs_addresses
    ), "InvitationCode Serialisation"
    assert invitation_code2.key.get_id() == invitation_manager.key.get_id()
    invitation_manager.terminate()


def test_threads_cleanup(request: pytest.FixtureRequest) -> None:
    """Test that no threads are left running."""
    cleanup_walytis_ipfs()
    collect_all_test_logs(
        test_name, [], request.config, shared_data.start_time
    )
    assert await_thread_cleanup(timeout=10)
