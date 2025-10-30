import _auto_run_with_pytest  # noqa
from emtest import await_thread_cleanup, env_vars, polite_wait
from walytis_identities.group_did_manager import (
    InvitationCode,
    InvitationManager,
)


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
    assert await_thread_cleanup(timeout=8)
