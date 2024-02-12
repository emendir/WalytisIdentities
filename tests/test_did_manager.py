import walytis_beta_api as walytis_api
from termcolor import colored as coloured
import pytest
import sys
import os
if True:
    sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
    # from management import friends_management
    # from management import identity_management
    # from identity.identity import Identity
    from identity.did_manager import DidManager
    from identity.did_objects import Key

BREAKPOINTS = True
PYTEST = True  # whether or not this script is being run by pytest


def mark(success: bool, message: str, error_info: str = ""):
    """Prints a check or cross and message depending on the given success.
    If pytest is running this test, an exception is thrown if success is False.

    Parameters:
            success (bool): whether or not the test succeeded
            message (str): short description of the test to print
            error_info (str): message to print in case of failure
    """
    if success:
        mark = coloured("✓", "green")
    else:
        mark = coloured("✗", "red")
        if error_info:
            print(error_info)
        if BREAKPOINTS:
            breakpoint()
    print(mark, message)
    if PYTEST and not success:
        raise Exception(f'Failed {message}')
    return success


def pytest_configure():
    """Setup resources in preparation for tests."""
    # declare 'global' variables
    pytest.did_manager = None


def test_create_did_manager():
    pytest.did_manager = DidManager.create()
    blockchain_id = pytest.did_manager.blockchain.id

    mark(
        (
            isinstance(pytest.did_manager, DidManager)
            and blockchain_id in walytis_api.list_blockchain_ids()
        ),
        "Create DidManager"
    )


def test_delete_did_manager():
    blockchain_id = pytest.did_manager.blockchain.id
    pytest.did_manager.delete()
    mark(
        blockchain_id not in walytis_api.list_blockchain_ids(),
        "Delete DidManager"
    )


def pytest_unconfigure():
    """Clean up resources used during tests."""
    pass


def test_update_control_key():
    old_control_key = pytest.did_manager.get_control_key()

    pytest.did_manager.update_control_key()

    pytest.new_control_key = pytest.did_manager.get_control_key()
    mark(
        (
            isinstance(old_control_key, Key)
            and isinstance(pytest.new_control_key, Key)
            and old_control_key.public_key != pytest.new_control_key.public_key
        ),
        "Control Key Update"
    )


def test_update_did_doc():
    pytest.did_doc = {
        "id": pytest.did_manager.get_did(),
        "verificationMethod": [
            pytest.new_control_key.generate_key_spec(pytest.did_manager.get_did())
        ]
    }
    pytest.did_manager.update_did_doc(pytest.did_doc)
    mark(pytest.did_manager.get_did_doc() == pytest.did_doc, "Update DID Doc")


def test_update_members_list():
    pytest.members_list = [
        {'did': 'device1'},
        {'did': 'device2'},
    ]
    pytest.did_manager.update_members_list(pytest.members_list)
    mark(
        pytest.did_manager.get_members_list() == pytest.members_list,
        "Update Members List"
    )


def test_reload_did_manager():
    did_manager_copy = DidManager.load_from_blockchain(pytest.did_manager.blockchain.id)

    mark((
        did_manager_copy.get_control_key().public_key == pytest.new_control_key.public_key
        and did_manager_copy.get_did_doc() == pytest.did_doc
        and did_manager_copy.get_members_list() == pytest.members_list
    ),
        "Reload DID Manager"
    )
    did_manager_copy.terminate()


def run_tests():
    global PYTEST
    PYTEST = False
    pytest_configure()  # run test preparations

    # run tests
    test_create_did_manager()
    test_update_control_key()
    test_update_did_doc()
    test_update_members_list()
    test_reload_did_manager()
    test_delete_did_manager()

    pytest_unconfigure()  # run test cleanup


run_tests()
