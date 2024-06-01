import sys
import os
import shutil
import os
import pytest
from termcolor import colored as coloured

if True:
    sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
    from management import friends_management
    from management import identity_management
    from identity.identity import IdentityAccess
import tempfile
BREAKPOINTS = True
PYTEST = True  # whether or not this script is being run by pytest


def mark(success, message, error_info=""):
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
    pytest.contacts_manager = None
    pytest.me2 = None
    pytest.tempdir = tempfile.mkdtemp()


def test_create_identity():
    print("Creating identity...")
    pytest.device1 = identity_management.create_device_identity()
    pytest.me1 = identity_management.create_person_identity(pytest.device1)
    keys = (
        pytest.me1.did_manager.crypt.public_key,
        pytest.me1.did_manager.crypt.private_key
    )
    did = pytest.me1.get_did()
    mark(isinstance(pytest.me1, IdentityAccess), "identity creation")


def test_create_contacts_manager():
    print("Creating contacts manager...")
    cm_filepath = os.path.join(pytest.tempdir, "contacts_manager.json")
    pytest.contacts_manager = friends_management.ContactsManager(cm_filepath)
    mark(True, "create contacts manager")


def test_befriend():
    print("Creating identity...")
    pytest.device2 = identity_management.create_device_identity()
    pytest.me2 = identity_management.create_person_identity(pytest.device2)
    print("Befriending...")
    pytest.contacts_manager.befriend(pytest.me2)
    mark(pytest.me2 in pytest.contacts_manager.get_friends(), "befriend")


def test_deletion():
    print("Deleting contacts...")
    pytest.me1.delete()
    pytest.contacts_manager.forget(pytest.me2)
    mark(pytest.me2 not in pytest.contacts_manager.get_friends(), "forget")


def pytest_unconfigure():
    """Clean up resources used during tests."""
    print("Cleaning up...")
    shutil.rmtree(pytest.tempdir)


def run_tests():
    global PYTEST
    PYTEST = False

    pytest_configure()
    test_create_identity()
    test_create_contacts_manager()
    test_befriend()
    test_deletion()
    pytest_unconfigure()


run_tests()
