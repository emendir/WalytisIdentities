import test_key_store
import test_did_manager
import test_group_did_manager
import test_contacts_chain
import test_key_sharing
import test_generic_blockchain_features
import test_did_manager_with_supers
import test_did_manager_with_supers_synchronisation
import _testing_utils
from time import sleep

_testing_utils.PYTEST = False

test_key_store.run_tests()
test_did_manager.run_tests()
test_group_did_manager.run_tests()
test_key_sharing.run_tests()
test_did_manager_with_supers.run_tests()
test_did_manager_with_supers_synchronisation.run_tests()

test_generic_blockchain_features.run_tests()
test_contacts_chain.run_tests()

sleep(1)
