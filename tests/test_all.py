import test_key_store
import test_did_manager
import test_identities
import test_contacts_chain
import test_key_sharing
import _testing_utils
from time import sleep

_testing_utils.PYTEST = False

test_key_store.run_tests()
test_did_manager.run_tests()
test_identities.run_tests()
test_key_sharing.run_tests()
test_contacts_chain.run_tests()
sleep(1)
