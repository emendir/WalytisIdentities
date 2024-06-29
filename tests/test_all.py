import test_key_store
import test_did_manager
import test_identities
import test_identity_manager
import test_key_sharing
import testing_utils
from time import sleep

testing_utils.PYTEST = False

test_key_store.run_tests()
test_did_manager.run_tests()
test_identities.run_tests()
test_identity_manager.run_tests()
test_key_sharing.run_tests()
sleep(1)
