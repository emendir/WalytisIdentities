import test_key_store
import test_did_manager
import test_identities
import test_identity_manager
import testing_utils

testing_utils.PYTEST = False

test_key_store.run_tests()
test_did_manager.run_tests()
test_identities.run_tests()
test_identity_manager.run_tests()
