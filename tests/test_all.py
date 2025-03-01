import test_key_store
import test_did_manager
import test_group_did_manager
import test_contacts_chain
import test_key_sharing
import test_generic_blockchain_features
import test_dmws
import test_dmws_synchronisation
import test_dmws_generic_blockchain_features
import _testing_utils
from time import sleep
from walytis_beta_api._experimental import generic_blockchain_testing

generic_blockchain_testing.PYTEST = False
_testing_utils.PYTEST = False

test_key_store.run_tests()
test_did_manager.run_tests()
test_group_did_manager.run_tests()
test_key_sharing.run_tests()
test_dmws.run_tests()
test_dmws_synchronisation.run_tests()
test_dmws_generic_blockchain_features.run_tests()
test_generic_blockchain_features.run_tests()
test_contacts_chain.run_tests()

sleep(1)
