import test_key_store
import test_did_manager
import test_group_did_manager
import test_key_sharing
import test_generic_blockchain_features
import test_dmws
import test_dmws_synchronisation
import test_dmws_generic_blockchain_features
import _testing_utils
from time import sleep
from walytis_beta_embedded._walytis_beta.walytis_beta_api._experimental import generic_blockchain_testing
from walytis_auth_docker.build_docker import build_docker_image

build_docker_image()
_testing_utils.PYTEST = False
_testing_utils.BREAKPOINTS = False
test_key_sharing.REBUILD_DOCKER=False
test_dmws_synchronisation.REBUILD_DOCKER=False

generic_blockchain_testing.PYTEST = False


test_key_store.run_tests()
test_did_manager.run_tests()

test_group_did_manager.run_tests()
test_key_sharing.run_tests()
test_generic_blockchain_features.run_tests()

test_dmws.run_tests()
test_dmws_generic_blockchain_features.run_tests()

test_dmws_synchronisation.run_tests()

sleep(1)
