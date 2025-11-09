from datetime import datetime, UTC
from walytis_identities.log import console_handler
from walytis_identities.key_objects import Key
import logging

console_handler.setLevel(logging.DEBUG)

CRYPTO_FAMILY = "EC-secp256k1"
KEY = Key(
    family=CRYPTO_FAMILY,
    public_key=b"\x04\xa6#\x1a\xcf\xa7\xbe\xa8\xbf\xd9\x7fd\xa7\xab\xba\xeb{Wj\xe2\x8fH\x08*J\xda\xebS\x94\x06\xc9\x02\x8c9>\xf45\xd3=Zg\x92M\x84\xb3\xc2\xf2\xf4\xe6\xa8\xf9i\x82\xdb\xd8\x82_\xcaIT\x14\x9cA\xd3\xe1",
    private_key=b"\xd9\xd1\\D\x80\xd7\x1a\xe6E\x0bt\xdf\xd0z\x88\xeaQ\xe8\x04\x91\x11\xaf\\%wC\x83~\x0eGP\xd8",
    creation_time=datetime(2024, 11, 6, 19, 17, 45, 713000,tzinfo=UTC),
)

dm_config_dir = "/tmp/wali_test_dmws_synchronisation"

# used for creation, first loading test, and invitation creation
PROFILE_CREATE_TIMEOUT_S = 20
PROFILE_JOIN_TIMEOUT_S = 40
CORRESP_JOIN_TIMEOUT_S = 40
