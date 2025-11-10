import _auto_run_with_pytest  # noqa

from walytis_identities.did_manager_blocks import ControlKeyBlock
from walytis_identities.key_objects import Key, KeyGroup


CRYPTO_FAMILY = "EC-secp256k1"


old_keys = [Key.create(CRYPTO_FAMILY) for i in range(2)]
new_keys = [Key.create(CRYPTO_FAMILY) for i in range(2)]
ckb = ControlKeyBlock.new(KeyGroup(old_keys), KeyGroup(new_keys))

sig_data = bytes.decode(ckb.get_signature_data())


def test_key_ids():
    for key in old_keys:
        assert key.get_id() in sig_data
    for key in new_keys:
        assert key.get_id() in sig_data


def test_keys():
    assert [key.get_id() for key in ckb.get_old_keys().keys] == [
        key.get_id() for key in old_keys
    ]
    assert [key.get_id() for key in ckb.get_new_keys().keys] == [
        key.get_id() for key in new_keys
    ]


def test_signing():
    ckb.sign()
    assert ckb.verify_signature()
