from walytis_identities.did_manager_blocks import ControlKeyBlock
from walytis_identities.key_objects import Key
from walytis_identities.group_did_manager import CRYPTO_FAMILY

old_keys = [Key.create(CRYPTO_FAMILY) for i in range(2)]
new_keys = [Key.create(CRYPTO_FAMILY) for i in range(2)]
ckb = ControlKeyBlock.new(old_keys, new_keys)

sig_data = bytes.decode(ckb.get_signature_data())
for key in old_keys:
    assert key.get_key_id() in sig_data
for key in new_keys:
    assert key.get_key_id() in sig_data

assert [key.get_key_id() for key in ckb.get_old_keys()] == [
    key.get_key_id() for key in old_keys
]
assert [key.get_key_id() for key in ckb.get_new_keys()] == [
    key.get_key_id() for key in new_keys
]
