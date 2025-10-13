## Next Steps:

- [ ] triple-layer encryption for key sharing: GroupDidManager, Member & spontaneous ephemeral keys
- [ ] multi-algorithm multi-layer cryptography: multiple simultaneous current-control-keys in different algorithms
- [ ] write a test to verify that private keys are stored encrypted
- Walytis Invitations:
  - ensure latest invitations are always published on DidManager
  - ensure all peers add Walytis invitations published on DidManager
  - ask all members of DidManager when joining with invitation
  - Walytis: retry invitation requests in `join_blockchain` function
- PeerMonitor for GroupDidManager members
- make GroupDidManagerWrapper inherits from DidManagerWrapper
- Blockchain invitation sharing across devices
- auto renewal of device-keys
- Check TODO marks in code

## API

- DidManager Encrypt, Decrypt, Sign, Verify: use CodePackage object instead of serialised CodePackage as parameters and return types

## Generics

- why use org_did_manager for cryptography functions?
- is org_did_manager really needed? If so, explain in docstrings

## KeyStore

- encrypted and unencrypted custom metadata

## walytis_identities

- ensure all published blockchain invitation contain all members' IPFS IDs
- GroupDidManager.get_members returns `list[dict]` - is that appropriate? symmetry to `DidManagerWithSupers.get_active_supers()` would be nice
- rename group_did_manager to did_manager_with_subs and other renames?
- remove constructors with cross-inheritance function signature conflicts
- DidManager.get_latest_did_doc & .get_latest_control_key: more efficiency by not reading through the whole blockchain
- when instantiating Blockchain objects, specify app_name
- sign infoblocks using control key AND member author's key

- How to make the same GroupDidManager accessible from multiple applications at once?
  - Ideas:
    - run a walytis_identities server in Brenthy
    - let each application use a separate member DID Manager, figure out how to solve ipfs_datatransmission
  - same solution for PrivateBlockchain?
- Proper caching (replace with thorough implementation of block handlers?)

- GroupDidManagerWithSupers sometimes has to check whether self.super_type is a subclass of GroupDidManagerWrapper or GroupDidManager, because they have different constructors. Can we simplify this?
- GroupDidManagerWithSupers: implement BlocksList to avoid loading SuperRegistrationBlocks
- find better way of getting DidManager's peer ID than using blockchain invitation? see GroupDidManager.get_ipfs_ids
- reduce probability of different GDM members renewing to different keys
- separate control key from communications keys published as verificationMethod in DID-Docs
  - ensure communication keys are read from DID-Docs, not ControlKeyBlocks
  - renew communication keys separately from control keys

### Tests

- DidManagerWithSupers
  - test that the return type is suprt_type in all operations returning a super
- make `test_dmws_synchronisation` more reliable, currently it often fails at random

### Debug

- pytest gets stuck
- walytis join fails relatively often

### Optimisations

- implement Blockchain constructors "auto_start_block_handler" when it is built
