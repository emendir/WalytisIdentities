## Next Steps:
- create DidManagerWrapper class
  - DidManagerWithSupers inherits from it
  - GroupDidManagerWrapper inherits from it
- Blockchain invitation sharing across devices
- auto renewal of device-keys

## KeyStore

- encrypted and unencrypted custom metadata

## WalIdentity

- rename group_did_manager to did_manager_with_subs and other renames?
- remove constructors with cross-inheritance function signature conflicts
- DidManager.get_latest_did_doc & .get_latest_control_key: more efficiency by not reading through the whole blockchain
- when instantiating Blockchain objects, specify app_name
- sign infoblocks using control key AND member author's key

- How to make the same GroupDidManager accessible from multiple applications at once?
  - Ideas:
    - run a WalIdentity server in Brenthy
    - let each application use a separate member DID Manager, figure out how to solve ipfs_datatransmission
  - same solution for PrivateBlockchain?
- Proper caching (replace with thorough implementation of block handlers?)
- Ensure full conformity with DID specifications

- GroupDidManagerWithSupers sometimes has to check whether self.super_type is a subclass of GroupDidManagerWrapper or GroupDidManager, because they have different constructors. Can we simplify this?
- GroupDidManagerWithSupers: implement BlocksList to avoid loading SuperRegistrationBlocks

### Tests
- DidManagerWithSupers
  - test that the return type is suprt_type in all operations returning a super

### Debug

- pytest gets stuck
- walytis join fails relatively often

### Optimisations

- implement Blockchain constructors "auto_start_block_handler" when it is built
