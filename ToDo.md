## Next Steps:
- PeerMonitor for GroupDidManager members
- create DidManagerWrapper class
  - DidManagerWithSupers inherits from it
  - GroupDidManagerWrapper inherits from it
- Blockchain invitation sharing across devices
- auto renewal of device-keys
- Check TODO marks in code

## Generics
- why use org_did_manager for cryptography functions?
- is org_did_manager really needed? If so, explain in docstrings

## KeyStore

- encrypted and unencrypted custom metadata

## WalIdentity
- GroupDidManager.get_members returns `list[dict]` - is that appropriate? symmetry to `DidManagerWithSupers.get_active_supers()` would be nice
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
- find better way of getting DidManager's peer ID than using blockchain invitation? see GroupDidManager.get_ipfs_ids
- 
### Tests
- DidManagerWithSupers
  - test that the return type is suprt_type in all operations returning a super

### Debug

- pytest gets stuck
- walytis join fails relatively often

### Optimisations

- implement Blockchain constructors "auto_start_block_handler" when it is built
