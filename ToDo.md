## WalIdentity

- Ensure full conformity with DID specifications
- DidManager.get_latest_did_doc & .get_latest_control_key: more efficiency by not reading through the whole blockchain
- when instantiating Blockchain objects, specify app_name

- How to make the same GroupDidManager accessible from multiple applications at once?
  - run a WalIdentity server in Brenthy
  - same solution for PrivateBlockchain?

### Debug

- pytest gets stuck

### Next Steps:

- Blockchain invitation sharing across devices
- auto renewal of device-keys
- inherit GenericBlockchain

### Optimisations

- implement Blockchain constructors "auto_start_block_handler" when it is built
