### KeyStore
- encrypted and unencrypted custom metadata

## WalIdentity

- Ensure full conformity with DID specifications
- DidManager.get_latest_did_doc & .get_latest_control_key: more efficiency by not reading through the whole blockchain
- when instantiating Blockchain objects, specify app_name

- How to make the same GroupDidManager accessible from multiple applications at once?
  - Ideas:
      - run a WalIdentity server in Brenthy
      - let each application use a separate member DID Manager, figure out how to solve ipfs_datatransmission
  - same solution for PrivateBlockchain?
  - sign infoblocks using control key AND member author's key
- Proper caching (replace with thorough implementation of block handlers?)

### Debug

- pytest gets stuck
- walytis join fails relatively often

### Next Steps:

- Blockchain invitation sharing across devices
- auto renewal of device-keys

### Optimisations

- implement Blockchain constructors "auto_start_block_handler" when it is built
