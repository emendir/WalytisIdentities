- Ensure full conformity with DID specifications
- DidManager.get_latest_did_doc & .get_latest_control_key: more efficiency by not reading through the whole blockchain
- when instantiating Blockchain objects, specify app_name

## Debug
- debug key sharing test: since refactoring, local IdentityAccess doesn't update self._control_key_id on renewal
- pytest gets stuck


## Next Steps:
- Blockchain invitation sharing across devices
- auto renewal of device-keys


## Optimisations
- implement Blockchain constructors "auto_start_block_handler" when it is built
