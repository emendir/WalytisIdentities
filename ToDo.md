- Ensure full conformity with DID specifications
- DidManager.get_latest_did_doc & .get_latest_control_key: more efficiency by not reading through the whole blockchain
- when instantiating Blockchain objects, specify app_name

## Debug
- pytest gets stuck


# Next Steps:
- member management
  - remove all occurrances of IdentityAccess.add_member, replacing with invite_member
- invitation sharing across devices
- auto renewal of device-keys


