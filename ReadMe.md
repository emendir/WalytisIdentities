# Walytis Decentralised Identity Management

A system for managing identities, contacts and their cryptographic keys based on the Walytis blockchain.

It implements the [World-Wide-Web-Consoritum's (W3C's) Decentralised Identifiers (DIDs) specifications](https://www.w3.org/TR/did-core/).

In the context of W3C's DID architecture, walytis_identities is a [DID method](https://www.w3.org/TR/did-core/#methods),
meaning that walytis_identities is a system for creating DIDs and managing DID-Documents.
walytis_identities achieves this using the Walytis blockchain.

## Project Status **EXPERIMENTAL**

This library is very early in its development.

The API of this library IS LIKELY TO CHANGE in the near future!

## Basic Functionality

### Communication With a walytis_identities Identity

- A WaltyisFriends identity is served by a Walytis blockchain.
- The blockchain is used to publish DID-documents, which contain cryptographic public keys.
- Other parties can join a walytis_identities identity's blockchain, get the currently valid DID document, and use the cryptographic keys therein for authentication and encryption when communicating with that identity.

### Security of DID-Document Publishing

- When creating a walytis_identities identity, a set of cryptographic keys called identity-control-keys are generated. These are used for authenticating the publication of DID-documents. These keys are distinct from the keys published in the DID-documents, instead they are published on the blockchain alongside DID-documents and used to sign the DID-documents. These keys are the ownership of the identity.
- These keys are automatically renewed, by publishing the new keys on the blockchain, signed by the latest currently valid key.
- The management of these keys, and their validity and renewal, is independent of the management, validity and renewal of DID-documents and the keys publishing therein.

### Managing Multiple Devices _(Identity Owners)_

#### Device Management

- the list of devices that are members of an identity is published on the identity-control blockchain

#### Device Authentication

- each device has cryptographic keys which they use for authentication
- each device updates its keys using a dedicated device-keys blockchain

#### Inter-Device Communication

- data is only shared with devices that authenticate as one of the identity-member-devices listed on the identity-control-blockchain
- identity owners need to share the following keys whenever an owner renews any of the keys: - private keys for the public keys published in DID documents - private keys for the identity control keys

#### Key Renewal For Identity Control And Communication

- A device decides to renew the keys.
- It waits until a significant number of its other devices are online
- it shares the new private key with the others
- it publishes the public key on the blockchain

#### Services:

URI specs: https://www.rfc-editor.org/rfc/rfc3986

## Related Projects

For more info, see:

- https://github.com/emendir/Endra
- https://github.com/emendir/BrenthyAndWalytis
