# Walytis Identity 

_P2P multi-controller cryptographic identity management, based on the Walytis blockchain._

Walytis is a peer-to-peer cryptographic identity management system that supports multiple controllers per identity.

The purpose of this system is to enable secure communications between distributed identities in peer-to-peer networks, which means:
- encrypting messages so that they can be decrypted only by a specific identity
- verifying the authenticity of received messages, ensuring they were authored by a specific identity

To achieve this goal in a sustainably secure fashion, WalytisIdentities' core task lies in managing the ephemeral cryptographic keys belonging to digital identities:
- it automatically renews keys at regular intervals
- it publishes the new public keys in a verifiable manner
- it securely distributes the private keys to all controllers of the identity
## Features

- fully peer-to-peer: no servers of any kind involved
- multi-controller support: a Walytis Identity can be managed by any number of controllers
- identity nesting: Walytis Identities can be controlled by other Walytis Identities
- ephemeral cryptography: regular key renewal, algorithm-agnostic, room for future algorithms

_See [Related Projects](#Related%20Projects) if this isn't quite what you're looking for!_

## Use cases

WalytisIdentities was developed to empower developers to build peer-to-peer distributed applications that require secure communications between digital identities.
A classic example of such a use case is a peer-to-peer messenger, which is being developed in the [Endra Project](https://github.com/emendir/Endra).

## Underlying Technologies
- Walytis Database-Blockchain: a blockchain that serves as a p2p distributed database
- IPFS: the peer-to-peer network layer which Walytis is built on
### DID Compatibility

WalytisIdentities implements the [World-Wide-Web-Consoritum's (W3C's) Decentralised Identifiers (DIDs) specifications](https://www.w3.org/TR/did-core/).

In the context of W3C's DID architecture, walytis_identities is a [DID method](https://www.w3.org/TR/did-core/#methods),
meaning that walytis_identities is a system for creating DIDs and managing DID-Documents.
walytis_identities achieves this using the Walytis blockchain.

## Project Status **EXPERIMENTAL**

This library is very early in its development.

The API of this library IS LIKELY TO CHANGE in the near future!

## Basic Functionality

- A Walytis identity is served by a Walytis blockchain.
- The blockchain is used to publish DID-documents, which contain cryptographic public keys.
- Other parties can join a walytis_identities identity's blockchain, get the currently valid DID document, and use the cryptographic keys therein for authentication and encryption when communicating with that identity.


URI specs: https://www.rfc-editor.org/rfc/rfc3986

## Documentation

The thorough documentation for this project and the technologies it's based on live in a dedicated repository:

https://github.com/emendir/WalytisTechnologies

## Related Projects
### The Endra Tech Stack

- [IPFS](https://ipfs.tech):  A p2p communication and content addressing protocol developed by ProtocolLabs.
- [Walytis](https://github.com/emendir/Walytis_Beta): A flexible, lightweight, nonlinear database-blockchain, built on IPFS.
- [WalytisIdentities](https://github.com/emendir/WalytisIdentities): P2P multi-controller cryptographic identity management, built on Walytis.
- [WalytisOffchain](https://github.com/emendir/WalytisOffchain): Secure access-controlled database-blockchain, built on WalytisIdentities.
- [WalytisMutability](https://github.com/emendir/WalytisMutability): A Walytis blockchain overlay featuring block mutability.
- [Endra](https://github.com/emendir/Endra): A p2p encrypted messaging protocol with multiple devices per user, built on Walytis.
- [EndraApp](https://github.com/emendir/EndraApp): A p2p encrypted messenger supporting multiple devices per user, built on Walytis.

### Alternative Technologies
- OrbitDB: a distributed IPFS-based database written in go
