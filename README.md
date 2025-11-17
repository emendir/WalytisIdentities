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
- secure data transmission
- cryptography:
	- key rotation
	- hybrid cryptography combining classical and post-quantum algorithms
	- cryptographic agility (upgradable to novel algorithms)
	- perfect forward and backward secrecy for transmissions

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

## Basic Functionality

- A Walytis identity is served by a Walytis blockchain.
- The blockchain is used to publish DID-documents, which contain cryptographic public keys.
- Other parties can join a walytis_identities identity's blockchain, get the currently valid DID document, and use the cryptographic keys therein for authentication and encryption when communicating with that identity.


URI specs: https://www.rfc-editor.org/rfc/rfc3986

## Documentation

The thorough documentation for this project and the technologies it's based on live in a dedicated repository:

- [WalytisIdentities](https://github.com/emendir/WalytisTechnologies/blob/master/WalytisIdentities/1-IntroToWalytisIdentities.md): learn how WalytisIdentities works
- [Walytis Technologies](https://github.com/emendir/WalytisTechnologies): learn about the suite of tools which WalytisIdentities is part of, built to enable developers to easily develop peer-to-peer distributed applications.

## Project Status **EXPERIMENTAL**

This library is very early in its development.

The API of this library IS LIKELY TO CHANGE in the near future!

## [RoadMap](https://github.com/emendir/WalytisTechnologies/blob/master/RoadMap.md)

See the [Walytis Technologies RoadMap](https://github.com/emendir/WalytisTechnologies/blob/master/RoadMap.md) for the current plans for WalytisIdentities in the context of the larger [Walytis Technologies Project](https://github.com/emendir/WalytisTechnologies).

## Contributing

### Get Involved

- GitHub Discussions: if you want to share ideas
- GitHub Issues: if you find bugs, other issues, or would like to submit feature requests
- GitHub Merge Requests: if you think you know what you're doing, you're very welcome!

### Donate

To support me in my work on this and other projects, you can make donations with the following currencies:

- **Bitcoin:** `BC1Q45QEE6YTNGRC5TSZ42ZL3MWV8798ZEF70H2DG0`
- **Ethereum:** `0xA32C3bBC2106C986317f202B3aa8eBc3063323D4`
- [Credit Card, Debit Card, Bank Transfer, Apple Pay, Google Pay, Revolut Pay)](https://checkout.revolut.com/pay/4e4d24de-26cf-4e7d-9e84-ede89ec67f32)

Donations help me:
- dedicate more time to developing and maintaining open-source projects
- cover costs for IT resources

## About the Developer

This project is developed by a human one-man team, publishing under the name _Emendir_.  
I build open technologies trying to improve our world;
learning, working and sharing under the principle:

> _Freely I have received, freely I give._

Feel welcome to join in with code contributions, discussions, ideas and more!

## Open-Source in the Public Domain

I dedicate this project to the public domain.
It is open source and free to use, share, modify, and build upon without restrictions or conditions.

I make no patent or trademark claims over this project.  

Formally, you may use this project under either the: 
- [MIT No Attribution (MIT-0)](https://choosealicense.com/licenses/mit-0/) or
- [Creative Commons Zero (CC0)](https://choosealicense.com/licenses/cc0-1.0/)
licence at your choice. 

## Related Projects

### [Walytis Technologies](https://github.com/emendir/WalytisTechnologies)

An overarching project comprising the development of Walytis and a collection of tools based on it for real-world peer-to-peer communications.

- [Walytis](https://github.com/emendir/Walytis_Beta): A flexible, lightweight, nonlinear database-blockchain, built on IPFS.
- [WalytisIdentities](https://github.com/emendir/WalytisIdentities): P2P multi-controller cryptographic identity management, built on Walytis.
- [WalytisOffchain](https://github.com/emendir/WalytisOffchain): Secure access-controlled database-blockchain, built on WalytisIdentities.
- [WalytisMutability](https://github.com/emendir/WalytisMutability): A Walytis blockchain overlay featuring block mutability.
- [Endra](https://github.com/emendir/Endra): A P2P encrypted messaging protocol with multiple devices per user, built on Walytis.
- [EndraApp](https://github.com/emendir/EndraApp): A P2P encrypted messenger supporting multiple devices per user, built on Walytis.

### [IPFS](https://ipfs.tech)

A P2P communication and content addressing protocol developed by Protocol Labs.
This is the networking foundation which Walytis builds upon.

### Alternative Technologies

- [OrbitDB](https://orbitdb.org/): a distributed IPFS-based database written in go