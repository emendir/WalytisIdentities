from dataclasses import dataclass
from typing import Type, TypeVar
from multi_crypt import Crypt
_Service = TypeVar('_Service', bound='Service')


@dataclass
class Service:
    """Represents a DID service.

    DID services are applications/operations registered in a DID document that
    use specific cryptographic keys also published in the DID document.
    """

    service_id: str
    type: str
    # example: 'messenger://user_id/chatroom'
    service_endpoint: str | list | dict

    @classmethod
    def from_service_spec(cls: Type[_Service], service_spec: dict) -> _Service:
        """Initialise a Service from a DID service spec from a DID document."""
        return cls(
            service_id=service_spec['id'].strip("#"),
            type=service_spec['type'],
            service_endpoint=['serviceEndpoint']
        )

    def generate_service_spec(self) -> dict:
        """Generate a service spec for a DID document."""
        return {
            "id": f"#{self.service_id}",
            "type": self.type,
            "serviceEndpoint": self.service_endpoint
        }


_Key = TypeVar('_Key', bound='Key')


@dataclass
class Key:
    """Represents a set of cryptographic keys, compatible with DID specs."""

    key_id: str
    type: str
    public_key: str
    private_key: str | None

    @classmethod
    def from_key_spec(cls: Type[_Key], key_spec: dict) -> _Key:
        """Initialise a Key from a DID key spec from a DID document."""
        return cls(
            key_id=key_spec['id'].strip("#"),
            type=key_spec['type'],
            public_key=key_spec['publicKeyMultibase'],
            private_key=None
        )

    def generate_key_spec(self, controller: str) -> dict:
        """Generate a key spec for a DID document."""
        return {
            "id": f"#{self.key_id}",
            "type": self.type,
            "publicKeyMultibase": self.public_key,
            "controller": controller
        }

    def serialise(self, crypt: Crypt) -> str:
        """Serialise this key's data, including the private key encrypted."""
        if not (self.key_id and self.type
                and self.public_key and self.private_key):
            raise ValueError("Not all of this objects' fields are set.")

        return {
            "key_id": self.key_id,
            "type": self.type,
            "public_key": self.public_key,
            "private_key": Crypt.encrypt(self.private_key.encode()).hex(),
        }

    @classmethod
    def deserialise(cls: Type[_Key], data: dict, crypt: Crypt) -> _Key:
        """Deserialise data with encrypted private key."""
        private_key = crypt.decrypt(bytes.fromhex(data["private_key"])).decode()
        return cls(
            key_id=data["key_id"],
            type=data["type"],
            public_key=data["public_key"],
            private_key=private_key,
        )
