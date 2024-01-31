import rfc3987
import json
from dataclasses import dataclass
from typing import Union


@dataclass
class Service:
    id: str
    type: str
    # example: 'messenger://user_id/chatroom'
    service_endpoint: Union[str, list, dict]

    @staticmethod
    def from_service_spec(service_spec: dict):
        return Service(
            id=service_spec['id'].strip("#"),
            type=service_spec['type'],
            service_endpoint=['serviceEndpoint']
        )

    def generate_service_spec(self):
        return {
            "id": f"#{self.id}",
            "type": self.type,
            "serviceEndpoint": self.service_endpoint
        }


@dataclass
class Key:
    id: str
    type: str
    public_key: str
    private_key: str

    @staticmethod
    def from_key_spec(key_spec: dict):
        return Key(
            id=key_spec['id'].strip("#"),
            type=key_spec['type'],
            public_key=['publicKeyMultibase']
        )

    def generate_key_spec(self, controller):
        return {
            "id": f"#{self.id}",
            "type": self.type,
            "publicKeyMultibase": self.public_key,
            "controller": controller
        }
