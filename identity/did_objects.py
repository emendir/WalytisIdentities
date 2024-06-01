import rfc3987
import json
from dataclasses import dataclass
from typing import Union


@dataclass
class Service:
    service_id: str
    type: str
    # example: 'messenger://user_id/chatroom'
    service_endpoint: str | list | dict

    @staticmethod
    def from_service_spec(service_spec: dict):
        return Service(
            service_id=service_spec['id'].strip("#"),
            type=service_spec['type'],
            service_endpoint=['serviceEndpoint']
        )

    def generate_service_spec(self):
        return {
            "id": f"#{self.service_id}",
            "type": self.type,
            "serviceEndpoint": self.service_endpoint
        }


@dataclass
class Key:
    key_id: str | None
    type: str | None
    public_key: str | None
    private_key: str | None

    @staticmethod
    def from_key_spec(key_spec: dict):
        return Key(
            key_id=key_spec['id'].strip("#"),
            type=key_spec['type'],
            public_key=key_spec['publicKeyMultibase'],
            private_key=None
        )

    def generate_key_spec(self, controller):
        return {
            "id": f"#{self.key_id}",
            "type": self.type,
            "publicKeyMultibase": self.public_key,
            "controller": controller
        }
