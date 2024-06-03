from strict_typing import strictly_typed
from decorate_all import decorate_all_functions
from .did_objects import Key
import json
import os


class KeyStore:
    keys: dict[Key]

    def __init__(self, key_store_path: str, key: Key):
        self.key_store_path = key_store_path
        self.key = key
        self._load_appdata()

    def _load_appdata(self):
        if not os.path.exists(os.path.dirname(self.key_store_path)):
            raise FileNotFoundError("The directory of the keystore path doesn't exist.")
        if not os.path.exists(self.key_store_path):
            self.keys = {}
            return
        with open(self.key_store_path, "r") as file:
            data = json.loads(file.read())
        appdata_encryption_public_key = data["appdata_encryption_public_key"]
        encrypted_keys = data["keys"]

        if appdata_encryption_public_key != self.key.public_key.hex():
            raise ValueError("Wrong cryptographic key for unlocking keystore.")

        keys = {}
        for encrypted_key in encrypted_keys:
            key = Key.deserialise(encrypted_key, self.key)
            keys.update({key.get_key_id(): key})
        self.keys = keys

    def save_appdata(self):
        encrypted_keys = []
        for key_id, key in list(self.keys.items()):
            encrypted_serialised_key = key.serialise(self.key)
            encrypted_keys.append(encrypted_serialised_key)
        data = {
            "appdata_encryption_public_key": self.key.public_key.hex(),
            "keys": encrypted_keys
        }

        with open(self.key_store_path, "w+") as file:
            file.write(json.dumps(data))

    def add_key(self, key: Key):
        self.keys.update({key.get_key_id(): key})
        self.save_appdata()

    def get_key(self, key_id: str) -> Key:
        return self.keys[key_id]


decorate_all_functions(strictly_typed, __name__)
