from multi_crypt import Crypt
import json
import os


class KeyStore:
    keys: dict[Crypt]

    def __init__(self, keystore_path: str, crypt: Crypt):
        self.keystore_path = keystore_path
        self.crypt = crypt
        self._load_appdata()

    def _load_appdata(self):
        if not os.path.exists(os.path.dirname(self.keystore_path)):
            raise FileNotFoundError("The directory of the keystore path doesn't exist.")
        if not os.path.exists(self.keystore_path):
            self.keys = {}
            return
        with open(self.keystore_path, "r") as file:
            data = json.loads(file.read())
        appdata_encryption_public_key = data["appdata_encryption_public_key"]
        encrypted_keys = data["keys"]

        if appdata_encryption_public_key != self.crypt.public_key.hex():
            raise ValueError("Wrong cryptographic key for unlocking keystore.")

        keys = {}
        for key_id, encrypted_key in list(encrypted_keys.items()):
            crypt = Crypt.deserialise(
                json.loads(
                    bytes.decode(
                        self.crypt.decrypt(
                            bytes.fromhex(
                                encrypted_key
                            )
                        )
                    )
                )
            )
            keys.update({key_id: crypt})
        self.keys = keys

    def save_appdata(self):
        encrypted_keys = {}
        for key_id, key in list(self.keys.items()):
            encrypted_serialised_key = bytes.hex(bytes(
                self.crypt.encrypt(
                    str.encode(
                        json.dumps(
                            key.serialise()
                        )
                    )
                )
            ))
            encrypted_keys.update({key_id: encrypted_serialised_key})
        data = {
            "appdata_encryption_public_key": self.crypt.public_key.hex(),
            "keys": encrypted_keys
        }

        with open(self.keystore_path, "w+") as file:
            file.write(json.dumps(data))

    def add_key(self, key_id: str, crypt: Crypt):
        self.keys.update({key_id: crypt})
        self.save_appdata()

    def get_key(self, key_id: str) -> Crypt:
        return self.keys[key_id]
