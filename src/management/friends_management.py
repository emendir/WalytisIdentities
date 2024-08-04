from identity.did_manager_blocks import DidDocBlock
import os
import json


class ContactsManager:
    def __init__(self, config_file: str):
        self.config_file = config_file
        if not os.path.exists(config_file):
            self.friends = []

    def befriend(self, friend):
        self.friends.append(friend)
        self.save_friends()

    def forget(self, friend):
        self.friends.remove(friend)
        friend.delete()
        self.save_friends()

    def save_friends(self, ):
        data = json.dumps([
            json.dumps(friend.did) for friend in self.friends
        ])

        with open(self.config_file, "w+") as file:
            file.write(data)

    def on_did_update_received(self, block: DidDocBlock):
        # verify signature
        # verify current_key
        # update contact

        pass

    def get_friends(self, ):
        return self.friends
