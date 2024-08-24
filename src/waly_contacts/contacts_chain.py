from walidentity import IdentityAccess
from walytis_beta_api import Block
from private_blocks import PrivateBlockchain
from typing import Callable
import json
CONTACTS_CHAIN_TOPIC = "ContactsChain"


class ContactsChain:

    def __init__(
        self,
        identity_access: IdentityAccess,
        other_blocks_handler: Callable[[Block], None] | None = None,
    ):
        self.identity_access = identity_access

        self.other_blocks_handler = other_blocks_handler
        if self.identity_access.person_did_manager.other_blocks_handler is not None:
            raise Exception(
                "The IdentityAccess' person-DID-Manager's "
                "`other_blocks_handler` field has been set and would be "
                "overriden by ContactsChain.\n"
                "Remove your setting `identity_access.person_did_manager."
                "other_blocks_handler`, using the `other_blocks_handler` "
                "parameter of the `ContactsChain` constructor instead."
            )
        self.other_blocks_handler = other_blocks_handler

        self.blockchain = PrivateBlockchain(
            blockchain_identity=self.identity_access,
            block_received_handler=self._on_block_received,
            virtual_layer_name=CONTACTS_CHAIN_TOPIC,
            other_blocks_handler=self.other_blocks_handler,
        )
        self.current_contacts = []

    def get_contacts(self) -> list[str]:
        if not self.current_contacts:
            try:
                self._on_block_received(
                    self.blockchain.get_block(-1)
                )
            except IndexError:
                pass
        return self.current_contacts

    def add_contact(self, did: str):
        contacts = self.get_contacts()
        if did in contacts:
            return
        contacts.append(did)
        self._publish_contacts(contacts)

    def remove_contact(self, did: str):
        contacts = self.get_contacts()
        if did not in contacts:
            return
        contacts.remove(did)
        self._publish_contacts(contacts)

    def _publish_contacts(self, contacts: list[str]):

        content = str.encode(json.dumps(contacts))
        self.blockchain.add_block(
            content=content,
            topics=CONTACTS_CHAIN_TOPIC
        )

    def _on_block_received(self, block: Block):
        self.current_contacts = json.loads(bytes.decode(bytes(block.content)))

    def delete(self):
        self.blockchain.delete()
        try:
            self.identity_access.delete()
        except:
            pass

    def terminate(self):
        self.blockchain.terminate()
        try:
            self.identity_access.terminate()
        except:
            pass

    def __del__(self):
        self.terminate()
