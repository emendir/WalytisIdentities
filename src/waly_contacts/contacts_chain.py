from loguru import logger
from walidentity import GroupDidManager
from walytis_beta_embedded._walytis_beta.walytis_beta_api import Block
from private_blocks import PrivateBlockchain
from typing import Callable
import json
CONTACTS_CHAIN_TOPIC = "ContactsChain"


class ContactsChain:

    def __init__(
        self,
        group_did_manager: GroupDidManager,
        other_blocks_handler: Callable[[Block], None] | None = None,
    ):
        self.group_did_manager = group_did_manager

        self._gdm_other_blocks_handler = other_blocks_handler
        if self.group_did_manager._gdm_other_blocks_handler is not None:
            raise Exception(
                "The GroupDidManager' person-DID-Manager's "
                "`._gdm_other_blocks_handler` field has been set and would be "
                "overriden by ContactsChain.\n"
                "Remove your setting `group_did_manager."
                "._gdm_other_blocks_handler`, using the `other_blocks_handler` "
                "parameter of the `ContactsChain` constructor instead."
            )
        self._dm_other_blocks_handler = other_blocks_handler

        self.blockchain = PrivateBlockchain(
            self.group_did_manager,
            block_received_handler=self._on_block_received,
            virtual_layer_name=CONTACTS_CHAIN_TOPIC,
            other_blocks_handler=self._dm_other_blocks_handler,
        )
        self.current_contacts = []
        self._terminate = False

    def get_contacts(self) -> list[str]:
        if not self.current_contacts:
            try:
                # logger.info("Trying to load latest block...")
                for i in range(-1, -1*self.blockchain.get_num_blocks()):
                    try:
                        self._on_block_received(
                            self.blockchain.get_block(-1)
                        )
                        break
                    except:
                        pass
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
        if self._terminate:
            return
        try:
            block_content = json.loads(bytes.decode(bytes(block.content)))
            if isinstance(block_content, list):
                for item in block_content:
                    if not isinstance(item, str) or not item.startswith("did:"):
                        raise Exception("This block doesn't contain a list of DIDs.")
            self.current_contacts = block_content
        except Exception as e:
            error_message = (
                "ContactsChain: failed to parse block content:\n"
                f"Block topics: {block.topics}\n"
                f"{block.content}\n"
            )
            logger.error(error_message)
            raise e

    def delete(self):
        self.terminate()
        self.blockchain.delete()
        try:
            self.group_did_manager.delete()
        except:
            pass

    def terminate(self):
        if self._terminate:
            return
        self._terminate = True
        self.blockchain.terminate()
        try:
            self.group_did_manager.terminate()
        except:
            pass

    def __del__(self):
        self.terminate()
