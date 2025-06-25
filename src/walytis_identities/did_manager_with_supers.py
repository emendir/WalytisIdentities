from threading import Thread
from time import sleep
from multi_crypt import Crypt
from .group_did_manager import GenericDidManager
from .generics import DidManagerWrapper
from walytis_beta_api.exceptions import BlockNotFoundError
from walytis_beta_tools._experimental.block_lazy_loading import BlockLazilyLoaded, BlocksList
from typing import Type
from typing import Callable
from walytis_identities.did_manager_blocks import get_info_blocks
from walytis_beta_api import Blockchain, join_blockchain, JoinFailureError, BlockchainAlreadyExistsError
from walytis_identities.did_manager import did_from_blockchain_id
from threading import Lock, Event
from walytis_identities.did_manager import blockchain_id_from_did
import os
from walytis_beta_api import decode_short_id
from brenthy_tools_beta.utils import bytes_to_string
from walytis_identities.did_objects import Key
from walytis_identities.did_manager_blocks import InfoBlock, SuperRegistrationBlock
from walytis_identities.group_did_manager import GroupDidManager
from walytis_identities import DidManager
from dataclasses import dataclass
import json
from walytis_identities.key_store import KeyStore
from walytis_beta_api import Block
from .utils import logger
from .generics import GroupDidManagerWrapper
from walytis_beta_api._experimental.generic_blockchain import GenericBlockchain
from collections.abc import Generator
from walytis_beta_tools._experimental.generic_block import GenericBlock

CRYPTO_FAMILY = "EC-secp256k1"


class SuperExistsError(Exception):
    pass


class DidManagerWithSupers(DidManagerWrapper):
    """Manages a collection of correspondences, managing adding archiving them.
    """

    def __init__(
        self,
        did_manager: DidManager,
        other_blocks_handler: Callable[[Block], None] | None = None,
        auto_load_missed_blocks: bool = True,
        super_type: Type[GroupDidManager |
                         GroupDidManagerWrapper] = GroupDidManager,
        virtual_layer_name: str = "DMWS",

    ):
        self.virtual_layer_name = virtual_layer_name
        self.super_type = super_type
        self._did_manager = did_manager
        self._org_did_manager = did_manager
        self._init_blocks()

        did_manager.block_received_handler = self._on_block_received_dmws

        self.lock = Lock()
        self.key_store_dir = os.path.dirname(
            self._did_manager.key_store.key_store_path

        )
        self._terminate_dmws = False
        self._dmws_other_blocks_handler = other_blocks_handler

        # cached list of archived  GroupDidManager IDs
        self._archived_corresp_ids: set[str] = set()
        self.correspondences: dict[str, GroupDidManager] = dict()
        self.correspondences_to_join: dict[str,
                                           SuperRegistrationBlock | None] = {}
        self._load_supers()  # load GroupDidManager objects
        self.__process_invitations = False
        self._correspondences_finder_thr = Thread(
            target=self._join_correspondences)
        if auto_load_missed_blocks:
            self.load_missed_blocks()

    def _init_blocks(self):
        # present to other programs all blocks not created by this DidManager
        blocks = [
            block for block in self._did_manager.get_blocks()
            if self.virtual_layer_name not in block.topics
        ]
        self._blocks = BlocksList.from_blocks(
            blocks, BlockLazilyLoaded)

    def get_blocks(self, reverse: bool = False) -> Generator[GenericBlock]:
        return self._blocks.get_blocks(reverse=reverse)

    def get_block_ids(self) -> list[bytes]:
        return self._blocks.get_long_ids()

    def get_num_blocks(self) -> int:
        return self._blocks.get_num_blocks()

    def get_block(self, id: bytes) -> GenericBlock:

        # if index is passed instead of block_id, get block_id from index
        if isinstance(id, int):
            try:
                id = self.get_block_ids()[id]
            except IndexError:
                message = (
                    "Walytis_BetaAPI.Blockchain: Get Block from index: "
                    "Index out of range."
                )
                raise IndexError(message)
        else:
            id_bytearray = bytearray(id)
            len_id = len(id_bytearray)
            if bytearray([0, 0, 0, 0]) not in id_bytearray:  # if a short ID was passed
                short_id = None
                for long_id in self.get_block_ids():
                    if bytearray(long_id)[:len_id] == id_bytearray:
                        short_id = long_id
                        break
                if not short_id:
                    raise BlockNotFoundError()
                id = bytes(short_id)
        if isinstance(id, bytearray):
            id = bytes(id)
        try:
            block = self._blocks[id]
            return block
        except KeyError:

            error = BlockNotFoundError(
                "This block isn't recorded (by brenthy_api.Blockchain) as being "
                "part of this blockchain."
            )
            raise error

    def load_missed_blocks(self):
        self._did_manager.load_missed_blocks()
        # start joining new correspondeces only after loading missed blocks
        if not self._correspondences_finder_thr.is_alive():
            self._correspondences_finder_thr.start()

    def _join_correspondences(self):
        while not self._terminate_dmws:
            self._process_invitations()
            sleep(1)

    def _process_invitations(self) -> None:
        # logger.debug(
        #     f"Processing invitations: {len(self.correspondences_to_join)}"
        # )
        _supers_to_join: dict[str, SuperRegistrationBlock | None] = {}
        joined_correspondences: dict[str, GroupDidManager] = {}
        for correspondence_id in self.correspondences_to_join.keys():
            if self._terminate_dmws:
                return
            registration = self.correspondences_to_join[correspondence_id]
            if not registration:
                # logger.info("DMWS: finding blockchain invitation...")

                registrations = get_info_blocks(
                    self._did_manager.blockchain,
                    SuperRegistrationBlock,
                )
                # logger.debug(f"DMWS REGISTRATIONS: {len(registrations)}")
                registrations.reverse()
                for reg in registrations:
                    if reg.active:
                        if reg.correspondence_id == correspondence_id:
                            registration = reg
                            self.correspondences_to_join[correspondence_id] = reg
                if not registration:
                    error_message = (
                        "BUG: "
                        "In trying to join already joined GroupDidManager, "
                        "couldn't find a matching SuperRegistrationBlock.\n"
                        f"{self._did_manager.blockchain.blockchain_id}"

                    )
                    logger.warning(error_message)
                    continue
            correspondence = self._join_already_joined_super(
                correspondence_id, registration
            )
            if correspondence:
                joined_correspondences.update(
                    {correspondence_id: correspondence}
                )
            else:
                _supers_to_join.update(
                    {correspondence_id: registration})
        for correspondence_id in joined_correspondences.keys():
            self.correspondences_to_join.pop(correspondence_id)
        # self.correspondences_to_join = _supers_to_join
        # with self.lock:
            # for correspondence_id, correspondence in joined_correspondences.items():
            #     # if correspondence was archived in the meantime
            #     if correspondence_id in self._archived_corresp_ids:
            #         correspondence.terminate()
            #     else:
            #         self.correspondences.update(
            #             {correspondence_id: correspondence}
            #         )

        self.__process_invitations = True

    def create_super(self) -> GroupDidManager:
        if self._terminate_dmws:
            raise Exception(
                "DidManagerWithSupers.add: we're shutting down"
            )
        with self.lock:
            # the GroupDidManager keystore file is located in self.key_store_dir
            # and named according to the created GroupDidManager's blockchain ID
            # and its KeyStore's key is automatically added to
            # self.key_store
            logger.debug("DMWS: Creating Super...")
            correspondence = self.super_type.create(
                self.key_store_dir,
                member=self._did_manager
            )
            logger.debug("DMWS: Joining created super...")
            invitation = correspondence.invite_member()
            # register GroupDidManager on blockchain
            logger.debug("DMWS: registering created super...")
            self._register_super(
                correspondence.did, True, invitation
            )
            logger.debug("DMWS: updating correspondences...")

            # add to internal collection of GroupDidManager objects
            self.correspondences.update({correspondence.did: correspondence})
            logger.debug("DMWS: Created super!")
            return correspondence

    def join_super(self, invitation: dict | str, register=True) -> GroupDidManager:
        """
        Args:
            register: whether or not the new correspondence still needs to be
                        registered on our DidManagerWithSupers's blockchain
        """
        logger.debug("Joining super...")
        with self.lock:
            if self._terminate_dmws:
                raise Exception(
                    "DidManagerWithSupers.add: we're shutting down")

            if isinstance(invitation, str):
                invitation_d = json.loads(invitation)
            else:
                invitation_d = invitation
            corresp_id = did_from_blockchain_id(
                invitation_d["blockchain_invitation"]["blockchain_id"]
            )
            if corresp_id in self.correspondences or corresp_id in self._archived_corresp_ids:
                raise SuperExistsError()

            # the GroupDidManager keystore file is located in self.key_store_dir
            # and named according to the created GroupDidManager's blockchain ID
            # and its KeyStore's key is automatically added to
            # self.key_store
            correspondence = self.super_type.join(
                invitation=invitation_d,
                group_key_store=self.key_store_dir,
                member=self._did_manager
            )

            if register:
                # register GroupDidManager on blockchain
                self._register_super(
                    correspondence.did, True, invitation_d
                )
            # add to internal collection of GroupDidManager objects
            self.correspondences.update({correspondence.did: correspondence})

            return correspondence

    def archive_super(self, correspondence_id: str, register=True):
        with self.lock:
            if correspondence_id in self.correspondences_to_join:
                self.correspondences_to_join.pop(correspondence_id)
                self._archived_corresp_ids.add(correspondence_id)
                return
            if correspondence_id not in self.correspondences:
                return
            self.correspondences[correspondence_id].terminate(
                terminate_member=False)

            if register:
                # register archiving on blockchain
                self._register_super(correspondence_id, False, None)

            # manage internal lists of Correspondences
            self.correspondences.pop(correspondence_id)
            self._archived_corresp_ids.add(correspondence_id)

    def get_active_supers(self) -> set[str]:
        # logger.debug(f"DMWS: Active supers: {len(self.correspondences)}")
        return set(self.correspondences.keys())

    def get_archived_supers(self) -> set[str]:
        return self._archived_corresp_ids

    def get_super(self, corresp_id: str) -> GroupDidManager:
        return self.correspondences[corresp_id]

    def _join_already_joined_super(
        self, correspondence_id: str,
        registration: SuperRegistrationBlock
    ) -> GroupDidManager | None:
        """Join a Coresp. which our DidManagerWithSupers has joined but member hasn't."""
        blockchain_id = blockchain_id_from_did(correspondence_id)
        try:
            logger.info("DMWS: JAJ: Joining blockchain...")
            # join blockchain, preprocessing existing blocks
            join_blockchain(
                registration.invitation["blockchain_invitation"],
            )
        except JoinFailureError:
            logger.warning("JAJ: Failed to join blockchain...")
            try:
                logger.info("DMWS: JAJ: Joining blockchain, retrying...")
                # join blockchain, preprocessing existing blocks
                join_blockchain(
                    registration.invitation["blockchain_invitation"],
                )
            except JoinFailureError:
                logger.warning("JAJ: Failed to join blockchain...")
                return None
        except BlockchainAlreadyExistsError:
            pass
        with self.lock:
            if correspondence_id in self.correspondences:
                logger.warning("JAJ: correspondeces already has entry")
                if not self.correspondences[correspondence_id]:
                    logger.warning("JAJ: correspondeces has entry with None")
                return self.correspondences[correspondence_id]

            logger.info("JAJ: Joining already joined GroupDidManager...")
            key_store_path = os.path.join(
                self.key_store_dir,
                blockchain_id_from_did(correspondence_id) + ".json"
            )
            key = Key.create(CRYPTO_FAMILY)
            self._did_manager.key_store.add_key(key)
            key_store = KeyStore(key_store_path, key)

            DidManager.assign_keystore(key_store, blockchain_id)

            # logger.info("Loading correspondence...")
            if issubclass(self.super_type, GroupDidManagerWrapper):
                correspondence = self.super_type(GroupDidManager(
                    group_key_store=key_store,
                    member=self
                ))
            elif issubclass(self.super_type, GroupDidManager):
                correspondence = self.super_type(
                    group_key_store=key_store,
                    member=self._did_manager
                )
            else:
                raise Exception(
                    "self.super_type must be a subclass of GroupDidManager or "
                    "GroupDidManagerWrapper"
                )

            self.correspondences.update({correspondence.did: correspondence})
            logger.info("JAJ: Joining Super!")
            return correspondence

    def _register_super(
        self, correspondence_id: str, active: bool, invitation: dict | None
    ):
        """Update a correspondence' registration, activating or archiving it.

        Args:
            correspondence_id: the ID of the correspondence to register
            active: whether the correspondence is being activated or archived 
        """
        correspondence_registration = SuperRegistrationBlock.create(
            correspondence_id,
            active,
            invitation
        )
        correspondence_registration.sign(
            self._did_manager.get_control_key()
        )
        self._did_manager.add_block(
            correspondence_registration.generate_block_content(),
            topics=[self.virtual_layer_name,
                    correspondence_registration.walytis_block_topic]
        )

    def _read_super_registry(self) -> tuple[set[str], set[str]]:
        """Get lists of active and archived Correspondences.

        Reads the profile_did_manager blockchain to get this information.

        Returns:
            tuple[set[str], set[str]]: list of active and list of archived
                                        GroupDidManager IDs
        """
        active_supers: set[str] = set()
        archived_supers: set[str] = set()
        for block in self._did_manager.blockchain.get_blocks():
            # ignore blocks that aren't SuperRegistrationBlock
            if (
                SuperRegistrationBlock.walytis_block_topic
                not in block.topics
            ):
                continue

            # load SuperRegistrationBlock
            crsp_registration = SuperRegistrationBlock.load_from_block_content(
                self._did_manager.blockchain.get_block(
                    block.long_id
                ).content
            )
            correspondence_bc_id = crsp_registration.correspondence_id

            # update lists of active and archived Correspondences
            if crsp_registration.active:
                active_supers.add(correspondence_bc_id)
                if correspondence_bc_id in archived_supers:
                    archived_supers.remove(correspondence_bc_id)
            else:
                archived_supers.add(correspondence_bc_id)
                if correspondence_bc_id in active_supers:
                    active_supers.remove(correspondence_bc_id)
        # logger.debug(f"DMWS Registry: {len(active_supers)} {
        #              len(archived_supers)}")
        return active_supers, archived_supers

    def _load_supers(self) -> None:
        with self.lock:
            correspondences = []

            active_super_ds, _archived_corresp_ids = self._read_super_registry()
            new_supers = []
            for correspondence_id in active_super_ds:
                # figure out the filepath of this correspondence' KeyStore
                key_store_path = os.path.join(
                    self.key_store_dir,
                    blockchain_id_from_did(correspondence_id) + ".json"
                )
                if not os.path.exists(key_store_path):
                    new_supers.append(correspondence_id)
                    continue
                # get this correspondence' KeyStore Key ID
                keystore_key_id = KeyStore.get_keystore_pubkey(key_store_path)
                # get the Key from KeyStore
                key_store_key = self._did_manager.key_store.get_key(
                    keystore_key_id
                )
                # load the correspondence' KeyStore
                key_store = KeyStore(key_store_path, key_store_key)
                if issubclass(self.super_type, GroupDidManagerWrapper):
                    correspondence = self.super_type(GroupDidManager(
                        group_key_store=key_store,
                        member=self
                    ))
                elif issubclass(self.super_type, GroupDidManager):
                    correspondence = self.super_type(
                        group_key_store=key_store,
                        member=self._did_manager
                    )
                else:
                    raise Exception(
                        "self.super_type must be a subclass of GroupDidManager or "
                        "GroupDidManagerWrapper"
                    )
                correspondences.append(correspondence)
            self.correspondences = dict([
                (correspondence.did, correspondence)
                for correspondence in correspondences
            ])
            self._archived_corresp_ids = _archived_corresp_ids

            self.correspondences_to_join = dict([
                (cid, None) for cid in new_supers
            ])
            # logger.debug(f"DMWS: Correspondences: {len(self.correspondences)} {
            #              len(self._archived_corresp_ids)} {len(self.correspondences_to_join)}")

    def _on_super_registration_received(self, block: Block):
        if self._terminate_dmws:
            return
        crsp_registration = SuperRegistrationBlock.load_from_block_content(
            block.content
        )
        logger.info(f"DidManagerWithSupers: got registration for "
                    f"{crsp_registration.correspondence_id}")

        # update lists of active and archived Correspondences
        try:
            if crsp_registration.active:
                if not self.__process_invitations:
                    self.correspondences_to_join.update({
                        crsp_registration.correspondence_id: crsp_registration
                    })
                    logger.info(
                        "DidManagerWithSupers: not yet joining GroupDidManager"
                    )
                else:
                    self.join_super(
                        crsp_registration.invitation, register=False)
                    logger.info(
                        "DidManagerWithSupers: added new GroupDidManager"
                    )
            else:
                self.archive_super(
                    crsp_registration.correspondence_id, register=False)
                logger.info("DidManagerWithSupers: archived GroupDidManager")
        except SuperExistsError:
            logger.info(
                "DidManagerWithSupers: we already have this GroupDidManager!"
            )
            pass

    def _on_block_received_dmws(self, block: Block):
        logger.debug("DMWS: received new block")
        if self.virtual_layer_name in block.topics[0]:
            match block.topics[1]:
                case SuperRegistrationBlock.walytis_block_topic:
                    Thread(
                        target=self._on_super_registration_received,
                        args= (block,)
                    ).start()
                case _:
                    logger.warning(
                        "DMWS DidManagerWithSupers: Received unhandled block with topics: "
                        f"{block.topics}"
                    )
        else:
            self._blocks.add_block(
                BlockLazilyLoaded.from_block(block))

            if self._dmws_other_blocks_handler:
                self._dmws_other_blocks_handler(block)

    def terminate(self):
        if self._terminate_dmws:
            return
        self._terminate_dmws = True
        if self._correspondences_finder_thr.is_alive():
            self._correspondences_finder_thr.join()
        with self.lock:
            for correspondence in self.correspondences.values():
                correspondence.terminate(terminate_member=False)
        self._did_manager.terminate()

    def delete(self):
        self.terminate()
        with self.lock:
            self._terminate_dmws = True
            for correspondence in self.correspondences.values():
                correspondence.delete(terminate_member=False)
        self._did_manager.delete()

    def __del__(self):
        self.terminate()

    @property
    def blockchain(self):
        return self._did_manager.blockchain

    @property
    def blockchain_id(self) -> str:
        return self._did_manager.blockchain_id

    def add_block(
        self, content: bytes, topics: list[str] | str | None = None
    ) -> GenericBlock:
        return self._did_manager.add_block(
            content=content, topics=topics
        )

    def encrypt(
        self,
        data: bytes,
        encryption_options: str = ""
    ) -> bytes:
        """Encrypt the provided data using the specified public key.

        Args:
            data_to_encrypt(bytes): the data to encrypt
            encryption_options(str): specification code for which
                                    encryption / decryption protocol should be used
        Returns:
            bytes: the encrypted data
        """
        return self._did_manager.encrypt(
            data=data,
            encryption_options=encryption_options,
        )

    def decrypt(
        self,
        data: bytes,
    ) -> bytes:
        """Decrypt the provided data using the specified private key.

        Args:
            data (bytes): the data to decrypt
        Returns:
            bytes: the decrypted data
        """
        return self._did_manager.decrypt(data=data)

    def sign(self, data: bytes, signature_options: str = "") -> bytes:
        """Sign the provided data using the specified private key.

        Args:
            data(bytes): the data to sign
            private_key(bytes): the private key to be used for the signing
            signature_options(str): specification code for which
                                signature / verification protocol should be used
        Returns:
            bytes: the signature
        """
        return self._did_manager.sign(
            data=data,
            signature_options=signature_options,
        )

    def verify_signature(
        self,
        signature: bytes,
        data: bytes,
    ) -> bool:
        return self._did_manager.verify_signature(
            signature=signature,
            data=data,
        )

    def get_control_key(self) -> Key:
        return self._did_manager.get_control_key()

    def get_peers(self) -> list[str]:
        return self._did_manager.get_peers()

    @property
    def did(self) -> str:
        return self._did_manager.did

    @property
    def did_doc(self):
        return self._did_manager.did_doc

    @property
    def block_received_handler(self) -> Callable[[Block], None] | None:
        return self._dmws_other_blocks_handler

    @block_received_handler.setter
    def block_received_handler(
        self, block_received_handler: Callable[Block, None]
    ) -> None:
        if self._dmws_other_blocks_handler is not None:
            raise Exception(
                "`block_received_handler` is already set!\n"
                "If you want to replace it, call `clear_block_received_handler()` first."
            )
        self._dmws_other_blocks_handler = block_received_handler

    def clear_block_received_handler(self) -> None:
        self._dmws_other_blocks_handler = None

    @property
    def did_manager(self) -> GenericDidManager:
        return self._did_manager

    @property
    def key_store(self) -> KeyStore:
        return self._did_manager.key_store

    def renew_control_key(self, new_ctrl_key: Crypt | None = None) -> None:
        return self._did_manager.renew_control_key(new_ctrl_key)

    def update_did_doc(self, did_doc: dict) -> None:
        return self.update_did_doc(did_doc)

    def org_did_manager(self) -> GenericDidManager:
        return self._org_did_manager
