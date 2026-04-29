"""Machinery for DID-Managers with super GDMs.

A GroupDidManager is a DidManager that manages a set of controlling members.
With DidManagerWithSupers, a DidManager can keep track of and manage
multiple GroupDidManagers which it is a member of.
"""

import json
import os
import traceback
from collections.abc import Generator
from threading import Lock, Thread
from time import sleep
from typing import Callable, Type

from ipfs_tk_transmission import Conversation  # type: ignore
from ipfs_tk_transmission.errors import ConvListenTimeout  # type: ignore
from walytis_beta_api import (  # type: ignore
    Block,
    BlockchainAlreadyExistsError,
    join_blockchain_from_zip,
)
from walytis_beta_api._experimental.generic_blockchain import (  # type: ignore
    GenericBlockchain,  # type: ignore
)
from walytis_beta_api.exceptions import BlockNotFoundError  # type: ignore
from walytis_beta_embedded import ipfs  # type: ignore
from walytis_beta_tools._experimental.block_lazy_loading import (  # type: ignore
    BlockLazilyLoaded,
    BlocksList,
)
from walytis_beta_tools._experimental.generic_block import (  # type: ignore
    GenericBlock,  # type: ignore
)

from walytis_identities.did_manager_blocks import (
    SuperRegistrationBlock,
    get_info_blocks,
)

from . import datatransmission
from .datatransmission import COMMS_TIMEOUT_S
from .did_manager import (
    DidManager,
    blockchain_id_from_did,
)
from .generics.dm_wrapper import DidManagerWrapper
from .generics.gdm_wrapper import GroupDidManagerWrapper
from .generics.generic_did_manager import GenericDidManager
from .group_did_manager import GroupDidManager
from .key_objects import Key
from .key_store import KeyStore
from .log import logger_dmws as logger

CRYPTO_FAMILY = "EC-secp256k1"


class SuperExistsError(Exception):
    """When an error is caused by a super already being assigned to a GDM."""

    pass


class DidManagerWithSupers(DidManagerWrapper):
    """GMD managing multiple super-GDMs, managing adding archiving them."""

    def __init__(
        self,
        did_manager: DidManager,
        other_blocks_handler: Callable[[Block], None] | None = None,
        auto_load_missed_blocks: bool = True,
        super_type: Type[
            GroupDidManager | GroupDidManagerWrapper
        ] = GroupDidManager,
        virtual_layer_name: str = "DMWS",
    ):
        self.virtual_layer_name = virtual_layer_name
        self.super_type = super_type
        self._did_manager = did_manager
        self._org_did_manager = did_manager

        self.super_join_req_listener = None
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
        self.supers: dict[
            str, GroupDidManager | GroupDidManagerWrapper
        ] = dict()
        self.supers_to_join: dict[
            str, SuperRegistrationBlock | None
        ] = {}
        self._load_supers()  # load GroupDidManager objects
        self.__process_invitations = False
        self._supers_finder_thr = Thread(
            target=self._join_supers
        )

        # If this is also a GroupDidManager,
        # listen to requests from other members to join an already joined Super
        if isinstance(self.org_did_manager, GroupDidManager):
            self.super_join_req_listener = (
                datatransmission.listen_for_conversations(
                    self.org_did_manager,
                    f"{self.did}-SuperJoinRequests",
                    self.super_join_requests_handler,
                )
            )
        if auto_load_missed_blocks:
            self.load_missed_blocks()

    def _init_blocks(self) -> None:
        """Process blockchain blocks for initialisation of this object."""
        # present to other programs all blocks not created by this DidManager
        blocks = [
            block
            for block in self._did_manager.get_blocks()
            if self.virtual_layer_name not in block.topics
        ]
        self._blocks = BlocksList.from_blocks(blocks, BlockLazilyLoaded)

    def get_blocks(self, reverse: bool = False) -> Generator[GenericBlock]:
        """Get all blocks that aren't part of DMWS machinery."""
        return self._blocks.get_blocks(reverse=reverse)

    def get_block_ids(self) -> list[bytes]:
        """Get the IDs of all blocks that aren't part of DMWS machinery."""
        return self._blocks.get_long_ids()

    def get_num_blocks(self) -> int:
        """Get the number of blocks that aren't part of DMWS machinery."""
        return self._blocks.get_num_blocks()

    def get_block(self, block_id: bytes) -> GenericBlock:
        """Get a block given its ID.

        Only for blocks that aren't part of DMWS machinery.
        """
        # if index is passed instead of block_id, get block_id from index
        if isinstance(block_id, int):
            try:
                block_id = self.get_block_ids()[block_id]
            except IndexError:
                message = (
                    "Walytis_BetaAPI.Blockchain: Get Block from index: "
                    "Index out of range."
                )
                raise IndexError(message)
        else:
            id_bytearray = bytearray(block_id)
            len_id = len(id_bytearray)
            if (
                bytearray([0, 0, 0, 0]) not in id_bytearray
            ):  # if a short ID was passed
                short_id = None
                for long_id in self.get_block_ids():
                    if bytearray(long_id)[:len_id] == id_bytearray:
                        short_id = long_id
                        break
                if not short_id:
                    raise BlockNotFoundError()
                block_id = bytes(short_id)
        if isinstance(block_id, bytearray):
            block_id = bytes(block_id)
        try:
            block = self._blocks[block_id]
            return block
        except KeyError:
            error = BlockNotFoundError(
                "This block isn't recorded (by brenthy_api.Blockchain) as "
                "being part of this blockchain."
            )
            raise error

    def load_missed_blocks(self) -> None:
        """Process new blocks after/while initialising this object."""
        self._did_manager.load_missed_blocks()
        # start joining new correspondeces only after loading missed blocks
        if not self._supers_finder_thr.is_alive():
            self._supers_finder_thr.start()

    def _join_supers(self) -> None:
        while not self._terminate_dmws:
            self._process_invitations()
            sleep(1)

    def _process_invitations(self) -> None:
        # logger.debug(
        #     f"Processing invitations: {len(self.supers_to_join)}"
        # )
        _supers_to_join: dict[str, SuperRegistrationBlock | None] = {}
        joined_supers: dict[
            str, GroupDidManager | GroupDidManagerWrapper
        ] = {}
        for super_id in self.supers_to_join.keys():
            if self._terminate_dmws:
                return
            registration = self.supers_to_join[super_id]
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
                        if reg.super_id == super_id:
                            registration = reg
                            self.supers_to_join[super_id] = (
                                reg
                            )
                if not registration:
                    error_message = (
                        "BUG: "
                        "In trying to join already joined GroupDidManager, "
                        "couldn't find a matching SuperRegistrationBlock.\n"
                        f"{self._did_manager.blockchain.blockchain_id}"
                    )
                    logger.warning(error_message)
                    continue
            assert super_id == registration.super_id, (
                "BUG: mismatched super IDs in supers_to_join"
            )
            super = self._join_already_joined_super(registration)
            if super:
                joined_supers.update(
                    {super_id: super}
                )
            else:
                _supers_to_join.update({super_id: registration})
        for super_id in joined_supers.keys():
            self.supers_to_join.pop(super_id)

        self.__process_invitations = True

    def create_super(self) -> GroupDidManager:
        """Create a new GDM as a super for this object."""
        if self._terminate_dmws:
            raise Exception("DidManagerWithSupers.add: we're shutting down")
        with self.lock:
            # the GroupDidManager keystore file is located in
            # self.key_store_dir and named according to the created
            # GroupDidManager's blockchain ID and its KeyStore's key is
            # automatically added to self.key_store
            logger.debug("DMWS: Creating Super...")
            super = self.super_type.create(
                self.key_store_dir, member=self._did_manager
            )
            logger.debug("DMWS: Joining created super...")
            # invitation = super.invite_member()
            blockchain_invitation = json.loads(
                super.blockchain.create_invitation(
                    one_time=False, shared=True
                )
            )
            # register GroupDidManager on blockchain
            logger.debug("DMWS: registering created super...")
            self._register_super(
                super.did, True, blockchain_invitation
            )
            logger.debug("DMWS: updating supers...")

            # add to internal collection of GroupDidManager objects
            self.supers.update({super.did: super})
            logger.debug("DMWS: Created super!")
            return super

    def join_super(
        self,
        invitation: dict | str,
    ) -> GroupDidManager:
        """Become a member of an existing GDM."""
        logger.debug("Joining super...")
        with self.lock:
            if self._terminate_dmws:
                raise Exception(
                    "DidManagerWithSupers.add: we're shutting down"
                )

            if isinstance(invitation, str):
                invitation_d = json.loads(invitation)
            else:
                invitation_d = invitation
            logger.debug(invitation_d.keys())
            # corresp_id = did_from_blockchain_id(
            #     invitation_d["blockchain_invitation"]["blockchain_id"]
            # )

            # the GroupDidManager keystore file is located in
            # self.key_store_dir and named according to the created
            # GroupDidManager's blockchain ID and its KeyStore's key is
            # automatically added to self.key_store
            super = self.super_type.join(
                invitation=invitation_d,
                group_key_store=self.key_store_dir,
                member=self._did_manager,
            )
            if (
                super.did in self.supers
                or super.did in self._archived_corresp_ids
            ):
                raise SuperExistsError()

            blockchain_invitation = json.loads(
                super.blockchain.create_invitation(
                    one_time=False, shared=True
                )
            )
            # register GroupDidManager on blockchain
            self._register_super(
                super.did, True, blockchain_invitation
            )
            # add to internal collection of GroupDidManager objects
            self.supers.update({super.did: super})

            return super

    def archive_super(
        self, super_id: str, register: bool = True
    ) -> None:
        """Cancel our membership of the specified super."""
        with self.lock:
            if super_id in self.supers_to_join:
                self.supers_to_join.pop(super_id)
                self._archived_corresp_ids.add(super_id)
                return
            if super_id not in self.supers:
                return
            self.supers[super_id].terminate(
                terminate_member=False
            )

            if register:
                # register archiving on blockchain
                self._register_super(super_id, False, None)

            # manage internal lists of Supers
            self.supers.pop(super_id)
            self._archived_corresp_ids.add(super_id)

    def get_active_supers(self) -> set[str]:
        """Get a list of super GDMs that we are still members of."""
        # logger.debug(f"DMWS: Active supers: {len(self.supers)}")
        return set(self.supers.keys())

    def get_archived_supers(self) -> set[str]:
        """Get a list of super GDMs that we were once a member of."""
        return self._archived_corresp_ids

    def get_super(
        self, corresp_id: str
    ) -> GroupDidManager | GroupDidManagerWrapper:
        """Get the GDM object of the given Super ID."""
        return self.supers[corresp_id]

    def _join_already_joined_super(
        self, registration: SuperRegistrationBlock
    ) -> GroupDidManager | GroupDidManagerWrapper | None:
        """Join a Super which our DMWS has joined this member hasn't."""
        assert isinstance(self.org_did_manager, GroupDidManager), (
            "org_did_manager must be GroupDidManager for joining "
            "already-joined DID-Mananger"
        )
        logger.debug("JAJ: Joining already joined super...")
        super_id = registration.super_id
        super_keys = self.request_join_super(super_id)
        if not super_keys:
            return None
        blockchain_id = blockchain_id_from_did(super_id)
        with self.lock:
            if super_id in self.supers:
                logger.warning("JAJ: correspondeces already has entry")
                if not self.supers[super_id]:
                    logger.warning("JAJ: correspondeces has entry with None")
                return self.supers[super_id]

            logger.info("JAJ: Joining already joined GroupDidManager...")
            key_store_path = os.path.join(
                self.key_store_dir,
                blockchain_id_from_did(super_id) + ".json",
            )
            key = Key.create(CRYPTO_FAMILY)
            self._did_manager.key_store.add_key(key)
            key_store = KeyStore(key_store_path, key)
            for key in super_keys:
                key_store.add_key(key)

            DidManager.assign_keystore(key_store, blockchain_id)

            # logger.info("Loading super...")
            if issubclass(self.super_type, GroupDidManagerWrapper):
                super = self.super_type(  # type: ignore
                    GroupDidManager(group_key_store=key_store, member=self)
                )
            elif issubclass(self.super_type, GroupDidManager):
                super = self.super_type(
                    group_key_store=key_store, member=self._did_manager
                )
            else:
                raise Exception(
                    "self.super_type must be a subclass of GroupDidManager or "
                    "GroupDidManagerWrapper"
                )

            self.supers.update({super.did: super})
            logger.info("JAJ: Joining Super!")
            return super

    def _register_super(
        self, super_id: str, active: bool, invitation: dict | None
    ) -> None:
        """Update a super' registration, activating or archiving it.

        Args:
            super_id: the ID of the super to register
            active: whether the super is being activated or archived
            invitation: invitation to super's blockchain. Leave None when
                        `active == False`
        """
        super_registration = SuperRegistrationBlock.create(
            super_id, active, invitation
        )
        super_registration.sign(self._did_manager.get_control_keys())
        self._did_manager.add_block(
            super_registration.generate_block_content(),
            topics=[
                self.virtual_layer_name,
                super_registration.walytis_block_topic,
            ],
        )

    def _read_super_registry(self) -> tuple[set[str], set[str]]:
        """Get lists of active and archived Supers.

        Reads the profile_did_manager blockchain to get this information.

        Returns:
            tuple[set[str], set[str]]: list of active and list of archived
                                        GroupDidManager IDs
        """
        active_supers: set[str] = set()
        archived_supers: set[str] = set()
        for block in self._did_manager.blockchain.get_blocks():
            # ignore blocks that aren't SuperRegistrationBlock
            if SuperRegistrationBlock.walytis_block_topic not in block.topics:
                continue

            # load SuperRegistrationBlock
            crsp_registration = SuperRegistrationBlock.load_from_block_content(
                self._did_manager.blockchain.get_block(block.long_id).content
            )
            super_bc_id = crsp_registration.super_id

            # update lists of active and archived Supers
            if crsp_registration.active:
                active_supers.add(super_bc_id)
                if super_bc_id in archived_supers:
                    archived_supers.remove(super_bc_id)
            else:
                archived_supers.add(super_bc_id)
                if super_bc_id in active_supers:
                    active_supers.remove(super_bc_id)
        # logger.debug(f"DMWS Registry: {len(active_supers)} {
        #              len(archived_supers)}")
        return active_supers, archived_supers

    def _load_supers(self) -> None:
        with self.lock:
            supers = []

            active_super_ds, _archived_corresp_ids = (
                self._read_super_registry()
            )
            new_supers = []
            for super_id in active_super_ds:
                # figure out the filepath of this super' KeyStore
                key_store_path = os.path.join(
                    self.key_store_dir,
                    blockchain_id_from_did(super_id) + ".json",
                )
                if not os.path.exists(key_store_path):
                    new_supers.append(super_id)
                    continue
                # get this super' KeyStore Key ID
                keystore_key_id = KeyStore.get_keystore_pubkey(key_store_path)
                # get the Key from KeyStore
                key_store_key = self._did_manager.key_store.get_key(
                    keystore_key_id
                )
                # load the super' KeyStore
                key_store = KeyStore(key_store_path, key_store_key)
                if issubclass(self.super_type, GroupDidManagerWrapper):
                    super = self.super_type(  # type: ignore
                        GroupDidManager(group_key_store=key_store, member=self)
                    )
                elif issubclass(self.super_type, GroupDidManager):
                    super = self.super_type(
                        group_key_store=key_store, member=self._did_manager
                    )
                else:
                    raise Exception(
                        "self.super_type must be a subclass of "
                        "GroupDidManager or GroupDidManagerWrapper"
                    )
                supers.append(super)
            self.supers = dict(
                [
                    (super.did, super)
                    for super in supers
                ]
            )
            self._archived_corresp_ids = _archived_corresp_ids

            self.supers_to_join = dict(
                [(cid, None) for cid in new_supers]
            )
            # logger.debug(
            # f"DMWS: Supers: {len(self.supers)} "
            # f"{ len(self._archived_corresp_ids)} "
            # f"{len(self.supers_to_join)}"
            # )

    def _on_super_registration_received(self, block: Block) -> None:
        if self._terminate_dmws:
            return
        crsp_registration = SuperRegistrationBlock.load_from_block_content(
            block.content
        )
        logger.info(
            f"DidManagerWithSupers: got registration for "
            f"{crsp_registration.super_id}"
        )

        # update lists of active and archived Supers
        try:
            if crsp_registration.active:
                if not self.__process_invitations:
                    entry = {
                        crsp_registration.super_id: crsp_registration
                    }
                    self.supers_to_join.update(entry)
                    logger.info(
                        "DidManagerWithSupers: not yet joining GroupDidManager"
                    )
                else:
                    self._join_already_joined_super(crsp_registration)
                    logger.info(
                        "DidManagerWithSupers: added new GroupDidManager"
                    )
            else:
                self.archive_super(
                    crsp_registration.super_id, register=False
                )
                logger.info("DidManagerWithSupers: archived GroupDidManager")
        except SuperExistsError:
            logger.info(
                "DidManagerWithSupers: we already have this GroupDidManager!"
            )
            pass

    def _on_block_received_dmws(self, block: Block) -> None:
        logger.debug("DMWS: received new block")
        if self.virtual_layer_name in block.topics[0]:
            match block.topics[1]:
                case SuperRegistrationBlock.walytis_block_topic:
                    Thread(
                        target=self._on_super_registration_received,
                        args=(block,),
                    ).start()
                case _:
                    logger.warning(
                        "DMWS DidManagerWithSupers: Received unhandled block "
                        f"with topics: {block.topics}"
                    )
        else:
            self._blocks.add_block(BlockLazilyLoaded.from_block(block))

            if self._dmws_other_blocks_handler:
                self._dmws_other_blocks_handler(block)

    def super_join_requests_handler(self, conv: Conversation) -> None:
        """Handle join requests for Super from other members of this GDM."""
        logger.debug("SJRH: Getting key request!")
        # double-check communications are encrypted
        assert conv._encryption_callback is not None
        assert conv._decryption_callback is not None

        logger.start_recording("SUPER_JOIN_REQUESTS_HANDLER")  # type: ignore
        try:
            if self._terminate_dmws:
                return
            logger.debug("SJRH: Joined conversation.")
            said = conv.say("Hello there!".encode())
            if not said:
                raise Exception("Failed to communicate with peer.")
            if self._terminate_dmws:
                return

            message = json.loads(conv.listen(timeout=COMMS_TIMEOUT_S).decode())
            if self._terminate_dmws:
                return
            logger.debug("SJRH: got key request.")
            did = message["did"]

            if did not in self.get_active_supers():
                conv.say(
                    str.encode(
                        json.dumps(
                            {"error": "no such active super", "did": did}
                        )
                    )
                )
                return
            super = self.get_super(did)
            keys = [
                key.serialise_private()
                for key in super.key_store.get_all_keys()
            ]
            logger.debug("SJRH: Transmitting keys...")
            said = conv.say(str.encode(json.dumps({"keys": keys})))

            if not said:
                raise Exception("Failed to communicate with peer.")
            logger.debug("SJRH: Getting blockchain data...")
            blockchain_data = super.blockchain.get_blockchain_data()
            # logger.debug(conv.ipfs_client.tunnels.get_tunnels())
            logger.debug("SJRH: Sending blockchain data...")
            transmitted = conv.transmit_file(
                blockchain_data,
                metadata=super.blockchain.blockchain_id.encode(),
            )
            if not transmitted:
                raise Exception("Failed to communicate with peer.")
            logger.debug("SJRH: Finished sending all data!")

        except ConvListenTimeout:
            log = logger.get_recording("SUPER_JOIN_REQUESTS_HANDLER")  # type: ignore
            logger.warning(f"SJRH: Timeout in key request handler.\n{log}")

        except Exception as error:
            log = logger.get_recording("SUPER_JOIN_REQUESTS_HANDLER")  # type: ignore
            logger.error(
                f"\n{log}"
                f"\n{traceback.format_exc()}"
                f"SJRH: Error in request_key: {type(error)} {error}"
            )
        finally:
            if conv:
                conv.terminate()
            logger.stop_recording("SUPER_JOIN_REQUESTS_HANDLER")  # type: ignore

    def request_join_super(
        self,
        did: str,
    ) -> list[Key] | None:
        """Request another member to help join an already joined Super."""
        super_join_request_message = str.encode(
            json.dumps(
                {
                    "did": did,
                }
            )
        )
        count = 0
        for peer_id in self.get_peers():
            if peer_id == ipfs.peer_id:
                continue
            count += 1
            logger.debug(
                f"RJS: Requesting Super join from {peer_id} for {did}..."
            )

            # collect debug logs in case we encounter error
            logger.start_recording("JOIN_SUPER_REQUEST")  # type: ignore

            conv = None
            try:
                conv = datatransmission.start_conversation(
                    self.org_did_manager,
                    conv_name=f"SuperJoinRequest-{did}",
                    peer_id=peer_id,
                    others_req_listener=f"{self.did}-SuperJoinRequests",
                )
                # double-check communications are encrypted
                assert conv._encryption_callback is not None
                assert conv._decryption_callback is not None

                if self._terminate_dmws:
                    return None
                logger.debug("RJS: started conversation")

                # receive salutation
                salute = conv.listen(timeout=COMMS_TIMEOUT_S)
                if salute != "Hello there!".encode():
                    raise Exception("Failed to communicate with peer.")
                if self._terminate_dmws:
                    return None
                said = conv.say(super_join_request_message)

                if not said:
                    raise Exception("Failed to communicate with peer.")
                if self._terminate_dmws:
                    return None
                logger.debug("RJS: awaiting keys...")
                keys_response = conv.listen(timeout=COMMS_TIMEOUT_S)
                keys_data = json.loads(bytes.decode(keys_response))
                if self._terminate_dmws:
                    return None
                if "error" in keys_data:
                    logger.warning(keys_response)
                    continue

                logger.debug(keys_data.keys())
                logger.debug("RJS: awaiting blockchain data...")
                logger.debug(conv.ipfs_client.tunnels.get_tunnels())
                blockchain_response = conv.listen_for_file()
                logger.debug("RJS: Got all data!")
                conv.terminate()

                logger.debug("RJS: Processing data...")
                blockchain_data = blockchain_response["filepath"]
                blockchain_id = blockchain_response["metadata"].decode()
                logger.debug(blockchain_id)
                logger.debug(blockchain_id_from_did(did))
                assert blockchain_id == blockchain_id_from_did(did)
                blockchain_id = blockchain_id_from_did(did)
                keys = [
                    Key.deserialise_private(key) for key in keys_data["keys"]
                ]
                logger.debug("RJS: Loading blockchain...")
                try:
                    join_blockchain_from_zip(blockchain_id, blockchain_data)
                except BlockchainAlreadyExistsError:
                    pass
                logger.debug("RJS: Done!")
                return keys

            except ConvListenTimeout:
                log = logger.get_recording("JOIN_SUPER_REQUEST")  # type: ignore
                logger.warning(
                    "RJS: Timeout in super join request."
                    f"SuperJoinRequest-{did}, "
                    f"{peer_id}, {did}-SuperJoinRequests"
                    f"\nRequested key for {did} "
                    f"from {peer_id}"
                    f"\n{log}"
                )

                continue
            except Exception as error:
                log = logger.get_recording("JOIN_SUPER_REQUEST")  # type: ignore
                logger.error(
                    f"\n{log}"
                    f"\n{traceback.format_exc()}"
                    f"RJS: Error in request_key: {type(error)} {error}"
                )
                continue
            finally:
                if conv:
                    conv.terminate()
                logger.stop_recording("JOIN_SUPER_REQUEST")  # type: ignore
        logger.warning(
            f"RJS: Failed to join super for {did} after asking {count} peers"
        )
        return None

    def terminate(self) -> None:
        """Clean up all resources."""
        if self._terminate_dmws:
            return
        self._terminate_dmws = True
        if self._supers_finder_thr.is_alive():
            self._supers_finder_thr.join()
        with self.lock:
            for super in self.supers.values():
                super.terminate(terminate_member=False)
        if self.super_join_req_listener:
            self.super_join_req_listener.terminate()
        self._did_manager.terminate()

    def delete(self) -> None:
        """Delete this DMWS."""
        self.terminate()
        with self.lock:
            self._terminate_dmws = True
            for super in self.supers.values():
                super.delete(terminate_member=False)
        self._did_manager.delete()

    def __del__(self):
        """Termintate this DMWS object."""
        self.terminate()

    @property
    def blockchain(self) -> GenericBlockchain:  # noqa
        return self._did_manager.blockchain

    @property
    def blockchain_id(self) -> str:  # noqa: D102
        return self._did_manager.blockchain_id

    def add_block(
        self, content: bytes, topics: list[str] | str | None = None
    ) -> GenericBlock:
        """Add an application level block to this blockchain."""
        return self._did_manager.add_block(content=content, topics=topics)

    def encrypt(self, data: bytes, encryption_options: str = "") -> bytes:  # noqa: D102
        return self._did_manager.encrypt(
            data=data,
            encryption_options=encryption_options,
        )

    def decrypt(  # noqa: D102
        self,
        data: bytes,
    ) -> bytes:
        return self._did_manager.decrypt(data=data)

    def sign(self, data: bytes, signature_options: str = "") -> bytes:  # noqa: D102
        return self._did_manager.sign(
            data=data,
            signature_options=signature_options,
        )

    def verify_signature(  # noqa: D102
        self,
        signature: bytes,
        data: bytes,
    ) -> bool:
        return self._did_manager.verify_signature(
            signature=signature,
            data=data,
        )

    def get_peers(self) -> list[str]:  # noqa: D102
        return self._did_manager.get_peers()

    @property
    def did(self) -> str:  # noqa: D102
        return self._did_manager.did

    @property
    def did_doc(self) -> dict:  # noqa: D102
        return self._did_manager.did_doc

    @property
    def block_received_handler(self) -> Callable[[Block], None] | None:
        """The event handler for blocks not used by the DMWS machinery."""
        return self._dmws_other_blocks_handler

    @block_received_handler.setter
    def block_received_handler(
        self, block_received_handler: Callable[[Block], None]
    ) -> None:
        if self._dmws_other_blocks_handler is not None:
            raise Exception(
                "`block_received_handler` is already set!\n"
                "If you want to replace it, call "
                "`clear_block_received_handler()` first."
            )
        self._dmws_other_blocks_handler = block_received_handler

    def clear_block_received_handler(self) -> None:
        """Remove any currently configured block received handler."""
        self._dmws_other_blocks_handler = None

    @property
    def did_manager(self) -> GenericDidManager:  # noqa: D102
        return self._did_manager

    @property
    def org_did_manager(self) -> DidManager | GroupDidManager:  # noqa: D102
        return self._org_did_manager

    @property
    def key_store(self) -> KeyStore:  # noqa: D102
        return self._did_manager.key_store
