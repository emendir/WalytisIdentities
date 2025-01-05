from typing import Callable
from walidentity.did_manager_blocks import get_info_blocks
from walytis_beta_api import Blockchain, join_blockchain, JoinFailureError
from walidentity.did_manager import did_from_blockchain_id
from threading import Lock, Event
from walidentity.did_manager import blockchain_id_from_did
import os
from walytis_beta_api import decode_short_id
from brenthy_tools_beta.utils import bytes_to_string
from walidentity.did_objects import Key
from walidentity.did_manager_blocks import InfoBlock
from walidentity.group_did_manager import GroupDidManager
from walidentity import DidManager
from dataclasses import dataclass
import json
from walidentity.key_store import KeyStore
from walytis_beta_api import Block
from walidentity.utils import logger
from .generics import GroupDidManagerWrapper
WALYTIS_BLOCK_TOPIC = "Endra"

CRYPTO_FAMILY = "EC-secp256k1"


@dataclass
class SuperRegistration(InfoBlock):
    """Block in a DidManagerWithSupers's blockchain registering a GroupDidManager."""
    walytis_block_topic = "endra_corresp_reg"
    info_content: dict

    @classmethod
    def create(
        cls, correspondence_id: str, active: bool, invitation: dict | None,
    ) -> 'SuperRegistration':

        info_content = {
            "correspondence_id": correspondence_id,
            "active": active,
            "invitation": invitation,
        }
        return cls.new(info_content)

    @property
    def correspondence_id(self) -> str:
        return self.info_content["correspondence_id"]

    @property
    def active(self) -> bool:
        return self.info_content["active"]

    @property
    def invitation(self) -> dict | None:
        return self.info_content["invitation"]


class SuperExistsError(Exception):
    pass
from typing import Type

class DidManagerWithSupers(GroupDidManager):
    """Manages a collection of correspondences, managing adding archiving them.
    """

    def __init__(
        self,
        group_key_store: KeyStore,
        member: KeyStore | DidManager,
        other_blocks_handler: Callable[[Block], None] | None = None,
        auto_load_missed_blocks: bool = True,
        super_type:Type[GroupDidManager|GroupDidManagerWrapper]=GroupDidManager
    ):
        self.super_type = super_type
        GroupDidManager.__init__(self,
                                 group_key_store=group_key_store,
                                 member=member,
                                 other_blocks_handler=self._on_block_received_dmws,
                                 auto_load_missed_blocks=False
                                 )

        self.lock = Lock()
        self.key_store_dir = os.path.dirname(
            self.key_store.key_store_path

        )
        self._terminate_dmws = False

        # cached list of archived  GroupDidManager IDs
        self._archived_corresp_ids: set[str] = set()
        self.correspondences: dict[str, GroupDidManager] = dict()
        self._load_supers()  # load GroupDidManager objects
        self.__process_invitations = False
        self.correspondences_to_join: dict[str, SuperRegistration | None] = {}

        self.load_missed_blocks()
        # start joining new correspondeces only after loading missed blocks
        self._process_invitations()

    def _process_invitations(self) -> None:
        # logger.debug(
        #     f"Processing invitations: {len(self.correspondences_to_join)}"
        # )
        _supers_to_join: dict[str,
                              SuperRegistration | None] = {}
        for correspondence_id in self.correspondences_to_join.keys():
            registration = self.correspondences_to_join[correspondence_id]
            if not registration:
                # logger.info("JAJ: finding blockchain invitation...")

                registrations = get_info_blocks(
                    SuperRegistration,
                    self.blockchain
                )
                invitation: SuperRegistration | None = None
                for registration in registrations.reverse():
                    if registration.active:
                        if registration.correspondence_id == correspondence_id:
                            invitation = registration.invitation
                if not invitation:
                    error_message = (
                        "BUG: "
                        "In trying to join already joined GroupDidManager, "
                        "couldn't find a matching SuperRegistration."

                    )
                    logger.warning(error_message)
                    continue
            correspondence = self._join_already_joined_super(
                correspondence_id, registration)
            if not correspondence:
                _supers_to_join.update(
                    {correspondence_id: correspondence})
        self.correspondences_to_join = _supers_to_join

        self.__process_invitations = True

    def create_super(self) -> GroupDidManager:
        with self.lock:
            if self._terminate_dmws:
                raise Exception(
                    "DidManagerWithSupers.add: we're shutting down"
                )
            # the GroupDidManager keystore file is located in self.key_store_dir
            # and named according to the created GroupDidManager's blockchain ID
            # and its KeyStore's key is automatically added to
            # self.key_store
            correspondence = self.super_type.create(
                self.key_store_dir,
                member=self
            )
            invitation = correspondence.invite_member()
            # register GroupDidManager on blockchain
            self._register_super(
                correspondence.did, True, invitation
            )

            # add to internal collection of GroupDidManager objects
            self.correspondences.update({correspondence.did: correspondence})
            return correspondence

    def join_super(self, invitation: dict | str, register=True) -> GroupDidManager:
        """
        Args:
            register: whether or not the new correspondence still needs to be
                        registered on our DidManagerWithSupers's blockchain
        """
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
                member=self
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
        return set(self.correspondences.keys())

    def get_archived_supers(self) -> set[str]:
        return self._archived_corresp_ids

    def get_super(self, corresp_id: str) -> GroupDidManager:
        return self.correspondences[corresp_id]

    def _join_already_joined_super(
        self, correspondence_id: str,
        registration: SuperRegistration
    ) -> GroupDidManager | None:
        """Join a Coresp. which our DidManagerWithSupers has joined but member hasn't."""
        with self.lock:
            # logger.info("JAJ: Joining already joined GroupDidManager...")
            key_store_path = os.path.join(
                self.key_store_dir,
                blockchain_id_from_did(correspondence_id) + ".json"
            )
            key = Key.create(CRYPTO_FAMILY)
            self.key_store.add_key(key)
            key_store = KeyStore(key_store_path, key)

            # logger.info("JAJ: Joining blockchain...")
            blockchain_id = blockchain_id_from_did(correspondence_id)
            DidManager.assign_keystore(key_store, blockchain_id)
            try:
                # join blockchain, preprocessing existing blocks
                blockchain = Blockchain.join(
                    registration.invitation["blockchain_invitation"],
                    appdata_dir=DidManager.get_blockchain_appdata_path(
                        key_store
                    ),
                )
                blockchain.terminate()
            except JoinFailureError:
                return None
            # logger.info("Loading correspondence...")
            correspondence = GroupDidManager(

                group_key_store=key_store,
                member=self

            )

            self.correspondences.update({correspondence.did: correspondence})
            return correspondence

    def _register_super(
        self, correspondence_id: str, active: bool, invitation: dict | None
    ):
        """Update a correspondence' registration, activating or archiving it.

        Args:
            correspondence_id: the ID of the correspondence to register
            active: whether the correspondence is being activated or archived 
        """
        correspondence_registration = SuperRegistration.create(
            correspondence_id,
            active,
            invitation
        )
        correspondence_registration.sign(
            self.get_control_key()
        )
        self.add_block(
            correspondence_registration.generate_block_content(),
            topics=[WALYTIS_BLOCK_TOPIC,
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
        for block in self.blockchain.get_blocks():
            # ignore blocks that aren't SuperRegistration
            if (
                SuperRegistration.walytis_block_topic
                not in block.topics
            ):
                continue

            # load SuperRegistration
            crsp_registration = SuperRegistration.load_from_block_content(
                self.blockchain.get_block(
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
                key_store_key = self.key_store.get_key(
                    keystore_key_id
                )
                # load the correspondence' KeyStore
                key_store = KeyStore(key_store_path, key_store_key)
                correspondence = GroupDidManager(
                    group_key_store=key_store,
                    member=self
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

    def _on_super_registration_received(self, block: Block):
        if self._terminate_dmws:
            return
        crsp_registration = SuperRegistration.load_from_block_content(
            block.content
        )
        # logger.info(f"DidManagerWithSupers: got registration for {
        #             crsp_registration.correspondence_id}")

        # update lists of active and archived Correspondences
        try:
            if crsp_registration.active:
                if not self.__process_invitations:
                    self.correspondences_to_join.update({
                        crsp_registration.correspondence_id: crsp_registration
                    })
                    # logger.info(
                    #     "DidManagerWithSupers: not yet joining GroupDidManager")
                else:
                    self.join_super(
                        crsp_registration.invitation, register=False)
                    # logger.info(
                    #     "DidManagerWithSupers: added new GroupDidManager")
            else:
                self.archive_super(
                    crsp_registration.correspondence_id, register=False)
                # logger.info("DidManagerWithSupers: archived GroupDidManager")
        except SuperExistsError:
            # logger.info(
            #     "DidManagerWithSupers: we already have this GroupDidManager!")
            pass

    def _on_block_received_dmws(self, block: Block):
        if WALYTIS_BLOCK_TOPIC == block.topics[0]:
            match block.topics[1]:
                case SuperRegistration.walytis_block_topic:
                    self._on_super_registration_received(
                        block
                    )
                case _:
                    logger.warning(
                        "Endra DidManagerWithSupers: Received unhandled block with topics: "
                        f"{block.topics}"
                    )
        else:
            logger.warning(
                "Endra DidManagerWithSupers: Received unhandled block with topics: "
                f"{block.topics}"
            )

    @classmethod
    def create(cls, config_dir: str, key: Key,
        super_type:Type[GroupDidManager|GroupDidManagerWrapper]=GroupDidManager
    ) -> 'DidManagerWithSupers':
        device_keystore_path = os.path.join(config_dir, "device_keystore.json")
        profile_keystore_path = os.path.join(
            config_dir, "profile_keystore.json")

        device_did_keystore = KeyStore(device_keystore_path, key)
        profile_did_keystore = KeyStore(profile_keystore_path, key)
        device_did_manager = DidManager.create(device_did_keystore)
        profile_did_manager = GroupDidManager.create(
            profile_did_keystore, device_did_manager
        )
        profile_did_manager.terminate()

        return cls(
            group_key_store=profile_did_keystore,
            member=device_did_manager,
            super_type=super_type,
        )

    @classmethod
    def load(cls, config_dir: str, key: Key,
        super_type:Type[GroupDidManager|GroupDidManagerWrapper]=GroupDidManager,
    ) -> 'DidManagerWithSupers':
        device_keystore_path = os.path.join(config_dir, "device_keystore.json")
        profile_keystore_path = os.path.join(
            config_dir, "profile_keystore.json")

        device_did_keystore = KeyStore(device_keystore_path, key)
        profile_did_keystore = KeyStore(profile_keystore_path, key)

        return cls(
            group_key_store=profile_did_keystore,
            member=device_did_keystore,
            auto_load_missed_blocks=False,
            super_type=super_type
        )

    @classmethod
    def join(cls,
             invitation: str | dict, config_dir: str, key: Key,
        super_type:Type[GroupDidManager|GroupDidManagerWrapper]=GroupDidManager
             
             ) -> 'DidManagerWithSupers':
        device_keystore_path = os.path.join(config_dir, "device_keystore.json")
        profile_keystore_path = os.path.join(
            config_dir, "profile_keystore.json")
        device_did_keystore = KeyStore(device_keystore_path, key)
        profile_did_keystore = KeyStore(profile_keystore_path, key)
        device_did_manager = DidManager.create(device_did_keystore)

        profile_did_manager = GroupDidManager.join(
            invitation,
            profile_did_keystore,
            device_did_manager
        )
        profile_did_manager.terminate()
        return cls(
            group_key_store=profile_did_keystore,
            member=device_did_manager,
            super_type=super_type,
        )

    def terminate(self):
        if self._terminate_dmws:
            return

        with self.lock:
            self._terminate_dmws = True
            for correspondence in self.correspondences.values():
                correspondence.terminate(terminate_member=False)
        GroupDidManager.terminate(self)

    def delete(self):
        with self.lock:
            self._terminate_dmws = True
            for correspondence in self.correspondences.values():
                correspondence.delete(terminate_member=False)
        GroupDidManager.delete(self)

    def __del__(self):
        self.terminate()
