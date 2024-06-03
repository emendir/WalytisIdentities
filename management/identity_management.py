from identity.identity import PersonIdentityAccess, DeviceIdentityAccess
from multi_crypt import Crypt


def create_person_identity(config_dir: str, crypt: Crypt) -> PersonIdentityAccess:
    return PersonIdentityAccess.create(config_dir, crypt)


def update_identity():
    pass


def delete_identity():
    pass
