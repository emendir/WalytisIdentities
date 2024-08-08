from decorate_all import decorate_all_functions
from strict_typing import strictly_typed
from walidentity.identity_access import IdentityAccess
from multi_crypt import Crypt


def create_person_identity(config_dir: str, crypt: Crypt) -> IdentityAccess:
    return IdentityAccess.create(config_dir, crypt)


def update_identity():
    pass


def delete_identity():
    pass


decorate_all_functions(strictly_typed, __name__)
