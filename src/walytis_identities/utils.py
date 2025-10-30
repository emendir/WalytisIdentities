import secrets
import string
from base64 import urlsafe_b64decode, urlsafe_b64encode

import rfc3987

from .log import logger_walid as logger  # noqa
from brenthy_tools_beta.utils import time_to_string, string_to_time  # noqa

# GroupDidManager Settings
NUM_NEW_CONTROL_KEYS = 1
NUM_ACTIVE_CONTROL_KEYS = NUM_NEW_CONTROL_KEYS * 1


def is_valid_uri(uri):
    try:
        # Use the parse function to validate the URI
        result = rfc3987.parse(uri, rule="URI")
        return True
    except ValueError:
        return False


def validate_did_doc(did_doc: dict):
    """Ensures the passed dictionary fulfils the specifications of a DID
    document, raisng an expetion if not
    """
    try:
        rfc3987.parse(did_doc["id"], rule="URI")
        for key in did_doc.get("verificationMethod", []):
            rfc3987.parse(f"{did_doc['id']}{key['id']}", rule="URI")
        for service in did_doc.get("service", []):
            rfc3987.parse(f"{did_doc['id']}{service['id']}", rule="URI")
    except Exception:
        raise ValueError(
            "One of this Identy's fields has an incompatible value."
        )


def bytes_to_string(
    data: bytes | bytearray, variable_name: str = "Value"
) -> str:
    """Convert the input data from bytes or bytearray to string if it isn't
    already, raising an error if it has an incompatible type.

    Parameters:
        data (bytearay): the data to convert
        variable_name (str): for error message
    """
    if isinstance(data, (bytearray, bytes)):
        # first perform base 64 encoding, then convert to string
        return urlsafe_b64encode(data).decode()
    raise ValueError(
        (
            f"{variable_name} must be of type bytearray or bytes, not "
            f"{type(data)}"
        )
    )


def bytes_from_string(data: str, variable_name: str = "Value") -> bytes:
    """Reverse of bytes_to_string, converting such encoded strings back to
    bytes (if they the data isn't already),
     raising an error if it has an incompatible type.

    Parameters:
        data (str): the data to convert
        variable_name (str): for error message
    """
    if isinstance(data, str):
        # first perform base 64 encoding, then convert to string
        return urlsafe_b64decode(data)
    raise ValueError(
        (f"{variable_name} must be of type str, not {type(data)}")
    )


def generate_random_string(num_chars: int):
    # Define the alphabet you want to use
    alphabet = string.ascii_letters + string.digits + string.punctuation

    # Generate a 200-character secure random string
    secure_string = "".join(secrets.choice(alphabet) for _ in range(num_chars))
    return secure_string
