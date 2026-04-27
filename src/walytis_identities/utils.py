"""Various utility functions."""

import secrets
import string
from abc import ABCMeta
from base64 import urlsafe_b64decode, urlsafe_b64encode

import rfc3987  # type: ignore
from brenthy_tools_beta.utils import (  # type: ignore # noqa
    string_to_time,
    time_to_string,
)
from docstring_inheritance._internal import (  # type: ignore
    GoogleDocstringInheritanceMeta,
)

from .log import logger_walid as logger  # noqa

# GroupDidManager Settings
NUM_NEW_CONTROL_KEYS = 1
NUM_ACTIVE_CONTROL_KEYS = NUM_NEW_CONTROL_KEYS * 1


def is_valid_uri(uri: str) -> bool:
    """Check if the given URI is valid according to RFC3987."""
    try:
        # Use the parse function to validate the URI
        _ = rfc3987.parse(uri, rule="URI")
        return True
    except ValueError:
        return False


def validate_did_doc(did_doc: dict) -> None:
    """Ensure the given DID-Document fulfills the specifications."""
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
    """Convert bytes to string with Base64.

    Args:
        data: the data to convert
        variable_name: for error message
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
    """Convert string to bytes with Base64.

    Args:
        data: the data to convert
        variable_name: for error message
    """
    if isinstance(data, str):
        # first perform base 64 encoding, then convert to string
        return urlsafe_b64decode(data)
    raise ValueError(
        (f"{variable_name} must be of type str, not {type(data)}")
    )


def generate_random_string(num_chars: int) -> str:
    """Generate a random string of the given length."""
    # Define the alphabet you want to use
    alphabet = string.ascii_letters + string.digits + string.punctuation

    # Generate a 200-character secure random string
    secure_string = "".join(secrets.choice(alphabet) for _ in range(num_chars))
    return secure_string


class AbstractClassMeta(GoogleDocstringInheritanceMeta, ABCMeta):
    """Metaclass for abstract classes with docstring inheritance."""

    pass
