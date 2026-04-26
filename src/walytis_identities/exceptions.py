"""Custom exceptions used by this module."""


class NotValidDidBlockchainError(Exception):
    """When a Walytis blockchain doesn't contain valid DID-Manager blocks."""


class NotInitialisedError(Exception):
    """When a method fails because its object is uninitialised."""
