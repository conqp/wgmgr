"""Common exceptions."""


__all__ = ['DuplicateClient', 'NoSuchClient']


class DuplicateClient(Exception):
    """Indicataes that a client with that name
    already exists in the respective PKI.
    """


class NoSuchClient(Exception):
    """Indicates that the respective client does not exist."""
