"""Common exceptions."""


__all__ = [
    'DuplicateClient',
    'DuplicateIPv4Address',
    'InvalidClientName',
    'NetworkExhausted',
    'NoSuchClient',
    'NotInitialized']


class DuplicateClient(Exception):
    """Indicataes that a client with that name
    already exists in the respective PKI.
    """


class DuplicateIPv4Address(Exception):
    """Indicates that the respective IPv4 address is already in use."""


class InvalidClientName(Exception):
    """Indicates an invalid client name."""


class NetworkExhausted(Exception):
    """Indicates that there are no more
    free IPv4 addresses in the network.
    """


class NoSuchClient(Exception):
    """Indicates that the respective client does not exist."""


class NotInitialized(Exception):
    """Indicates that the PKI is not initialized."""
