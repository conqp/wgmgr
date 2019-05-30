"""Common functions."""

from base64 import b64decode
from io import StringIO
from sys import stdout

from wgmgr.exceptions import NoSuchClient
from wgmgr.orm import Client


__all__ = ['config_to_string', 'get_client', 'stripped', 'wgkey', 'write']


def config_to_string(config):
    """Converts the configuration parser into a string."""

    stringio = StringIO()
    config.write(stringio)
    stringio.seek(0)
    return stringio.read()


def get_client(pki, name):
    """Returns the respective client."""

    try:
        return Client.get((Client.pki == pki) & (Client.name == name))
    except Client.DoesNotExist:
        raise NoSuchClient()


def stripped(string):
    """Returns a stripped string."""

    return string.strip()


def wgkey(string):
    """Checks whether a string is a valid WireGuard key."""

    if len(string) != 44:
        raise ValueError('Invalid length for WireGuard key.')

    b64decode(string)   # Check for correct base64 encodeing.
    return string


def write(config, path):
    """Writes the config parser to the respective file."""

    if path is None:
        return config.write(stdout)

    with path.open('w') as file:
        return config.write(file)
