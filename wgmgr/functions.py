"""Common functions."""

from base64 import b64decode
from io import StringIO
from os import linesep
from sys import stdout


__all__ = ['config_to_string', 'dump', 'stripped', 'wgkey', 'write']


def config_to_string(config):
    """Converts the configuration parser into a string."""

    stringio = StringIO()
    config.write(stringio)
    stringio.seek(0)
    return stringio.read()


def dump(text, path=None):
    """Dumps a text to a file."""

    if path is None:
        print(text, flush=True)
    else:
        with path.open('w') as file:
            file.write(text)
            file.write(linesep)


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
        config.write(stdout)
        print(flush=True)
    else:
        with path.open('w') as file:
            config.write(file)
            file.write(linesep)
