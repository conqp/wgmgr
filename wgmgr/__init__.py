"""Python bindings for WireGuard."""

from wgmgr.cli import main
from wgmgr.exceptions import DuplicateClient
from wgmgr.exceptions import InvalidClientName
from wgmgr.exceptions import NetworkExhausted
from wgmgr.exceptions import NoSuchClient
from wgmgr.exceptions import NotInitialized
from wgmgr.pki import PKI


__all__ = [
    'DuplicateClient',
    'InvalidClientName',
    'NetworkExhausted',
    'NoSuchClient',
    'NotInitialized',
    'main',
    'PKI']
