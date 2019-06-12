"""WireGuard manager CLI parser."""

from configparser import DuplicateSectionError
from logging import getLogger

from wgmgr.argparse import get_args
from wgmgr.exceptions import DuplicateClient
from wgmgr.exceptions import InvalidClientName
from wgmgr.exceptions import NoSuchClient
from wgmgr.exceptions import NotInitialized
from wgmgr.functions import dump, write
from wgmgr.pki import PKI


__all__ = ['main']


LOGGER = getLogger('wgmgr')


def _add_client(args, pki):
    """Adds a new client."""

    try:
        pki.add_client(args.pubkey, args.address, name=args.name)
    except InvalidClientName:
        LOGGER.error('Invalid client name: "%s".', args.name)
        exit(1)
    except DuplicateClient:
        LOGGER.error('A client named "%s" already exists.', args.name)
        exit(2)

    write(pki, args.config_file)


def _modify_client(args, pki):
    """Modifies a client."""

    try:
        pki.modify_client(
            args.name, pubkey=args.pubkey, address=args.address)
    except InvalidClientName:
        LOGGER.error('Invalid client name: "%s".', args.name)
        exit(1)
    except NoSuchClient:
        LOGGER.error('No such client: "%s".', args.name)
        exit(2)

    write(pki, args.config_file)


def _remove_client(args, pki):
    """Removes a client."""

    try:
        pki.remove_client(args.pki, args.name)
    except InvalidClientName:
        LOGGER.error('Invalid client name: "%s".', args.name)
        exit(1)
    except NoSuchClient:
        LOGGER.error('No such client: "%s".', args.name)
        exit(2)

    write(pki, args.config_file)


def _dump_client(args, pki):
    """Dumps a client."""

    try:
        text = pki.dump_client(args.name)
    except InvalidClientName:
        LOGGER.error('Invalid client name: "%s".', args.name)
        exit(1)
    except NoSuchClient:
        LOGGER.error('No such client: "%s".', args.name)
        exit(2)
    except NotInitialized:
        LOGGER.error('PKI not initialized.')
        exit(3)

    dump(text, path=args.out_file)


def _handle_client(args, pki):
    """Handles actions on clients."""

    if args.action == 'add':
        _add_client(args, pki)
    elif args.action == 'modify':
        _modify_client(args, pki)
    elif args.action == 'remove':
        _remove_client(args, pki)
    elif args.action == 'list':
        print(pki.list_clients(), flush=True)
    elif args.action == 'dump':
        _dump_client(args, pki)


def _handle_server(args, pki):
    """Handles actions on servers."""

    if args.action == 'dump':
        try:
            text = pki.dump_netdev()
        except NotInitialized:
            LOGGER.error('PKI not initialized.')
            exit(2)

        dump(text, path=args.out_file)


def main():
    """Runs the main program."""

    args = get_args()
    pki = PKI()
    pki.read(args.config_file)

    if args.mode == 'init':
        try:
            pki.init(
                args.name, args.description, args.network, args.address,
                args.endpoint, psk=args.psk)
        except DuplicateSectionError:
            LOGGER.error('PKI is already initilized.')
            exit(1)

        write(pki, args.config_file)
    elif args.mode == 'client':
        _handle_client(args, pki)
    elif args.mode == 'server':
        _handle_server(args, pki)

    exit(0)
