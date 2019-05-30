"""WireGuard manager CLI parser."""

from logging import getLogger

from wgmgr.argparse import get_args
from wgmgr.exceptions import DuplicateClient, NoSuchClient
from wgmgr.functions import write
from wgmgr.orm import Client
from wgmgr.pki import add_client, change_client, delete_client, PKIManager


__all__ = ['main']


LOGGER = getLogger('wgmgr')


def _handle_client(args, pkimgr):
    """Handles actions on clients."""

    if args.action == 'add':
        try:
            add_client(args.pki, args.name, args.pubkey, args.address)
        except DuplicateClient:
            LOGGER.error('A client named "%s" already exists.', args.name)
            exit(1)

        write(pkimgr, args.config_file)
    elif args.action == 'change':
        try:
            change_client(
                args.pki, args.name, pubkey=args.pubkey, address=args.address)
        except NoSuchClient:
            LOGGER.error('No such client: "%s".', args.name)
            exit(1)
    elif args.action == 'delete':
        try:
            delete_client(args.pki, args.name)
        except NoSuchClient:
            LOGGER.error('No such client: "%s".', args.name)
            exit(1)
    elif args.action == 'list':
        if args.pki:
            clients = Client.select().where(Client.pki << args.pki)
        else:
            clients = Client

        for client in clients:
            print(client, flush=True)
    elif args.action == 'dump':
        try:
            text = pkimgr.dump_client(args.pki, args.name)
        except KeyError as key_error:
            LOGGER.error('PKI not configured.')
            LOGGER.error('Missing key: "%s".', key_error)
            exit(2)

        print(text, flush=True)


def _handle_server(args, pkimgr):
    """Handles actions on servers."""

    if args.action == 'dump':
        try:
            text = pkimgr.dump_netdev(
                args.pki, args.device, args.port,
                description=args.description)
        except KeyError as key_error:
            LOGGER.error('PKI not configured.')
            LOGGER.error('Missing key: "%s".', key_error)
            exit(2)

        print(text, flush=True)


def main():
    """Runs the main program."""

    args = get_args()
    pkimgr = PKIManager()
    pkimgr.read(args.config_file)

    if args.mode == 'addpki':
        pkimgr.add_pki(
            args.name, args.network, args.address, args.endpoint, psk=args.psk)
        write(pkimgr, args.config_file)
    elif args.mode == 'client':
        _handle_client(args, pkimgr)
    elif args.mode == 'server':
        _handle_server(args, pkimgr)

    exit(0)
