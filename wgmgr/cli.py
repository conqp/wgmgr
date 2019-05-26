"""WireGuard manager CLI parser."""

from argparse import ArgumentParser
from configparser import DuplicateSectionError
from ipaddress import IPv4Address, IPv4Network
from logging import getLogger
from pathlib import Path

from wgmgr.functions import wgkey, write
from wgmgr.orm import Client
from wgmgr.pki import PKI


__all__ = ['main']


CONFIG_FILE = 'pki.conf'
LOGGER = getLogger('wgmgr')


def list_clients(pkis):
    """Lists the client of the respective PKI."""

    clients = Client.select().where(Client.pki << pkis) if pkis else Client

    for client in clients:
        print(client, flush=True)


def get_args():
    """Parses the command line arguments."""

    parser = ArgumentParser()
    parser.add_argument(
        '-c', '--config-file', type=Path,
        default=Path.cwd().joinpath(CONFIG_FILE),
        help='the config file to use')
    parser.add_argument(
        '-f', '--force', action='store_true',
        help='force override of existing PKI')
    modes = parser.add_subparsers(dest='mode')
    # Add a PKI.
    add = modes.add_parser('addpki', help='adds a new PKI')
    add.add_argument('name', help="the PKI's name")
    add.add_argument('network', type=IPv4Network, help='the IPv4 network')
    add.add_argument(
        'address', type=IPv4Address, help="the server's IPv4 address")
    add.add_argument('endpoint', help="the server's IPv4 address")
    add.add_argument(
        '-p', '--psk', action='store_true',
        help='generate and add a pre-shared key')
    # Adding a client.
    client = modes.add_parser('client', help='add a client')
    client.add_argument('pki', help='the PKI to add the client to')
    client.add_argument('pubkey', type=wgkey, help="the client's public key")
    client.add_argument(
        'address', type=IPv4Address, help="the client's IPv4Address")
    client.add_argument('name', nargs='?', help="the client's name")
    # Dumping configuration.
    dump = modes.add_parser('dump')
    dump.add_argument('-o', '--out-file', type=Path, help='the output file')
    types = dump.add_subparsers(dest='type')
    dump_client = types.add_parser(
        'client', help="dumps a client's configuration")
    dump_client.add_argument('pki', help='the PKI to dump the client from')
    dump_client.add_argument('name', help="the client's name")
    dump_server = types.add_parser(
        'server', help='dumps the server configuration')
    dump_server.add_argument('pki', help='the PKI to dump the server from')
    dump_server.add_argument('device', help='the WireGuard device name')
    dump_server.add_argument('port', type=int, help='the listening port')
    dump_server.add_argument('description', nargs='?', help='a description')
    # Listing of clients.
    lst = modes.add_parser('list', help='list clients')
    lst.add_argument('pki', nargs='*', help='the PKI to list')
    return parser.parse_args()


def main():
    """Runs the main program."""

    args = get_args()
    pki = PKI()
    pki.read(args.config_file)

    if args.mode == 'addpki':
        pki.add_pki(
            args.name, args.network, args.address, args.endpoint, psk=args.psk)
        write(pki, args.config_file)
    elif args.mode == 'client':
        try:
            pki.add_client(args.pki, args.name, args.pubkey, args.address)
        except DuplicateSectionError as dse:
            LOGGER.error('A client named "%s" already exists.', dse.section)
            exit(1)

        write(pki, args.config_file)
    elif args.mode == 'dump':
        if args.type == 'client':
            try:
                text = pki.dump_client(args.pki, args.name)
            except KeyError as key_error:
                LOGGER.error('PKI not configured.')
                LOGGER.error('Missing key: "%s".', key_error)
                exit(2)

            print(text, flush=True)
        elif args.type == 'server':
            try:
                text = pki.dump_netdev(
                    args.pki, args.device, args.port,
                    description=args.description)
            except KeyError as key_error:
                LOGGER.error('PKI not configured.')
                LOGGER.error('Missing key: "%s".', key_error)
                exit(2)

            print(text, flush=True)
    elif args.mode == 'list':
        list_clients(args.pki)

    exit(0)
