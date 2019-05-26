"""WireGuard manager CLI parser."""

from argparse import ArgumentParser
from configparser import DuplicateSectionError
from ipaddress import IPv4Address, IPv4Network
from logging import getLogger
from pathlib import Path

from wgmgr.exceptions import NoSuchClient
from wgmgr.functions import wgkey, write
from wgmgr.pki import PKI


__all__ = ['main']


CONFIG_FILE = 'pki.conf'
LOGGER = getLogger('wgmgr')


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
    # PKI Initialization.
    init = modes.add_parser('init', help='initializes the PKI')
    init.add_argument('network', type=IPv4Network, help='the IPv4 network')
    init.add_argument(
        'address', type=IPv4Address, help="the server's IPv4 address")
    init.add_argument('endpoint', help="the server's IPv4 address")
    init.add_argument(
        '-p', '--psk', action='store_true',
        help='generate and add a pre-shared key')
    # Adding a client.
    client = modes.add_parser('client', help='add a client')
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
    dump_client.add_argument('name', help="the client's name")
    dump_server = types.add_parser(
        'server', help='dumps the server configuration')
    dump_server.add_argument('device', help='the WireGuard device name')
    dump_server.add_argument('port', type=int, help='the listening port')
    dump_server.add_argument('description', nargs='?', help='a description')
    # Listing of clients.
    modes.add_parser('list', help='list clients')
    return parser.parse_args()


def main():
    """Runs the main program."""

    args = get_args()
    pki = PKI(args.config_file)

    if args.mode == 'init':
        if args.config_file.is_file() and not args.force:
            LOGGER.error('PKI already exists.')
            exit(1)

        pki.init(args.network, args.address, args.endpoint, psk=args.psk)
        pki.write()
    elif args.mode == 'client':
        try:
            pki.add_client(args.pubkey, args.address, name=args.name)
        except DuplicateSectionError as dse:
            LOGGER.error('A client named "%s" already exists.', dse.section)
            exit(1)

        pki.write()
    elif args.mode == 'dump':
        if args.type == 'client':
            try:
                client_config = pki.dump_client(args.name)
            except NoSuchClient as nsc:
                LOGGER.error('Client "%s" does not exist.', nsc.client)
                exit(1)
            except KeyError as key_error:
                LOGGER.error('PKI not configured.')
                LOGGER.error('Missing key: "%s".', key_error)
                exit(2)

            write(client_config, path=args.out_file)
        elif args.type == 'server':
            try:
                configs = pki.dump_server(
                    args.device, args.port, description=args.description)
            except KeyError as key_error:
                LOGGER.error('PKI not configured.')
                LOGGER.error('Missing key: "%s".', key_error)
                exit(2)

            write(*configs, path=args.out_file)
    elif args.mode == 'list':
        for client in pki.list_clients():
            print(*client, flush=True)

    exit(0)
