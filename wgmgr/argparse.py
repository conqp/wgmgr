"""CLI arguments parsing."""

from argparse import ArgumentParser, Namespace
from ipaddress import ip_address, ip_network
from pathlib import Path

from wgmgr.functions import wgkey


__all__ = ['get_args']


CONFIG_FILE = 'pki.conf'


def _add_initpki_parser(subparsers):
    """Adds the addpki parser."""

    add = subparsers.add_parser('init', help='initializes the PKI')
    add.add_argument('name', help='the name of the network device')
    add.add_argument('description', help='a description of the network')
    add.add_argument('network', type=ip_network, help='the IP network')
    add.add_argument(
        'address', type=ip_address, help="the server's IP address")
    add.add_argument('endpoint', help="the server's IP address and port")
    add.add_argument(
        '-p', '--psk', action='store_true',
        help='generate and add a pre-shared key')


def _add_add_client_parser(subparsers):
    """Adds a subparser to add a client."""

    add_client = subparsers.add_parser('add', help='add a client')
    add_client.add_argument(
        'pubkey', type=wgkey, help="the client's public key")
    add_client.add_argument(
        'address', nargs='?', type=ip_address, help="the client's IPAddress")
    add_client.add_argument('-n', '--name', help='a descriptive name')


def _add_modify_client_parser(subparsers):
    """Adds a subparser to modify a client."""

    add_client = subparsers.add_parser('modify', help='modify a client')
    add_client.add_argument(
        '-p', '--pubkey', type=wgkey, help="the client's public key")
    add_client.add_argument(
        '-a', '--address', type=ip_address, help="the client's IP address")
    add_client.add_argument('name', nargs='?', help="the client's name")


def _add_remove_client_parser(subparsers):
    """Adds a subparser to remove a client."""

    add_client = subparsers.add_parser('remove', help='remove a client')
    add_client.add_argument('name', help="the client's name")


def _add_list_clients_parser(subparsers):
    """Adds a parser to list clients."""

    subparsers.add_parser('list', help='list clients')


def _add_dump_client_parser(subparsers):
    """Adds a client to dump a client."""

    dump_client = subparsers.add_parser(
        'dump', help="dumps a client's configuration")
    dump_client.add_argument(
        '-o', '--out-file', type=Path, help='the output file')
    dump_client.add_argument('name', help="the client's name")


def _add_client_parser(subparsers):
    """Adds a subparser to handle clients."""

    client = subparsers.add_parser('client', help='handle clients')
    action = client.add_subparsers(dest='action')
    _add_add_client_parser(action)
    _add_modify_client_parser(action)
    _add_remove_client_parser(action)
    _add_list_clients_parser(action)
    _add_dump_client_parser(action)


def _add_dump_server_parser(subparser):
    """Adds a parser to parse arguments to dump server or client."""

    dump_server = subparser.add_parser(
        'dump', help='dumps the server configuration')
    dump_server.add_argument(
        '-o', '--out-file', type=Path, help='the output file')


def _add_server_parser(subparsers):
    """Adds a subparser to handle the server."""

    server = subparsers.add_parser('server', help='handle servers')
    action = server.add_subparsers(dest='action')
    _add_dump_server_parser(action)


def get_args() -> Namespace:
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
    _add_initpki_parser(modes)
    _add_client_parser(modes)
    _add_server_parser(modes)
    return parser.parse_args()
