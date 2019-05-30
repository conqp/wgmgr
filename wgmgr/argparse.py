"""CLI arguments parsing."""

from argparse import ArgumentParser
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from wgmgr.functions import wgkey


__all__ = ['get_args']


CONFIG_FILE = 'pki.conf'


def _add_addpki_parser(subparsers):
    """Adds the addpki parser."""

    add = subparsers.add_parser('addpki', help='adds a new PKI')
    add.add_argument('name', help="the PKI's name")
    add.add_argument('network', type=IPv4Network, help='the IPv4 network')
    add.add_argument(
        'address', type=IPv4Address, help="the server's IPv4 address")
    add.add_argument('endpoint', help="the server's IPv4 address")
    add.add_argument(
        '-p', '--psk', action='store_true',
        help='generate and add a pre-shared key')


def _add_add_client_parser(subparsers):
    """Adds a subparser to add a client."""

    add_client = subparsers.add_parser('add', help='add a client')
    add_client.add_argument('pki', help='the PKI to add the client to')
    add_client.add_argument('name', help="the client's name")
    add_client.add_argument(
        'pubkey', type=wgkey, help="the client's public key")
    add_client.add_argument(
        'address', type=IPv4Address, help="the client's IPv4Address")


def _add_change_client_parser(subparsers):
    """Adds a subparser to change a client."""

    add_client = subparsers.add_parser('change', help='change a client')
    add_client.add_argument('pki', help='the PKI to add the client to')
    add_client.add_argument('name', help="the client's name")
    add_client.add_argument(
        'pubkey', type=wgkey, help="the client's public key")
    add_client.add_argument(
        'address', type=IPv4Address, help="the client's IPv4Address")


def _add_delete_client_parser(subparsers):
    """Adds a subparser to delete a client."""

    add_client = subparsers.add_parser('delete', help='delete a client')
    add_client.add_argument('pki', help='the PKI to add the client to')
    add_client.add_argument('name', help="the client's name")


def _add_list_clients_parser(subparsers):
    """Adds a parser to list clients."""

    list_clients = subparsers.add_parser('list', help='list clients')
    list_clients.add_argument('pki', nargs='*', help='the PKI to list')


def _add_dump_client_parser(subparsers):
    """Adds a client to dump a client."""

    dump_client = subparsers.add_parser(
        'dump', help="dumps a client's configuration")
    dump_client.add_argument(
        '-o', '--out-file', type=Path, help='the output file')
    dump_client.add_argument('pki', help='the PKI to dump the client from')
    dump_client.add_argument('name', help="the client's name")


def _add_client_parser(subparsers):
    """Adds a subparser to handle clients."""

    client = subparsers.add_parser('client', help='handle clients')
    action = client.add_subparsers(dest='action')
    _add_add_client_parser(action)
    _add_change_client_parser(action)
    _add_delete_client_parser(action)
    _add_list_clients_parser(action)
    _add_dump_client_parser(action)


def _add_dump_server_parser(subparser):
    """Adds a parser to parse arguments to dump server or client."""

    dump_server = subparser.add_parser(
        'dump', help='dumps the server configuration')
    dump_server.add_argument(
        '-o', '--out-file', type=Path, help='the output file')
    dump_server.add_argument('pki', help='the PKI to dump the server from')
    dump_server.add_argument('device', help='the WireGuard device name')
    dump_server.add_argument('port', type=int, help='the listening port')
    dump_server.add_argument('description', nargs='?', help='a description')


def _add_server_parser(subparsers):
    """Adds a subparser to handle the server."""

    server = subparsers.add_parser('server', help='handle servers')
    action = server.add_subparsers(dest='action')
    _add_dump_server_parser(action)


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
    _add_addpki_parser(modes)
    _add_client_parser(modes)
    _add_server_parser(modes)
    return parser.parse_args()
