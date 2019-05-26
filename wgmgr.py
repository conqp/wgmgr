"""Python bindings for WireGuard."""

from argparse import ArgumentParser
from configparser import DuplicateSectionError, ConfigParser
from contextlib import suppress
from ipaddress import IPv4Address, IPv4Network
from logging import getLogger
from pathlib import Path
from sys import stdout

from wgtools import keypair, genpsk


__all__ = ['PKI']


CONFIG_FILE = 'pki.conf'
LOGGER = getLogger('wgmgr')


class NoSuchClient(Exception):
    """Indicates that the respective client does not exist."""

    def __init__(self, client):
        """Sets the client."""
        super().__init__(client)
        self.client = client


class PKI(ConfigParser):    # pylint: disable = R0901
    """A public key infrastructure."""

    def __init__(self, file: Path):
        """Sets the file path."""
        super().__init__()
        self.file = file

    def read(self, filenames=None, encoding=None):
        """Reads from the config file."""
        if filenames is None:
            filenames = self.file

        return super().read(filenames, encoding=encoding)

    def write(self, fp=None, **kwargs):     # pylint: disable=W0221
        """Writes to the config file."""
        if fp is None:
            with self.file.open('w') as file:
                return super().write(file)

        return super().write(fp, **kwargs)

    def init(self, network: IPv4Network, address: IPv4Address, endpoint: str,
             *, psk: bool = False):
        """Initializes the PKI."""
        self.clear()
        self.add_section('Server')
        self['Server']['Network'] = str(network)
        self['Server']['Address'] = str(address)
        self['Server']['Endpoint'] = endpoint
        self['Server']['PublicKey'], self['Server']['PrivateKey'] = keypair()

        if psk:
            self['Server']['PresharedKey'] = genpsk()

        return True

    def add_client(self, pubkey: str, address: IPv4Address, name: str = None):
        """Adds a new clients."""
        section = name or pubkey
        self.add_section(section)
        self[section]['PublicKey'] = pubkey
        self[section]['Address'] = address

    def dump_client(self, name):
        """Dumps the client."""
        try:
            client = self[name]
        except KeyError as key_error:
            raise NoSuchClient(str(key_error))

        config = ConfigParser()
        config.add_section('Interface')
        config['Interface']['PrivateKey'] = '<your private key>'
        config['Interface']['Address'] = client['Address']
        config.add_section('Peer')
        server = self['Server']
        config['Peer']['PublicKey'] = server['PublicKey']

        with suppress(KeyError):    # PSK is optional.
            config['Peer']['PresharedKey'] = server['PresharedKey']

        config['Peer']['AllowedIPs'] = server['Network']
        config['Peer']['Endpoint'] = server['Endpoint']
        return config


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
    subparsers = parser.add_subparsers(dest='mode')
    init = subparsers.add_parser('init', help='initializes the PKI')
    init.add_argument('network', type=IPv4Network, help='the IPv4 network')
    init.add_argument(
        'address', type=IPv4Address, help="the server's IPv4 address")
    init.add_argument('endpoint', help="the server's IPv4 address")
    init.add_argument(
        '-p', '--psk', action='store_true',
        help='generate and add a pre-shared key')
    client = subparsers.add_parser('client', help='add a client')
    client.add_argument('pubkey', help="the client's public key")
    client.add_argument(
        'address', type=IPv4Address, help="the client's IPv4Address")
    client.add_argument('name', nargs='?', help="the client's name")
    dump = subparsers.add_parser('dump', help="dumps a client's configuration")
    dump.add_argument('name', help="the client's name")
    return parser.parse_args()


def main():
    """Runs the main program."""

    args = get_args()
    pki = PKI(args.config)

    if args.mode == 'init':
        if args.config.is_file() and not args.force:
            LOGGER.error('PKI already exists.')
            exit(1)

        pki.init(args.network, args.address, args.endpoint, psk=args.psk)
    elif args.mode == 'client':
        try:
            pki.add_client(args.pubkey, args.address, name=args.name)
        except DuplicateSectionError as dse:
            LOGGER.error('A client named "%s" already exists.', dse.section)
            exit(1)
    elif args.mode == 'dump':
        try:
            client_config = pki.dump_client(args.client)
        except NoSuchClient as nsc:
            LOGGER.error('Client "%s" does not exist.', nsc.client)
            exit(1)
        except KeyError as key_error:
            LOGGER.error('PKI not configured. Missing key: "%s".', key_error)
            exit(2)

        client_config.write(stdout)

    pki.write()
    exit(0)
