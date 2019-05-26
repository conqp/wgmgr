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


def stripped(string):
    """Returns a stripped string."""

    return string.strip()


class PKI(ConfigParser):    # pylint: disable = R0901
    """A public key infrastructure."""

    def __init__(self, file: Path):
        """Sets the file path."""
        super().__init__()
        self.optionxform = stripped
        self.file = file
        self.read()

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

    def add_client(self, pubkey: str, address: IPv4Address, name: str = None):
        """Adds a new clients."""
        section = name or pubkey
        self.add_section(section)
        self[section]['PublicKey'] = pubkey
        self[section]['Address'] = str(address)

    def dump_client(self, name):
        """Dumps the client."""
        try:
            client = self[name]
        except KeyError as key_error:
            raise NoSuchClient(str(key_error))

        config = ConfigParser()
        config.optionxform = stripped
        config.add_section('Interface')
        config['Interface']['PrivateKey'] = '<your private key>'
        config['Interface']['Address'] = client['Address']
        config.add_section('Peer')
        config['Peer']['PublicKey'] = self['Server']['PublicKey']

        with suppress(KeyError):    # PSK is optional.
            config['Peer']['PresharedKey'] = self['Server']['PresharedKey']

        config['Peer']['AllowedIPs'] = self['Server']['Network']
        config['Peer']['Endpoint'] = self['Server']['Endpoint']
        return config

    def dump_server(self, device: str, port: int, *, description: str = None):
        """Dumps the server config."""
        config = ConfigParser()
        config.optionxform = stripped
        config.add_section('NetDev')
        config['NetDev']['Name'] = device
        config['NetDev']['Kind'] = 'wireguard'

        if description:
            config['NetDev']['Description'] = description

        config.add_section('WireGuard')
        config['WireGuard']['ListenPort'] = str(port)
        config['WireGuard']['PrivateKey'] = self['Server']['PrivateKey']
        yield config

        for section in self.sections():
            if section == 'Server':
                continue

            config = ConfigParser()
            config.optionxform = stripped
            config.add_section('WireGuardPeer')
            peer = config['WireGuardPeer']
            client = self[section]
            peer['PublicKey'] = client['PublicKey']

            with suppress(KeyError):
                peer['PresharedKey'] = client['PresharedKey']

            peer['AllowedIPs'] = client['Address'] + '/32'
            yield config


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
    client.add_argument('pubkey', help="the client's public key")
    client.add_argument(
        'address', type=IPv4Address, help="the client's IPv4Address")
    client.add_argument('name', nargs='?', help="the client's name")
    # Dumping configuration.
    dump = modes.add_parser('dump')
    types = dump.add_subparsers(dest='type')
    dump_client = types.add_parser(
        'client', help="dumps a client's configuration")
    dump_client.add_argument('name', help="the client's name")
    dump_server = types.add_parser(
        'server', help='dumps the server configuration')
    dump_server.add_argument('device', help='the WireGuard device name')
    dump_server.add_argument('port', type=int, help='the listening port')
    dump_server.add_argument('description', nargs='?', help='a description')
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

            client_config.write(stdout)
        elif args.type == 'server':
            try:
                for config in pki.dump_server(
                        args.device, args.port, description=args.description):
                    config.write(stdout)
            except KeyError as key_error:
                LOGGER.error('PKI not configured.')
                LOGGER.error('Missing key: "%s".', key_error)
                exit(2)

    exit(0)
