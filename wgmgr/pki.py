"""PKI management."""

from configparser import ConfigParser
from contextlib import suppress
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from wgtools import genpsk, keypair

from wgmgr.exceptions import NoSuchClient
from wgmgr.functions import stripped


__al__ = ['PKI']


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

    def dump_netdev(self, device: str, port: int, *, description: str = None):
        """Dumps a systemd.netdev configuration."""
        config = ConfigParser()
        config.optionxform = stripped
        config.add_section('NetDev')
        config['NetDev']['Name'] = device
        config['NetDev']['Kind'] = 'wireguard'

        if description:
            config['NetDev']['Description'] = description

        config.add_section('WireGuard')
        config['WireGuard']['ListenPort'] = str(port)
        server = self['Server']
        config['WireGuard']['PrivateKey'] = server['PrivateKey']
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
                peer['PresharedKey'] = server['PresharedKey']

            peer['AllowedIPs'] = client['Address'] + '/32'
            yield config

    def dump_server(self, device: str, port: int, *, description: str = None):
        """Dumps the server config."""
        return list(self.dump_netdev(device, port, description=description))

    def list_clients(self):
        """Lists clients."""
        for section in self.sections():
            if section == 'Server':
                continue

            client = self[section]
            yield (section, client['Address'], client['PublicKey'])
