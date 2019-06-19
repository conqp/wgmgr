"""PKI management."""

from configparser import DuplicateSectionError, NoSectionError, ConfigParser
from contextlib import suppress
from ipaddress import IPv4Address, IPv4Network
from os import linesep

from wgtools import genpsk, keypair

from wgmgr.exceptions import DuplicateClient
from wgmgr.exceptions import InvalidClientName
from wgmgr.exceptions import NetworkExhausted
from wgmgr.exceptions import NoSuchClient
from wgmgr.exceptions import NotInitialized
from wgmgr.functions import config_to_string, stripped


__all__ = ['PKI']


SERVER = 'Server'


class PKI(ConfigParser):    # pylint: disable = R0901
    """A public key infrastructure."""

    def __init__(self, *args, **kwargs):
        """Sets the file path."""
        super().__init__(*args, **kwargs)
        self.optionxform = stripped

    @property
    def network(self):
        """Returns the IPv4 network."""
        return IPv4Network(self[SERVER]['Network'])

    @property
    def addresses(self):
        """Yields issued IPv4 addresses."""
        for section in self.sections():
            with suppress(KeyError):
                yield IPv4Address(self[section]['Address'])

    @property
    def port(self):
        """Returns the server's port."""
        _, port = self[SERVER]['Endpoint'].rsplit(':', maxsplit=1)
        return int(port)

    @property
    def clients(self):
        """Yields all client sections."""
        for section in self.sections():
            if section == SERVER:
                continue

            yield (section, self[section])

    def init(self, name, description, network, address, endpoint, psk=False):
        """Initializes the PKI."""
        self.add_section(SERVER)
        self[SERVER]['Name'] = str(name)
        self[SERVER]['Description'] = str(description)
        self[SERVER]['Network'] = str(network)
        self[SERVER]['Address'] = str(address)
        self[SERVER]['Endpoint'] = str(endpoint)
        self[SERVER]['PublicKey'], self[SERVER]['PrivateKey'] = keypair()

        if psk:
            self[SERVER]['PresharedKey'] = genpsk()

    def get_address(self):
        """Returns a free address."""
        addresses = {address for address in self.addresses}

        for count, address in enumerate(self.network, start=1):
            if count > 1 and address not in addresses:
                return address

        raise NetworkExhausted()

    def add_client(self, pubkey, address=None, name=None):
        """Adds a client."""
        section = str(pubkey) if name is None else str(name)

        if section == SERVER:
            raise InvalidClientName()

        try:
            self.add_section(section)
        except DuplicateSectionError:
            raise DuplicateClient(section)

        client = self[section]
        client['PublicKey'] = str(pubkey)
        address = self.get_address() if address is None else address
        client['Address'] = str(address)

    def modify_client(self, name, pubkey=None, address=None):
        """Modifies a client."""
        if name == SERVER:
            raise InvalidClientName()

        try:
            client = self[name]
        except NoSectionError:
            raise NoSuchClient(name)

        if pubkey is not None:
            client['PublicKey'] = str(pubkey)

        if address is not None:
            client['Address'] = str(address)

    def remove_client(self, name):
        """Removes the respective client."""
        if name == SERVER:
            raise InvalidClientName()

        return self.remove_section(name)

    def list_clients(self):
        """Lists all clients."""
        clients = ConfigParser()
        clients.optionxform = stripped

        for name, section in self.clients:
            clients.add_section(name)
            client = clients[name]
            client['PublicKey'] = section['PublicKey']
            client['Address'] = section['Address']

        return config_to_string(clients).strip(linesep)

    def dump_client(self, name):
        """Dumps the client."""
        if name == SERVER:
            raise InvalidClientName()

        try:
            server = self['Server']
        except NoSectionError:
            raise NotInitialized()

        try:
            client = self[name]
        except NoSectionError:
            raise NoSuchClient(name)

        config = ConfigParser()
        config.optionxform = stripped
        config.add_section('Interface')
        config['Interface']['PrivateKey'] = '<your private key>'
        config['Interface']['Address'] = client['Address']
        config.add_section('Peer')
        config['Peer']['PublicKey'] = server['PublicKey']

        with suppress(KeyError):    # PSK is optional.
            config['Peer']['PresharedKey'] = server['PresharedKey']

        config['Peer']['AllowedIPs'] = server['Network']
        config['Peer']['Endpoint'] = server['Endpoint']
        return config_to_string(config).strip(linesep)

    def dump_netdev(self):
        """Dumps a systemd.netdev configuration."""
        try:
            server = self[SERVER]
        except NoSectionError:
            raise NotInitialized()

        config = ConfigParser()
        config.optionxform = stripped
        config.add_section('NetDev')
        config['NetDev']['Name'] = server['Name']
        config['NetDev']['Kind'] = 'wireguard'
        config['NetDev']['Description'] = server['Description']
        config.add_section('WireGuard')
        config['WireGuard']['ListenPort'] = str(self.port)
        config['WireGuard']['PrivateKey'] = server['PrivateKey']
        string = config_to_string(config)

        for _, client in self.clients:
            peer = ConfigParser()
            peer.optionxform = stripped
            peer.add_section('WireGuardPeer')
            peer['WireGuardPeer']['PublicKey'] = client['PublicKey']

            with suppress(KeyError):    # PSK is optional.
                peer['WireGuardPeer']['PresharedKey'] = server['PresharedKey']

            peer['WireGuardPeer']['AllowedIPs'] = client['Address']
            string += config_to_string(peer)

        return string.strip(linesep)
