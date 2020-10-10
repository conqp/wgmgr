"""PKI management."""

from configparser import DuplicateSectionError, ConfigParser, SectionProxy
from contextlib import suppress
from ipaddress import ip_address
from ipaddress import ip_network
from ipaddress import IPv4Address
from ipaddress import IPv4Network
from ipaddress import IPv6Address
from ipaddress import IPv6Network
from os import linesep
from typing import Generator, Tuple, Union

from wgtools import genpsk, keypair

from wgmgr.exceptions import DuplicateClient
from wgmgr.exceptions import DuplicateIPAddress
from wgmgr.exceptions import InvalidClientName
from wgmgr.exceptions import NetworkExhausted
from wgmgr.exceptions import NoSuchClient
from wgmgr.exceptions import NotInitialized
from wgmgr.functions import config_to_string, stripped


__all__ = ['PKI']


SERVER = 'Server'
IPAddress = Union[IPv4Address, IPv6Address]
IPNetwork = Union[IPv4Network, IPv6Network]


class PKI(ConfigParser):    # pylint: disable = R0901
    """A public key infrastructure."""

    def __init__(self, *args, **kwargs):
        """Sets the file path."""
        super().__init__(*args, **kwargs)
        self.optionxform = stripped

    @property
    def network(self) -> IPNetwork:
        """Returns the IP network."""
        return ip_network(self[SERVER]['Network'])

    @property
    def addresses(self) -> Generator[IPAddress, None, None]:
        """Yields issued IP addresses."""
        for section in self.sections():
            with suppress(KeyError):
                yield ip_address(self[section]['Address'])

    @property
    def port(self) -> int:
        """Returns the server's port."""
        _, port = self[SERVER]['Endpoint'].rsplit(':', maxsplit=1)
        return int(port)

    @property
    def clients(self) -> Tuple[str, SectionProxy]:
        """Yields all client sections."""
        for section in self.sections():
            if section == SERVER:
                continue

            yield (section, self[section])

    # pylint: disable=R0913
    def init(self, name: str, description: str, network: IPNetwork,
             address: IPAddress, endpoint: str, psk: bool = False):
        """Initializes the PKI."""
        self.add_section(SERVER)
        self[SERVER]['Name'] = str(name)
        self[SERVER]['Description'] = str(description)
        self[SERVER]['Network'] = str(network)
        self[SERVER]['Address'] = str(address)
        self[SERVER]['Endpoint'] = endpoint
        self[SERVER]['PublicKey'], self[SERVER]['PrivateKey'] = keypair()

        if psk:
            self[SERVER]['PresharedKey'] = genpsk()

    def get_address(self) -> IPAddress:
        """Returns a free address."""
        addresses = set(self.addresses)

        for count, address in enumerate(self.network, start=1):
            if count > 1 and address not in addresses:
                return address

        raise NetworkExhausted()

    def add_client(self, pubkey: str, address: IPAddress = None,
                   name: str = None):
        """Adds a client."""
        section = str(pubkey) if name is None else str(name)

        if section == SERVER:
            raise InvalidClientName()

        try:
            self.add_section(section)
        except DuplicateSectionError:
            raise DuplicateClient(section) from None

        if address is None:
            address = self.get_address()
        elif address in self.addresses:
            raise DuplicateIPAddress()

        client = self[section]
        client['PublicKey'] = str(pubkey)
        client['Address'] = str(address)

    def modify_client(self, name: str, pubkey: str = None,
                      address: IPAddress = None):
        """Modifies a client."""
        if name == SERVER:
            raise InvalidClientName()

        try:
            client = self[name]
        except KeyError:
            raise NoSuchClient(name) from None

        if pubkey is not None:
            client['PublicKey'] = str(pubkey)

        if address is not None:
            if address in self.addresses:
                raise DuplicateIPAddress()

            client['Address'] = str(address)

    def remove_client(self, name: str) -> bool:
        """Removes the respective client."""
        if name == SERVER:
            raise InvalidClientName()

        return self.remove_section(name)

    def list_clients(self) -> str:
        """Lists all clients."""
        clients = ConfigParser()
        clients.optionxform = stripped

        for name, section in self.clients:
            clients.add_section(name)
            client = clients[name]
            client['PublicKey'] = section['PublicKey']
            client['Address'] = section['Address']

        return config_to_string(clients).strip(linesep)

    def dump_client(self, name: str) -> str:
        """Dumps the client."""
        if name == SERVER:
            raise InvalidClientName()

        try:
            server = self['Server']
        except KeyError:
            raise NotInitialized() from None

        try:
            client = self[name]
        except KeyError:
            raise NoSuchClient(name) from None

        config = ConfigParser()
        config.optionxform = stripped
        config.add_section('Interface')
        config['Interface']['PrivateKey'] = '<your private key>'
        network = ip_network(ip_address(client['Address']))
        config['Interface']['Address'] = str(network)
        config.add_section('Peer')
        config['Peer']['PublicKey'] = server['PublicKey']

        with suppress(KeyError):    # PSK is optional.
            config['Peer']['PresharedKey'] = server['PresharedKey']

        config['Peer']['AllowedIPs'] = server['Network']
        config['Peer']['Endpoint'] = server['Endpoint']
        return config_to_string(config).strip(linesep)

    def dump_netdev(self) -> str:
        """Dumps a systemd.netdev configuration."""
        try:
            server = self[SERVER]
        except KeyError:
            raise NotInitialized() from None

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

            network = ip_network(ip_address(client['Address']))
            peer['WireGuardPeer']['AllowedIPs'] = str(network)
            string += config_to_string(peer)

        return string.strip(linesep)
