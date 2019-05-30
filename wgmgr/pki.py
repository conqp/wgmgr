"""PKI management."""

from configparser import ConfigParser
from contextlib import suppress

from wgtools import genpsk, keypair

from wgmgr.exceptions import DuplicateClient, NoSuchClient
from wgmgr.functions import config_to_string, get_client, stripped
from wgmgr.orm import Client


__all__ = ['add_client', 'change_client', 'delete_client', 'PKIManager']


def add_client(pki, name, pubkey, address):
    """Adds a new clients."""

    try:
        get_client(pki, name)
    except NoSuchClient:
        client = Client(pki=pki, pubkey=pubkey, ipv4addr=address, name=name)
        client.save()
        return client

    raise DuplicateClient()


def change_client(pki, name, *, pubkey=None, address=None):
    """Modifies an existing client."""

    client = get_client(pki, name)

    if pubkey:
        client.pubkey = pubkey

    if address:
        client.ipv4addr = address

    client.save()


def delete_client(pki, name):
    """Deletes the client."""

    get_client(pki, name).delete_instance()


class PKIManager(ConfigParser):    # pylint: disable = R0901
    """A public key infrastructure."""

    def __init__(self, *args, **kwargs):
        """Sets the file path."""
        super().__init__(*args, **kwargs)
        self.optionxform = stripped

    def add_pki(self, name, network, address, endpoint, *, psk=False):
        """Initializes the PKI."""
        self.add_section(name)
        self[name]['Network'] = str(network)
        self[name]['Address'] = str(address)
        self[name]['Endpoint'] = endpoint
        self[name]['PublicKey'], self[name]['PrivateKey'] = keypair()

        if psk:
            self[name]['PresharedKey'] = genpsk()

    def dump_client(self, pki, name):
        """Dumps the client."""
        client = get_client(pki, name)
        section = self[pki]
        config = ConfigParser()
        config.optionxform = stripped
        config.add_section('Interface')
        config['Interface']['PrivateKey'] = '<your private key>'
        config['Interface']['Address'] = str(client.ipv4addr) + '/32'
        config.add_section('Peer')
        config['Peer']['PublicKey'] = section['PublicKey']

        with suppress(KeyError):    # PSK is optional.
            config['Peer']['PresharedKey'] = section['PresharedKey']

        config['Peer']['AllowedIPs'] = section['Network']
        config['Peer']['Endpoint'] = section['Endpoint']
        return config_to_string(config)

    def dump_netdev(self, pki, device, port, *, description=None):
        """Dumps a systemd.netdev configuration."""
        config = ConfigParser()
        config.optionxform = stripped
        config.add_section('NetDev')
        config['NetDev']['Name'] = device
        config['NetDev']['Kind'] = 'wireguard'
        config['NetDev']['Description'] = pki

        if description:
            config['NetDev']['Description'] = description

        config.add_section('WireGuard')
        config['WireGuard']['ListenPort'] = str(port)
        config['WireGuard']['PrivateKey'] = self[pki]['PrivateKey']
        string = config_to_string(config)

        for client in Client.select().where(Client.pki == pki):
            peer = ConfigParser()
            peer.optionxform = stripped
            peer.add_section('WireGuardPeer')
            peer['WireGuardPeer']['PublicKey'] = client.pubkey

            with suppress(KeyError):
                peer['WireGuardPeer']['PresharedKey'] = \
                    self[pki]['PresharedKey']

            peer['WireGuardPeer']['AllowedIPs'] = str(client.ipv4addr) + '/32'
            string += config_to_string(peer)

        return string
