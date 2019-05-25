"""Python bindings for WireGuard."""

from configparser import DuplicateSectionError, ConfigParser
from typing import NamedTuple

from wgtools import keypair, genpsk


__all__ = ['WG', 'Keypair', 'genkey', 'pubkey', 'keypair', 'genpsk']


def load_config(config_file: Path):
    """Returns the server configuration."""

    with config_file.open('r') as file:
        return ConfigParser().load(file)


def initpki(config: ConfigParser, network: IPv4Network, server: IPv4Address):
    """Initializes the PKI."""

    config.clear()
    config.add_section('Network')
    config['Network']['network'] = str(network)
    config['Network']['server'] = str(server)
    return config


def main():
    """Runs the main program."""

    
