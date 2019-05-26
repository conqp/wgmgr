"""Database models."""

from configparser import ConfigParser
from threading import Lock

from peewee import CharField, Model
from peeweeplus import IPv4AddressField, MySQLDatabase


__al__ = ['init', 'Client']


CONFIG_FILE = '/etc/wgmgr.conf'
DATABASE = MySQLDatabase(None)
LOCK = Lock()


def init():
    """Loads the configuration and initializes the database."""

    config = ConfigParser()
    config.read(CONFIG_FILE)
    DATABASE.from_config(config)


class Client(Model):
    """Table to store clients."""

    class Meta:     # pylint: disable=C0111,R0903
        database = DATABASE
        schema = database.database

    pki = CharField(255)
    name = CharField(255)
    ipv4addr = IPv4AddressField()
    pubkey = CharField(44)

    def __str__(self):
        """Returns the client as string."""
        return f'{self.name}@{self.pki} {self.ipv4addr} {self.pubkey}'

    @classmethod
    def _ipv4addresses(cls, pki):
        """Yields IPv4 addresses."""
        for client in cls.select().where(cls.pki == pki):
            yield client.ipv4addr

    @classmethod
    def ipv4addresses(cls, pki):
        """Lists IPv4Addresses of the given PKI."""
        with LOCK:
            return frozenset(cls._ipv4addresses(pki))
