"""Common exceptions."""


__all__ = ['NoSuchClient']


class NoSuchClient(Exception):
    """Indicates that the respective client does not exist."""

    def __init__(self, client):
        """Sets the client."""
        super().__init__(client)
        self.client = client
