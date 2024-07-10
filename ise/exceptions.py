"""
Exceptions for ISE Data Connect
"""

from db import DatabaseConnectorException


class IseDataConnectException(Exception):
    """
    ISE Data Connect Exception
    """


def handle_exception(func):
    """
    Raise `IseDataConnectException` when needed
    """

    def try_or_raise(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except DatabaseConnectorException as err:
            raise IseDataConnectException(err) from err

    return try_or_raise
