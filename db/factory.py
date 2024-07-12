"""
Database Connector Factory
"""

from abc import ABC
import logging
from .connector import DatabaseConnector
from .thin import ThinOjdbcConnector
from .thick import ThickOjdbcConnector


class DatabaseConnectorFactory(ABC):  # pylint: disable=too-few-public-methods
    """
    Database Connector Factory
    """

    @staticmethod
    def create_connector(
        hostname: str, port: str, user: str, password: str, **kwargs
    ) -> DatabaseConnector:
        """
        Create Database Connector

        Args:
            hostname (str): OJDBC hostname
            port (str): OJDBC port
            user (str): OJDBC username
            password (str): OJDBC password
            kwargs (dict): Additional parameters for specific connector implementation

        Raises:
            ValueError: For unexpected input parameters

        Returns:
            DatabaseConnector: Database Connector
        """



class OjdbcConnectorFactory(DatabaseConnectorFactory):  # pylint: disable=too-few-public-methods
    """
    Database Connector Factory that return either of these connector instances:

    - ThinOjdbcConnector
    - ThickOjdbcConnector
    """

    @staticmethod
    def create_connector(
        hostname: str, port: str, user: str, password: str, **kwargs
    ) -> DatabaseConnector:
        """
        Create Database Connector

        Args:
            hostname (str): OJDBC hostname
            port (str): OJDBC port
            user (str): OJDBC username
            password (str): OJDBC password

            For `ThinOjdbcConnector`:
            verify (bool, optional): Verify OJDBC certificate, Defaults to True.

            For `ThickOjdbcConnector`:
            jar (str): Thick client JAR filename
            trust_store (str): Java key store filename
            trust_store_password (str): Java key store password

        Raises:
            ValueError: For unexpected input parameters

        Returns:
            DatabaseConnector: Database Connector
        """
        thick_specific_params = ["jar", "trust_store", "trust_store_password"]

        if all(param in kwargs for param in thick_specific_params):
            logging.debug("Using thick client for OJDBC connection")
            return ThickOjdbcConnector(hostname, port, user, password, **kwargs)

        unexpected_params = [param for param in thick_specific_params if param in kwargs]
        if unexpected_params:
            raise ValueError(
                f"Unexpected parameters for ThinOjdbcConnector: {', '.join(unexpected_params)}"
            )
        logging.debug("Using thin client for OJDBC connection")
        return ThinOjdbcConnector(hostname, port, user, password, **kwargs)
