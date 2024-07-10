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
    def create_connector(**kwargs) -> DatabaseConnector:
        """
        Create Database Connector
        """


class OjdbcConnectorFactory(DatabaseConnectorFactory):  # pylint: disable=too-few-public-methods
    """
    Database Connector Factory that return either of these connector instances:

    - ThinOjdbcConnector
    - ThickOjdbcConnector
    """

    @staticmethod
    def create_connector(**kwargs) -> DatabaseConnector:
        required_params = ["hostname", "port", "user", "password"]
        thick_specific_params = ["jar", "trust_store", "trust_store_password"]

        missing_params = [param for param in required_params if param not in kwargs]
        if missing_params:
            raise ValueError(f"Missing required parameters: {', '.join(missing_params)}")

        if all(param in kwargs for param in thick_specific_params):
            logging.debug("Using thick client for OJDBC connection")
            return ThickOjdbcConnector(**kwargs)

        unexpected_params = [param for param in thick_specific_params if param in kwargs]
        if unexpected_params:
            raise ValueError(
                f"Unexpected parameters for ThinOjdbcConnector: {', '.join(unexpected_params)}"
            )
        logging.debug("Using thin client for OJDBC connection")
        return ThinOjdbcConnector(**kwargs)
