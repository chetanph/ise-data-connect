"""
ISE Data Connect using Thin Oracle DB connector
"""

import logging
import ssl
import oracledb
from .connector import DatabaseConnector, DatabaseConnectorException


class ThinOjdbcConnector(DatabaseConnector):
    """
    OJDBC Database Connector using Thin client

    Args:
        hostname (str): OJDBC hostname
        port (str): OJDBC port
        user (str): OJDBC username
        password (str): OJDBC password
        verify (bool, optional): Verify OJDBC certificate, Defaults to True.
    """

    def __init__(
        self, hostname: str, port: str, user: str, password: str, verify: bool = True
    ):  # pylint: disable=too-many-arguments
        self.params = oracledb.ConnectParams(
            protocol="tcps",
            host=hostname,
            port=port,
            service_name="cpm10",
            user=user,
            password=password,
            retry_count=3,
            retry_delay=3,
            ssl_context=self._ssl_context(verify),
            # boolean indicating if the server certificate distinguished name (DN) should be matched
            # ssl_server_dn_match=False,  # Default: True
            # the distinguished name (DN), which should be matched with the server
            # ssl_server_cert_dn=False,
            # the directory containing the PEM-encoded wallet file, ewallet.pem
            # wallet_location=DIR_EWALLET,
        )
        self.connection = None

    def _ssl_context(self, verify: bool):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if not verify:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        return ssl_context

    def connect(self):
        """
        Establish OJDBC connection to the database

        Raises:
            DatabaseConnectorException: For any errors encountered when connecting to the database
        """
        self.connection = oracledb.connect(params=self.params)
        try:
            self.connection = oracledb.connect(params=self.params)
            logging.debug("Successfully connected to the database.")
        except oracledb.DatabaseError as err:
            logging.error("Database connection failed: %s.", err)
            raise DatabaseConnectorException(err) from err

    def close(self):
        """
        Close the database connection

        Raises:
            DatabaseConnectorException: For any errors encountered when closing the connection
        """
        if self.connection:
            try:
                self.connection.close()
                logging.debug("Database connection closed.")
            except oracledb.DatabaseError as err:
                logging.error("Failed to close the database connection: %s", err)
                raise DatabaseConnectorException(err) from err

    def execute_query(self, query: str, params: list | tuple | dict = None) -> list:
        """
        Execute SQL query against the database.

        Args:
            query (str): SQL query string
            params (list | tuple | dict): Named query parameters

        Returns:
            list: All records from the query result.

        Raises:
            DatabaseConnectorException: For any errors encountered when executing the query
        """
        if not self.connection:
            raise ConnectionError("Database connection is not established.")

        cursor = None
        try:
            cursor = self.connection.cursor()
            cursor.execute(statement=query, parameters=params)
            results = cursor.fetchall()
            logging.debug("Query executed successfully.")
            return results
        except oracledb.DatabaseError as err:
            logging.error("Failed to execute query: %s", err)
            raise DatabaseConnectorException(err) from err
        finally:
            if cursor:
                try:
                    cursor.close()
                    logging.debug("Cursor closed.")
                except oracledb.DatabaseError as err:
                    logging.error("Failed to close the cursor: %s", err)
