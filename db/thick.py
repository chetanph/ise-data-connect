"""
Database connector using Oracle JAR file as a thick client
"""

import logging
import jaydebeapi
import jpype
from .connector import DatabaseConnector, DatabaseConnectorException


def stringified(rows: list) -> list:
    """
    Convert all the items in all the rows to string

    Args:
        rows (list): Rows returned by database query result

    Returns:
        list: Return stringified rows returned by OJDBC connection
    """
    return [[str(entry) for entry in row] for row in rows]


class ThickOjdbcConnector(DatabaseConnector):  # pylint: disable=too-many-instance-attributes
    """
    OJDBC Database Connector using Thick client

    Args:
        hostname (str): OJDBC hostname
        port (str): OJDBC port
        user (str): OJDBC username
        password (str): OJDBC password
        jar (str): Thick client JAR filename
        trust_store (str): Java key store filename
        trust_store_password (str): Java key store password
    """

    def __init__(
        self,
        hostname: str,
        port: str,
        user: str,
        password: str,
        jar: str,
        trust_store: str,
        trust_store_password: str,
    ):  # pylint: disable=too-many-arguments
        self.ip = hostname
        self.port = port
        self.connection_string = (
            f"jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(PROTOCOL=tcps)(HOST="
            f"{self.ip})(PORT={self.port}))(CONNECT_DATA=(SID=cpm10)))"
        )
        self.user = user
        self.password = password
        self.jar = jar
        self.trust_store = trust_store
        self.trust_store_password = trust_store_password
        self.conn = None
        self.cursor = None

    def _start_jvm(self):
        if not jpype.isJVMStarted():
            jvm_path = jpype.getDefaultJVMPath()
            jpype.startJVM(
                jvm_path,
                f"-Djava.class.path={self.jar}",
                f"-Djavax.net.ssl.trustStore={self.trust_store}",
                f"-Djavax.net.ssl.trustStorePassword={self.trust_store_password}",
            )

    def connect(self):
        """
        Establish OJDBC connection to the database

        Raises:
            DatabaseConnectorException: For any errors encountered when connecting to the database
        """
        try:
            self._start_jvm()
            self.conn = jaydebeapi.connect(
                "oracle.jdbc.driver.OracleDriver",
                self.connection_string,
                {"user": self.user, "password": self.password, "secure": "true"},
            )
            logging.debug("Successfully connected to the database.")
            self.cursor = self.conn.cursor()
        except jaydebeapi.Error as err:
            logging.error("Database connection error: %s", err)
            raise DatabaseConnectorException(err) from err
        except (jpype.JVMNotFoundException, jpype.JVMNotSupportedException) as err:
            logging.error("JVM error: %s", err)
            raise DatabaseConnectorException(err) from err
        except (TypeError, ValueError) as err:
            logging.error("Invalid connection parameters: %s", err)
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
        try:
            self.cursor.execute(operation=query, parameters=params)
            logging.debug("Query executed successfully.")
            return stringified(self.cursor.fetchall())
        except jaydebeapi.ProgrammingError as err:
            logging.error("Programming error during query execution: %s", err)
            raise DatabaseConnectorException(err) from err
        except jaydebeapi.DatabaseError as err:
            logging.error("Database error during query execution: %s", err)
            raise DatabaseConnectorException(err) from err

    def close(self):
        """
        Close the database connection

        Raises:
            DatabaseConnectorException: For any errors encountered when closing the connection
        """
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
        logging.debug("Database connection closed.")
        if jpype.isJVMStarted():
            jpype.shutdownJVM()

    @property
    def tables(self) -> list:
        """
        List of all table names in the database
        """
        return stringified(super().tables)

    def table_schema(self, table_name: str) -> list:
        """
        Return schema for all the tables.

        These values are returned for each database table:
        - Column Name
        - Data Type
        - Column Description

        Args:
            table_name (str): Database table name

        Returns:
            list: List of Column names, their data type and description of each column
        """
        query = """SELECT utc.COLUMN_NAME, utc.DATA_TYPE, ucc.COMMENTS
            FROM USER_TAB_COLUMNS utc
            LEFT JOIN USER_COL_COMMENTS ucc 
            ON utc.TABLE_NAME = ucc.TABLE_NAME AND utc.COLUMN_NAME = ucc.COLUMN_NAME
            WHERE utc.TABLE_NAME = ?
            ORDER BY utc.COLUMN_ID"""
        return self.execute_query(query, [table_name])
