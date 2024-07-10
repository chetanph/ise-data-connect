"""
Database Connector
"""

from abc import ABC, abstractmethod


class DatabaseConnectorException(Exception):
    """
    Database Connector Exception
    """


class DatabaseConnector(ABC):
    """
    Abstract database connector
    """

    @abstractmethod
    def connect(self):
        """
        Connect to the database.
        """

    @abstractmethod
    def close(self):
        """
        Close the database connection.
        """

    @abstractmethod
    def execute_query(self, query: str, params: list | tuple | dict = None):
        """
        Execute query against the database.

        Args:
            query (str): SQL query string
            params (dict): Named query parameters
        """

    @property
    def tables(self):
        """
        List of all table names in the database
        """
        return self.execute_query("SELECT TABLE_NAME, COMMENTS FROM USER_TAB_COMMENTS")

    def table_schema(self, table_name):
        """
        Return schema for all the tables.

        These values are returned for each database table:
            Column Name, Data Type, Column Description
        """
        query = """SELECT utc.COLUMN_NAME, utc.DATA_TYPE, ucc.COMMENTS
            FROM USER_TAB_COLUMNS utc
            LEFT JOIN USER_COL_COMMENTS ucc 
            ON utc.TABLE_NAME = ucc.TABLE_NAME AND utc.COLUMN_NAME = ucc.COLUMN_NAME
            WHERE utc.TABLE_NAME = :table_name
            ORDER BY utc.COLUMN_ID"""
        return self.execute_query(query, {"table_name": table_name})

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
