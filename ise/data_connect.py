"""
Cisco ISE Data Connect
"""

import logging
from db import OjdbcConnectorFactory
from .exceptions import handle_exception
from .models import *  # pylint: disable=unused-wildcard-import, wildcard-import


class IseDataConnect:
    """
    Cisco ISE Data Connect

    For all the tables available, a `get_<table_name>` method is supported, e.g.
    - `NODE_LIST`: `get_node_list`
    - `ADMIN_USERS`: `get_admin_users`

    Args:
        @hostname (str): ISE hostname for Data Connect connection
        port (str): ISE port for Data Connect connection
        user (str): ISE Data Connect username
        password (str): ISE Data Connect password
        jar (str): Thick client JAR filename
        trust_store (str): Java key store filename, required for thick client
        trust_store_password (str): Java key store password, required for thick client
        verify (bool, optional): Verify ISE Data Connect certificate, Defaults to True.
    """

    def __init__(self, hostname: str, port: str, user: str, password: str, **kwargs):
        self._db_connector = OjdbcConnectorFactory.create_connector(
            hostname=hostname,
            port=port,
            user=user,
            password=password,
            **kwargs,
        )

    @handle_exception
    def execute_query(self, query, params=None):
        """
        Execute a SQL query statement and return results
        """
        return self._db_connector.execute_query(query, params)

    def get_all_records(self, table_name: str) -> list:
        """
        Get all records from the table.

        Args:
            table_name (str): Table name from ISE Data Connect

        Returns:
            list: All records from the table.
        """
        logging.debug("Get all records from table: %s", table_name)
        return self._deserialize(table_name, self.execute_query(f"SELECT * from {table_name}"))

    def _deserialize(self, table_name, results) -> any:
        class_object = _class_object(table_name)
        return [class_object(*instance) for instance in results]

    @handle_exception
    def __enter__(self):
        self._db_connector.connect()
        return self

    @handle_exception
    def __exit__(self, exc_type, exc_value, traceback):
        self._db_connector.close()


def _add_dynamic_function(table_name):
    setattr(
        IseDataConnect,
        f"get_{table_name.lower()}",
        lambda self: self.get_all_records(f"{table_name}"),
    )


def _convert_to_pascal_case(snake_str):
    components = snake_str.lower().split("_")
    return "".join(x.title() for x in components)


def _class_object(table_name):
    class_name = _convert_to_pascal_case(table_name)
    return globals()[class_name]


for ise_table_name in TABLE_NAMES:
    _add_dynamic_function(ise_table_name)
