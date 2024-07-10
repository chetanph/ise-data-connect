"""
This script retrieves the schema of all the database tables from ISE Data Connect.

All the information printed by this script is similar documentation here:
https://developer.cisco.com/docs/dataconnect/database-views/#aaa_diagnostics_view

Obtaining the same information programmatically allows for automated code generation for processing
data returned by ISE.
"""

import traceback
from db import ThinOjdbcConnector, DatabaseConnectorException
from util import parse_arguments, print_table


def main():
    """
    Print schema of all the tables from ISE Data Connect
    """
    args = parse_arguments()

    try:
        with ThinOjdbcConnector(
            args.ise_hostname,
            args.ise_dataconnect_port,
            args.dataconnect_user,
            args.dataconnect_password,
            verify=False,
        ) as db_connector:
            for table_name, description in db_connector.tables:
                print_table(
                    table_name,
                    ["Column Name", "Data Type", "Column Description"],
                    db_connector.table_schema(table_name),
                    description,
                )

    except DatabaseConnectorException as e:
        print(f"An exception occurred: {e}")
        print(traceback.format_exc())


if __name__ == "__main__":
    main()
