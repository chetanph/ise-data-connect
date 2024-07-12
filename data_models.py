"""
Generate data models for ISE Data Connect tables. It is saved in `ise/models.py`
"""

import datetime
import json
from dataclasses import field, make_dataclass
from typing import Optional
import traceback
from db import ThinOjdbcConnector, DatabaseConnectorException
from util import parse_arguments


MODELS_HEADER = '''"""
Python Data Models for ISE Data Connect table views

This is an auto-generated file
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


'''


def main():
    """
    Generate data models for ISE Data Connect tables
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
            data_class_definitions = []
            with open("ise/models.py", "w", encoding="utf-8") as f:
                f.write(MODELS_HEADER)
                tables = db_connector.tables
                table_names = json.dumps([table_name for table_name, _ in tables], indent=4)
                f.write(f"TABLE_NAMES = {table_names}\n")
                for table_name, description in tables:
                    columns = db_connector.table_schema(table_name)
                    class_definition = create_data_class_definition(
                        table_name, description, columns
                    )
                    data_class_definitions.append(class_definition)

                for class_definition in data_class_definitions:
                    f.write(class_definition)

            print("Data classes have been saved to ise/models.py")

    except DatabaseConnectorException as e:
        print(f"An exception occurred: {e}")
        print(traceback.format_exc())


def map_data_type(oracle_type):
    """
    map Oracle data types to Python data types
    """
    type_mapping = {
        "VARCHAR2": str,
        "NUMBER": int,
        "TIMESTAMP(6)": datetime.datetime,
        "TIMESTAMP(6) WITH TIME ZONE": datetime.datetime,
        "CLOB": str,
        "GLOB": str,
    }
    return type_mapping.get(oracle_type, str)


def create_data_class(table_name, description, columns):
    """
    Create a data class dynamically
    """
    return make_dataclass(
        table_name,
        [
            (column_name.lower(), Optional[map_data_type(data_type)], field(default=None))
            for column_name, data_type, _ in columns
        ],
        namespace={"__doc__": description},
    )


def create_data_class_definition(table_name, description, columns):
    """
    Create data class definition
    """
    class_name = convert_to_pascal_case(table_name)
    class_def = f'\n\n@dataclass\nclass {class_name}:\n    """{description}"""\n\n'
    for column_name, data_type, comment in columns:
        python_type = map_data_type(data_type)
        comment_str = f'\n    """{comment}"""' if comment else ""
        class_def += (
            f"    {column_name.lower()}: Optional[{python_type.__name__}] = "
            f"field(default=None){comment_str}\n"
        )
    return class_def


def convert_to_pascal_case(snake_str):
    """
    Convert ISE database table name to pascal case, `NODE_LIST` -> `NodeList`
    """
    components = snake_str.lower().split("_")
    return "".join(x.title() for x in components)


if __name__ == "__main__":
    main()
