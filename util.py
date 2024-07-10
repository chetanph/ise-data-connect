"""
Utilities
"""

import argparse
from datetime import datetime
import logging
import os
import sys
from rich.console import Console
from rich.table import Table


def parse_arguments():
    """
    Parse input values from CLI arguments or environment variables.

    CLI arguments take precedence over environment variables.
    """
    parser = argparse.ArgumentParser(description="Read parameters for ISE data connect.")

    parser.add_argument("--ojdbc-jar", default=os.getenv("OJDBC_JAR", "ojdbc11-23.4.0.24.05.jar"))
    parser.add_argument("--trust-store", default=os.getenv("TRUST_STORE", "keystore.jks"))
    parser.add_argument("--trust-store-password", default=os.getenv("TRUST_STORE_PASSWORD"))
    parser.add_argument("--ise-hostname", default=os.getenv("ISE_HOSTNAME"))
    parser.add_argument("--ise-dataconnect-port", default=os.getenv("ISE_DATACONNECT_PORT", "2484"))
    parser.add_argument("--dataconnect-user", default=os.getenv("DATACONNECT_USER", "dataconnect"))
    parser.add_argument("--dataconnect-password", default=os.getenv("DATACONNECT_PASSWORD"))
    parser.add_argument("--log-level", default=os.getenv("DATACONNECT_LOG_LEVEL", "INFO"))
    return parser.parse_args()


def stringify(obj):
    """
    Return objects that can be rendered by `rich`
    """
    converters = {
        datetime: lambda obj: obj.strftime("%Y-%m-%d %H:%M:%S"),
        dict: lambda obj: {k: stringify(v) for k, v in obj.items()},
        list: lambda obj: [stringify(item) for item in obj],
        tuple: lambda obj: [stringify(item) for item in obj],
        int: str,
        float: lambda obj: f"{obj:.2f}",
    }

    converter = converters.get(type(obj))
    return converter(obj) if converter else obj


def print_table(title, headers, rows, caption=None):
    """
    Print table using Rich console
    """
    console = Console()

    table = Table(title=title, caption=caption)
    for header in headers:
        table.add_column(header)
    for row in rows:
        table.add_row(*stringify(row))

    console.print(table)


def configure_logging(level):
    """
    Configures logging for the entire program.
    """
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )
