"""
Example usage of ISE Data Connect
"""

import traceback
from ise import IseDataConnect, IseDataConnectException
from usecases import get_radius_authentications_by_day, get_radius_authentications_by_location
from util import parse_arguments, configure_logging, print_table


def main():
    """
    Print example tables from ISE Data Connect
    """
    args = parse_arguments()
    configure_logging(args.log_level)
    try:
        with IseDataConnect(
            hostname=args.ise_hostname,
            port=args.ise_dataconnect_port,
            user=args.dataconnect_user,
            password=args.dataconnect_password,
            verify=not args.insecure,  # Thin Connector
            # jar=args.ojdbc_jar,                             # Thick Connector
            # trust_store=args.trust_store,                   # Thick Connector
            # trust_store_password=args.trust_store_password  # Thick Connector
        ) as ise_dc:
            print_table(
                "Network Device Groups",
                ["Created By", "Status", "Name"],
                [
                    (group.created_by, group.active_status, group.name)
                    for group in ise_dc.get_network_device_groups()
                ],
            )

            print_table(
                "Admin Users",
                ["Status", "Admin Group", "Name"],
                [
                    (admin_user.admin_group, admin_user.status, admin_user.name)
                    for admin_user in ise_dc.get_admin_users()
                ],
            )

            print_table(
                "Node List",
                ["Hostname", "Node Type", "Node Role"],
                [
                    (node.hostname, node.node_type, node.node_role)
                    for node in ise_dc.get_node_list()
                ],
            )

            print_table(
                "Authentications by Day",
                ["Day", "Passed", "Failed"],
                get_radius_authentications_by_day(ise_dc),
            )

            print_table(
                "Authentications by Locations",
                [
                    "Location",
                    "Passed",
                    "Failed",
                    "Total",
                    "Failed %",
                    "Average Response Time",
                    "Max Response Time",
                ],
                get_radius_authentications_by_location(ise_dc),
            )

    except IseDataConnectException as e:
        print(f"An exception occurred: {e}")
        print(traceback.format_exc())


if __name__ == "__main__":
    main()
