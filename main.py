"""
Example usage of ISE Data Connect
"""

import traceback
from ise import IseDataConnect, IseDataConnectException
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
            verify=False,  # Thin Connector
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

            query_auth_by_day = """SELECT
                TRUNC(TIMESTAMP) DAY, SUM(PASSED_COUNT), SUM(FAILED_COUNT)
            FROM RADIUS_AUTHENTICATION_SUMMARY
            GROUP BY TRUNC(TIMESTAMP)
            ORDER BY DAY DESC"""

            print_table(
                "Authentications by Day",
                ["Day", "Passed", "Failed"],
                ise_dc.execute_query(query_auth_by_day),
            )

            query_auth_by_location = """SELECT
                LOCATION,
                SUM(PASSED_COUNT) AS TOTAL_PASSED_COUNT,
                SUM(FAILED_COUNT) AS TOTAL_FAILED_COUNT,
                (SUM(PASSED_COUNT) + SUM(FAILED_COUNT)) AS TOTAL_COUNT,
                ROUND((SUM(FAILED_COUNT) / NULLIF(SUM(PASSED_COUNT) + SUM(FAILED_COUNT), 0)) * 100, 2) AS FAILED_PERCENTAGE,
                AVG(TOTAL_RESPONSE_TIME) AS AVG_RESPONSE_TIME,
                MAX(MAX_RESPONSE_TIME) AS PEAK_RESPONSE_TIME
            FROM RADIUS_AUTHENTICATION_SUMMARY
            GROUP BY LOCATION
            ORDER BY TOTAL_COUNT DESC"""

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
                ise_dc.execute_query(query_auth_by_location),
            )

    except IseDataConnectException as e:
        print(f"An exception occurred: {e}")
        print(traceback.format_exc())


if __name__ == "__main__":
    main()
