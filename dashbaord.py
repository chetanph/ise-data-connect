"""
ISE Dashboard that pulls data from ISE Data Connect, powered by streamlit
"""

import streamlit as st
import pandas as pd
from ise import IseDataConnect, IseDataConnectException
from util import parse_arguments, configure_logging
from usecases import get_system_summary_last_hour, get_radius_authentications_by_location


st.set_page_config(page_title="Cisco ISE Data Connect dashboard", layout="wide")


def main():
    """
    Streamlit UI app for ISE Data Connect dashbaord
    """
    st.title(":blue[ISE Data Connect Dashboards]")

    args = parse_arguments()
    configure_logging(args.log_level)
    try:
        with IseDataConnect(
            hostname=args.ise_hostname,
            port=args.ise_dataconnect_port,
            user=args.dataconnect_user,
            password=args.dataconnect_password,
            verify=not args.insecure,
        ) as ise_dc:

            def page_system_summary():
                system_summary_charts(ise_dc)

            def page_auth_by_location():
                radius_auth_by_location_chart(ise_dc)

            pages = st.navigation(
                [
                    st.Page(page_system_summary, title="System Summary"),
                    st.Page(page_auth_by_location, title="RADIUS Authentications by Location"),
                ]
            )
            pages.run()

    except IseDataConnectException as e:
        st.error(f"An exception occurred: {e}")


def system_summary_charts(ise_dc: IseDataConnect) -> None:
    """
    Display ISE System Summary chart

    Args:
        ise_dc (IseDataConnect): ISE Data Connect object
    """
    st.subheader("System Summary")
    nodes = ise_dc.get_node_list()
    node_list = [node.hostname for node in nodes]

    all_cpu_data = []
    all_memory_data = []

    for node in node_list:
        data = get_system_summary_last_hour(ise_dc, node)
        if data:
            df = pd.DataFrame(
                data,
                columns=[
                    "Timestamp",
                    "ISE Node",
                    "CPU Utilization",
                    "Memory Utilization",
                ],
            )
            df["Timestamp"] = pd.to_datetime(df["Timestamp"])
            df.set_index("Timestamp", inplace=True)

            all_cpu_data.append(df["CPU Utilization"].rename(node))
            all_memory_data.append(df["Memory Utilization"].rename(node))

    cpu_df = pd.concat(all_cpu_data, axis=1)
    memory_df = pd.concat(all_memory_data, axis=1)

    cpu_df = cpu_df.resample("min").mean().interpolate()  # 'min' for minute frequency
    memory_df = memory_df.resample("min").mean().interpolate()

    if not cpu_df.empty:
        st.subheader("CPU Utilization")
        st.line_chart(cpu_df)

    if not memory_df.empty:
        st.subheader("Memory Utilization")
        st.line_chart(memory_df)


def radius_auth_by_location_chart(ise_dc: IseDataConnect) -> None:
    """
    Display ISE RADIUS Authentications by Location chart

    Args:
        ise_dc (IseDataConnect): ISE Data Connect object
    """
    st.subheader("RADIUS Authentications by Location")
    data = get_radius_authentications_by_location(ise_dc)
    if data:
        df = pd.DataFrame(
            data,
            columns=[
                "Location",
                "Total Passed Count",
                "Total Failed Count",
                "Total Count",
                "Failed Percentage",
                "Avg Response Time",
                "Peak Response Time",
            ],
        )
        df["Location"] = df["Location"].apply(lambda x: x.split("#")[-1])
        df.set_index("Location", inplace=True)
        st.bar_chart(df[["Total Passed Count", "Total Failed Count"]], color=["#e3241b", "#74bf4b"])
    else:
        st.write("No data available for RADIUS Authentications by Location.")


if __name__ == "__main__":
    main()
