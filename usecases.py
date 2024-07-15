"""
ISE Data Connect use cases
"""

from ise import IseDataConnect


def get_radius_authentications_by_day(ise_dc: IseDataConnect):
    """
    Return daywise number of passed and failed authentications
    """
    query = """SELECT TRUNC(TIMESTAMP) DAY, SUM(PASSED_COUNT), SUM(FAILED_COUNT)
        FROM RADIUS_AUTHENTICATION_SUMMARY
        GROUP BY TRUNC(TIMESTAMP)
        ORDER BY DAY DESC"""
    return ise_dc.execute_query(query)


def get_radius_authentications_by_location(ise_dc: IseDataConnect):
    """
    Return the Authentications by Location table that shows number of authentications passed,
    failed, total, failed percentage, avg response time, and peak response time for each location
    i.e the performance details of authentications locationwise.
    """
    query = """SELECT
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
    return ise_dc.execute_query(query)


def get_system_summary_last_hour(ise_dc: IseDataConnect, node: str):
    """
    Return system CPU and memory utilization for last one hour
    """
    query = """SELECT TIMESTAMP, ISE_NODE, CPU_UTILIZATION, MEMORY_UTILIZATION
        FROM SYSTEM_SUMMARY
        WHERE TIMESTAMP > SYSDATE - INTERVAL '1' HOUR
        AND ISE_NODE = :node
        ORDER BY TIMESTAMP DESC
        """
    return ise_dc.execute_query(query, {"node": node})
