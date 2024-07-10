"""
ISE Data Models for Data Connect table views

This is an auto-generated file
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


TABLE_NAMES = [
    "AAA_DIAGNOSTICS_VIEW",
    "ADAPTER_STATUS",
    "ADAPTIVE_NETWORK_CONTROL",
    "ADMINISTRATOR_LOGINS",
    "ADMIN_USERS",
    "AUP_ACCEPTANCE_STATUS",
    "AUTHORIZATION_PROFILES",
    "CHANGE_CONFIGURATION_AUDIT",
    "COA_EVENTS",
    "ENDPOINTS_DATA",
    "ENDPOINT_IDENTITY_GROUPS",
    "ENDPOINT_PURGE_VIEW",
    "EXT_ID_SRC_ACTIVE_DIRECTORY",
    "EXT_ID_SRC_CERT_AUTH_PROFILE",
    "EXT_ID_SRC_LDAP",
    "EXT_ID_SRC_ODBC",
    "EXT_ID_SRC_RADIUS_TOKEN",
    "EXT_ID_SRC_REST",
    "EXT_ID_SRC_RSA_SECURID",
    "EXT_ID_SRC_SAML_ID_PROVIDERS",
    "EXT_ID_SRC_SOCIAL_LOGIN",
    "FAILURE_CODE_CAUSE",
    "GUEST_ACCOUNTING",
    "GUEST_DEVICELOGIN_AUDIT",
    "KEY_PERFORMANCE_METRICS",
    "LOGICAL_PROFILES",
    "MISCONFIGURED_NAS_VIEW",
    "MISCONFIGURED_SUPPLICANTS_VIEW",
    "NETWORK_ACCESS_USERS",
    "NETWORK_DEVICES",
    "NETWORK_DEVICE_GROUPS",
    "NODE_LIST",
    "OPENAPI_OPERATIONS",
    "POLICY_SETS",
    "POSTURE_ASSESSMENT_BY_CONDITION",
    "POSTURE_ASSESSMENT_BY_ENDPOINT",
    "POSTURE_GRACE_PERIOD",
    "POSTURE_SCRIPT_CONDITION",
    "POSTURE_SCRIPT_REMEDIATION",
    "PRIMARY_GUEST",
    "PROFILED_ENDPOINTS_SUMMARY",
    "PROFILING_POLICIES",
    "PXGRID_DIRECT_DATA",
    "RADIUS_ACCOUNTING",
    "RADIUS_ACCOUNTING_WEEK",
    "RADIUS_AUTHENTICATIONS",
    "RADIUS_AUTHENTICATIONS_WEEK",
    "RADIUS_AUTHENTICATION_SUMMARY",
    "RADIUS_ERRORS_VIEW",
    "REGISTERED_ENDPOINTS",
    "SECURITY_GROUPS",
    "SECURITY_GROUP_ACLS",
    "SPONSOR_LOGIN_AND_AUDIT",
    "SYSTEM_DIAGNOSTICS_VIEW",
    "SYSTEM_SUMMARY",
    "TACACS_ACCOUNTING",
    "TACACS_ACCOUNTING_LAST_TWO_DAYS",
    "TACACS_AUTHENTICATION",
    "TACACS_AUTHENTICATION_LAST_TWO_DAYS",
    "TACACS_AUTHENTICATION_SUMMARY",
    "TACACS_AUTHORIZATION",
    "TACACS_COMMAND_ACCOUNTING",
    "THREAT_EVENTS",
    "UPSPOLICY",
    "UPSPOLICYSET",
    "UPSPOLICYSET_POLICIES",
    "USER_IDENTITY_GROUPS",
    "USER_PASSWORD_CHANGES",
    "VULNERABILITY_ASSESSMENT_FAILURES",
]


@dataclass
class AaaDiagnosticsView:
    """Provides details of all network sessions between Cisco ISE and users"""

    timestamp_timezone: Optional[datetime] = field(default=None)
    """Time with timezone when record added"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    session_id: Optional[str] = field(default=None)
    """Shows the session ID"""
    ise_node: Optional[str] = field(default=None)
    """Displays the hostname of the ISE server"""
    username: Optional[str] = field(default=None)
    """Displays the username"""
    message_severity: Optional[str] = field(default=None)
    """Displays the severity of message"""
    message_code: Optional[str] = field(default=None)
    """Displays the message code"""
    message_text: Optional[str] = field(default=None)
    """Displays the message text"""
    category: Optional[str] = field(default=None)
    """Displays the category"""
    info: Optional[str] = field(default=None)
    """Displays the diagnostic info"""


@dataclass
class AdapterStatus:
    """Adapter Status Report"""

    logged_at: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was processed and stored by the Monitoring node"""
    status: Optional[str] = field(default=None)
    """Specifies the adapter status"""
    id: Optional[str] = field(default=None)
    """Unique database ID"""
    adapter_name: Optional[str] = field(default=None)
    """Specifies the adapter name"""
    connectivity: Optional[str] = field(default=None)
    """Specifies the connectivity"""


@dataclass
class AdaptiveNetworkControl:
    """The Adaptive Network Control Audit report is based on the RADIUS accounting. It displays historical reporting of all network sessions for each endpoint"""

    logged_at: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was processed and stored by the Monitoring node"""
    endpoint_id: Optional[str] = field(default=None)
    """Specifies the endpoint ID"""
    id: Optional[int] = field(default=None)
    """Unique Database ID"""
    ip_address: Optional[str] = field(default=None)
    """Specifies the IP address"""
    ipv6_address: Optional[str] = field(default=None)
    """Specifies the IPV6 IP address"""
    operation_type: Optional[str] = field(default=None)
    """Specifies the operation type"""
    operation_status: Optional[str] = field(default=None)
    """Specifies the operation status"""
    audit_session: Optional[str] = field(default=None)
    """Specifies the audit session"""
    admin_identity: Optional[str] = field(default=None)
    """Specifies the admin identity"""
    admin_ip: Optional[str] = field(default=None)
    """Specifies the admin IP"""
    ise_node: Optional[str] = field(default=None)
    """Specifies the ISE node"""


@dataclass
class AdministratorLogins:
    """Gives the data about the administrator logins to the ISE"""

    timestamp_timezone: Optional[datetime] = field(default=None)
    """Time with timezone when administrator logged in"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when administrator logged in"""
    ise_node: Optional[str] = field(default=None)
    """Hostname of ISE node"""
    admin_name: Optional[str] = field(default=None)
    """Name of the admin"""
    ip_address: Optional[str] = field(default=None)
    """IP address of the client from where the admin logged in"""
    ipv6_address: Optional[str] = field(default=None)
    """IPV6 address"""
    interface: Optional[str] = field(default=None)
    """Interface used for login GUI/CLI"""
    admin_session: Optional[str] = field(default=None)
    """admin session"""
    event_details: Optional[str] = field(default=None)
    """Details of the event"""
    event: Optional[str] = field(default=None)
    """Admin logged in or logged out"""


@dataclass
class AdminUsers:
    """This provides details of all the administrators of ISE"""

    id: Optional[str] = field(default=None)
    """Database unique ID"""
    status: Optional[str] = field(default=None)
    """Admin user is enabled or disabled"""
    name: Optional[str] = field(default=None)
    """Name of the admin user"""
    description: Optional[str] = field(default=None)
    """Description"""
    first_name: Optional[str] = field(default=None)
    """First name of the admin user"""
    last_name: Optional[str] = field(default=None)
    """Last name of the admin user"""
    email_address: Optional[str] = field(default=None)
    """Email address of the admin user"""
    admin_group: Optional[str] = field(default=None)
    """Group to which admin user belongs"""


@dataclass
class AupAcceptanceStatus:
    """Track all accepted and denied AUP connections"""

    id: Optional[int] = field(default=None)
    """Database unique ID"""
    timestamp_timezone: Optional[datetime] = field(default=None)
    """Time with timezone when record added"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    message_code: Optional[str] = field(default=None)
    """Message code"""
    username: Optional[str] = field(default=None)
    """User name"""
    ip_address: Optional[str] = field(default=None)
    """IP address of the endpoint"""
    mac_address: Optional[str] = field(default=None)
    """MAC address of the endpoint"""
    portal_name: Optional[str] = field(default=None)
    """Portal name"""
    aup_acceptance: Optional[str] = field(default=None)
    """AUP acceptance status"""
    first_name: Optional[str] = field(default=None)
    """First name of user"""
    last_name: Optional[str] = field(default=None)
    """Last name of user"""
    identity_group: Optional[str] = field(default=None)
    """Identity group"""
    email_address: Optional[str] = field(default=None)
    """Email address of user"""
    phone_number: Optional[str] = field(default=None)
    """Phone number of user"""
    company: Optional[str] = field(default=None)
    """Company of user"""
    identity_store: Optional[str] = field(default=None)
    """Identify store"""
    nad_address: Optional[str] = field(default=None)
    """IP address of NAD"""
    nas_ip_address: Optional[str] = field(default=None)
    """IP address of NAS"""
    user_details: Optional[str] = field(default=None)
    """Details of the user"""


@dataclass
class AuthorizationProfiles:
    """Displays all existing authorization profiles"""

    name: Optional[str] = field(default=None)
    """Name of the authorization profiles"""
    description: Optional[str] = field(default=None)
    """Description of the authorization profiles"""


@dataclass
class ChangeConfigurationAudit:
    """Displays the configuration audit data"""

    id: Optional[int] = field(default=None)
    """Database unique ID"""
    timestamp_timezone: Optional[datetime] = field(default=None)
    """Time with timezone when record added"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    ise_node: Optional[str] = field(default=None)
    """Hostname of ISE node"""
    message_code: Optional[str] = field(default=None)
    """Message code"""
    admin_name: Optional[str] = field(default=None)
    """Name of the admin who made config change"""
    nas_ip_address: Optional[str] = field(default=None)
    """IP address of NAD"""
    nas_ipv6_address: Optional[str] = field(default=None)
    """IPV6 address of NAD"""
    interface: Optional[str] = field(default=None)
    """Interface used for login GUI/CLI"""
    object_name: Optional[str] = field(default=None)
    """Name of object for which config is changed"""
    object_type: Optional[str] = field(default=None)
    """Type of object for which config is changed"""
    message_class: Optional[str] = field(default=None)
    """Message class"""
    event: Optional[str] = field(default=None)
    """Config change done"""
    requested_operation: Optional[str] = field(default=None)
    """Operation done"""
    operation_message_text: Optional[str] = field(default=None)
    """Operation details"""
    host_id: Optional[str] = field(default=None)
    """Hostname of ISE node on which change is done"""
    request_response_type: Optional[str] = field(default=None)
    """Type of request response"""
    failure_flag: Optional[str] = field(default=None)
    """Failure flag"""
    modified_properties: Optional[str] = field(default=None)
    """Modified properties"""
    details: Optional[str] = field(default=None)
    """Details of the event"""
    object_id: Optional[str] = field(default=None)
    """Object ID"""
    applied_to_acs_instance: Optional[str] = field(default=None)
    """ISE nodes to which change is applied"""
    local_mode: Optional[int] = field(default=None)
    """Local mode"""


@dataclass
class CoaEvents:
    """Log of change of authorization issued based on threat events received from various adapters"""

    logged_at: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was processed and stored by the Monitoring node"""
    coa_event_id: Optional[str] = field(default=None)
    """Specifies the COA event ID"""
    coa_status: Optional[str] = field(default=None)
    """Specifies the COA status"""
    calling_station_id: Optional[str] = field(default=None)
    """Specifies the calling station ID"""
    ip_address: Optional[str] = field(default=None)
    """Specifies the IP address"""
    username: Optional[str] = field(default=None)
    """Specifies the user name"""
    new_authz_rule: Optional[str] = field(default=None)
    """Specifies the Network Authorization Rule"""
    old_authz_profile: Optional[str] = field(default=None)
    """Specifies the old Authorization profile"""
    new_authz_profile: Optional[str] = field(default=None)
    """Specifies the new Authorization profile"""
    vendor_name: Optional[str] = field(default=None)
    """Specifies the vendor name"""
    incident_type: Optional[str] = field(default=None)
    """Specifies the incident type"""
    threat_events: Optional[str] = field(default=None)
    """Specifies the threat events"""
    operation_message_text: Optional[str] = field(default=None)
    """Specifies the operation message text"""


@dataclass
class EndpointsData:
    """Collection of all data related to endpoint that ISE collects"""

    id: Optional[str] = field(default=None)
    """Database unique ID"""
    mac_address: Optional[str] = field(default=None)
    """Specifies MAC address of the endpoint"""
    endpoint_policy: Optional[str] = field(default=None)
    """Specifies the profiling policy under which endpoint got profiled"""
    static_assignment: Optional[str] = field(default=None)
    """Specifies the endpoint static assignment status"""
    static_group_assignment: Optional[str] = field(default=None)
    """Specifies if endpoint statically assigned to user identity group"""
    identity_group_id: Optional[str] = field(default=None)
    """Specifies the unique ID of the User identity Group the endpoint belongs to"""
    endpoint_ip: Optional[str] = field(default=None)
    """Specifies the IP address of the endpoint"""
    endpoint_policy_version: Optional[int] = field(default=None)
    """The version of endpoint policy used"""
    matched_value: Optional[str] = field(default=None)
    """Matched Certainty Factor"""
    endpoint_policy_id: Optional[str] = field(default=None)
    """Specifies the unique ID of the endpoint policy used"""
    matched_policy_id: Optional[str] = field(default=None)
    """Specifies the ID of profiling used"""
    nmap_subnet_scanid: Optional[int] = field(default=None)
    """NMAP subnet can ID of end points"""
    portal_user: Optional[str] = field(default=None)
    """Specifies the portal user"""
    auth_store_id: Optional[str] = field(default=None)
    """Specifies the auth store ID"""
    device_registrations_status: Optional[int] = field(default=None)
    """Specifies if device is registered"""
    reg_timestamp: Optional[int] = field(default=None)
    """Specifies the registered timestamp"""
    posture_applicable: Optional[int] = field(default=None)
    """Specifies if Posture is Applicable"""
    create_time: Optional[datetime] = field(default=None)
    """Time when record added"""
    update_time: Optional[datetime] = field(default=None)
    """Time when record last updated"""
    profile_server: Optional[str] = field(default=None)
    """Specifies the ISE node that profiled the endpoint"""
    byod_reg: Optional[str] = field(default=None)
    """Specifies the BYOD Registration status"""
    hostname: Optional[str] = field(default=None)
    """Specifies the hostname of the endpoint"""
    version: Optional[int] = field(default=None)
    """Specifies the version"""
    posture_expiry: Optional[str] = field(default=None)
    """Specifies the posture expiry"""
    native_udid: Optional[str] = field(default=None)
    """Endpoint native UDID"""
    phone_id: Optional[str] = field(default=None)
    """Endpoint phone ID"""
    phone_id_type: Optional[str] = field(default=None)
    """Endpoint phone ID type"""
    mdm_server_id: Optional[str] = field(default=None)
    """Endpoint MDM server ID"""
    unique_subject_id: Optional[str] = field(default=None)
    """Endpoint subject ID"""
    mdm_guid: Optional[str] = field(default=None)
    """Endpoint MDM GUID"""
    endpoint_unique_id: Optional[str] = field(default=None)
    """Endpoint unique ID"""
    endpoint_id: Optional[str] = field(default=None)
    """Specifies the EPID of the endpoint"""
    probe_data: Optional[str] = field(default=None)
    """Specifies all the probe data acquired during profiling"""
    custom_attributes: Optional[str] = field(default=None)
    """Specifies the custom attributes"""


@dataclass
class EndpointIdentityGroups:
    """This will provide details of all the endpoint identity groups"""

    id: Optional[str] = field(default=None)
    """Database unique ID"""
    name: Optional[str] = field(default=None)
    """Name"""
    description: Optional[str] = field(default=None)
    """Description"""
    created_by: Optional[str] = field(default=None)
    """Name of the user"""
    create_time: Optional[datetime] = field(default=None)
    """Time of creation"""
    update_time: Optional[datetime] = field(default=None)
    """Time of updating"""
    status: Optional[str] = field(default=None)
    """Active/Inactive"""


@dataclass
class EndpointPurgeView:
    """Enables the user to review the history of endpoints purge activities"""

    id: Optional[int] = field(default=None)
    """Database unique ID"""
    endpoint_purge_id: Optional[str] = field(default=None)
    """Endpoint purge ID"""
    run_time: Optional[datetime] = field(default=None)
    """Run time"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    profiler_server: Optional[str] = field(default=None)
    """Profiler server"""
    endpoint_purge_rule: Optional[str] = field(default=None)
    """Endpoint purge rule"""
    endpoint_count: Optional[int] = field(default=None)
    """Number of endpoints"""


@dataclass
class ExtIdSrcActiveDirectory:
    """List of Active Directory Identity Stores"""

    name: Optional[str] = field(default=None)
    """Name of active directory"""


@dataclass
class ExtIdSrcCertAuthProfile:
    """List of Certificate Authentication Profiles"""

    name: Optional[str] = field(default=None)
    """Name of Certificate Authentication Profile"""
    description: Optional[str] = field(default=None)
    """Description of Certificate Authentication Profile"""


@dataclass
class ExtIdSrcLdap:
    """List of LDAP Identity Sources"""

    name: Optional[str] = field(default=None)
    """Name of LDAP Identity Store"""
    description: Optional[str] = field(default=None)
    """Description of LDAP Identity Store"""


@dataclass
class ExtIdSrcOdbc:
    """List of ODBC Identity Sources"""

    name: Optional[str] = field(default=None)
    """Name of ODBC Identity Store"""
    description: Optional[str] = field(default=None)
    """Description of ODBC Identity Store"""


@dataclass
class ExtIdSrcRadiusToken:
    """List of RADIUS Token Identity Sources"""

    name: Optional[str] = field(default=None)
    """Name of RADIUS Token Identity Sources"""
    description: Optional[str] = field(default=None)
    """Description of RADIUS Token Identity Sources"""


@dataclass
class ExtIdSrcRest:
    """List of REST ID Stores"""

    name: Optional[str] = field(default=None)
    """Name of REST ID store"""
    description: Optional[str] = field(default=None)
    """Description of REST ID store"""


@dataclass
class ExtIdSrcRsaSecurid:
    """List of RSA SecurID Identity Sources"""

    name: Optional[str] = field(default=None)
    """Name of RSA SecurID Identity Sources"""


@dataclass
class ExtIdSrcSamlIdProviders:
    """List of SAML Identity Providers"""

    name: Optional[str] = field(default=None)
    """Name of SAML Identity Providers"""
    description: Optional[str] = field(default=None)
    """Description of SAML Identity Providers"""


@dataclass
class ExtIdSrcSocialLogin:
    """List of Social Login Identity Stores"""

    name: Optional[str] = field(default=None)
    """Name of Social Login Identity Store"""
    description: Optional[str] = field(default=None)
    """Description of Social Login Identity Store"""


@dataclass
class FailureCodeCause:
    """Provides details of various failure causes and respective codes"""

    failure_code: Optional[str] = field(default=None)
    """Specifies the failure code"""
    failure_cause: Optional[str] = field(default=None)
    """Specifies the failure cause"""


@dataclass
class GuestAccounting:
    """Details of all users assigned to guest identity groups appear in this report"""

    logged_at: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was processed and stored by the Monitoring node"""
    identity: Optional[str] = field(default=None)
    """Specifies the identity of the user"""
    time_spent: Optional[str] = field(default=None)
    """Specifies the time spent"""
    logged_in: Optional[str] = field(default=None)
    """Specifies the logged in time"""
    logged_out: Optional[str] = field(default=None)
    """Specifies the logged out time"""
    endpoint_id: Optional[str] = field(default=None)
    """Specifies the endpoint ID"""
    ip_address: Optional[str] = field(default=None)
    """Specifies the IP address"""


@dataclass
class GuestDeviceloginAudit:
    """Tracks login activity by employees at the my device portal and device related operation performed by the users in the my device portal"""

    logged_at: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was processed and stored by the Monitoring node"""
    username: Optional[str] = field(default=None)
    """User name of user"""
    message_code: Optional[str] = field(default=None)
    """Syslog message code"""
    first_name: Optional[str] = field(default=None)
    """First Name of user"""
    last_name: Optional[str] = field(default=None)
    """Last Name of user"""
    identity_group: Optional[str] = field(default=None)
    """Identity group to which users belongs to"""
    email_address: Optional[str] = field(default=None)
    """Email address of the user"""
    phone_number: Optional[str] = field(default=None)
    """Phone Number of user"""
    company: Optional[str] = field(default=None)
    """Company of the user"""
    static_assignment: Optional[str] = field(default=None)
    """Specifies the endpoint static assignment status"""
    endpoint_profiler_server: Optional[str] = field(default=None)
    """ISE node which profiled the endpoint"""
    nad_address: Optional[str] = field(default=None)
    """IP address of NAD"""
    nas_ip_address: Optional[str] = field(default=None)
    """IP address of NAS"""
    identity_store_name: Optional[str] = field(default=None)
    """Specifies the name of the identity store"""
    identity_store_guid: Optional[str] = field(default=None)
    """ID of Identity store in which user belongs"""
    description: Optional[str] = field(default=None)
    """Description of user"""
    user_details: Optional[str] = field(default=None)
    """Details of the user"""
    portal_name: Optional[str] = field(default=None)
    """Name of guest portal used"""
    device_name: Optional[str] = field(default=None)
    """Name of device used"""
    device_details: Optional[str] = field(default=None)
    """Details of the device"""
    mac_address: Optional[str] = field(default=None)
    """MAC address of Device"""
    ip_address: Optional[str] = field(default=None)
    """IP address of Device"""
    operation: Optional[str] = field(default=None)
    """Operation that the user performed"""
    result: Optional[str] = field(default=None)
    """Status of the user operation"""
    failure_reason: Optional[str] = field(default=None)
    """Specifies the failure reason"""
    auth_identity_store: Optional[str] = field(default=None)
    """Specifies the authentication identity store"""
    server: Optional[str] = field(default=None)
    """Shows the name of the ISE node through which the access request is processed."""


@dataclass
class KeyPerformanceMetrics:
    """It will provides details of key performance metrics like average TPS, average load etc.,"""

    logged_time: Optional[datetime] = field(default=None)
    """Time data is collected"""
    ise_node: Optional[str] = field(default=None)
    """ISE Node in deployment"""
    radius_requests_hr: Optional[int] = field(default=None)
    """Number of radius requests per hour for selected PSN server"""
    logged_to_mnt_hr: Optional[int] = field(default=None)
    """Number of requests logged to MNT database for selected PSN server"""
    noise_hr: Optional[int] = field(default=None)
    """Calculated as difference between radius requests and logged to MnT per hour"""
    suppression_hr: Optional[int] = field(default=None)
    """Calculated as percentage of Noise w.r.t. radius requests per hour for selected PSN server"""
    avg_load: Optional[int] = field(default=None)
    """Average server load for selected server"""
    max_load: Optional[int] = field(default=None)
    """Maximum server load for selected server"""
    avg_latency_per_req: Optional[int] = field(default=None)
    """Average latency per radius request for selected PSN server"""
    avg_tps: Optional[int] = field(default=None)
    """Average transactions per second"""


@dataclass
class LogicalProfiles:
    """Displays all the logical profiles that exist along with their assigned policies"""

    logical_profile: Optional[str] = field(default=None)
    """Name of logical Profile"""
    system_type: Optional[str] = field(default=None)
    """Type of logical profile like admin created or Cisco provided"""
    description: Optional[str] = field(default=None)
    """Description"""
    assigned_policies: Optional[str] = field(default=None)
    """Profiling policy assigned to logical profile."""


@dataclass
class MisconfiguredNasView:
    """Provides information about NADs with inaccurate accounting frequency typically when sending accounting information frequently"""

    id: Optional[int] = field(default=None)
    """Database unique ID"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    ise_node: Optional[str] = field(default=None)
    """Displays the hostname of the ISE server"""
    message_code: Optional[int] = field(default=None)
    """Displays the message code"""
    nas_ip_address: Optional[str] = field(default=None)
    """IP address of NAS"""
    calling_station_id: Optional[str] = field(default=None)
    """Calling station ID"""
    detail_info: Optional[str] = field(default=None)
    """Displays the detailed info"""
    failed_attempts: Optional[str] = field(default=None)
    """Failed attempts"""
    failed_times: Optional[str] = field(default=None)
    """Failed times"""
    other_attributes: Optional[str] = field(default=None)
    """Other attributes"""
    nas_ipv6_address: Optional[str] = field(default=None)
    """NAS IPV6 address"""
    timestamp_timezone: Optional[datetime] = field(default=None)
    """Time with timezone when record added"""
    failed_times_hours: Optional[str] = field(default=None)
    """Failed times in hours"""
    message_text: Optional[str] = field(default=None)
    """Displays the message text"""


@dataclass
class MisconfiguredSupplicantsView:
    """Provides a list of mis-configured supplicants along with the statistics due to failed attempts that are performed by a specific supplicant"""

    message_text: Optional[str] = field(default=None)
    """Displays the message text"""
    framed_ipv6_address: Optional[str] = field(default=None)
    """Framed IPV6 address"""
    id: Optional[int] = field(default=None)
    """Database unique ID"""
    timestamp_timezone: Optional[datetime] = field(default=None)
    """Time with timezone when record added"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    ise_node: Optional[str] = field(default=None)
    """Displays the hostname of the ISE server"""
    message_code: Optional[int] = field(default=None)
    """Displays the message code"""
    username: Optional[str] = field(default=None)
    """User's claimed identity"""
    user_type: Optional[str] = field(default=None)
    """User type"""
    calling_station_id: Optional[str] = field(default=None)
    """Calling station ID"""
    access_service: Optional[str] = field(default=None)
    """Access service"""
    framed_ip_address: Optional[str] = field(default=None)
    """Framed IP address"""
    identity_store: Optional[str] = field(default=None)
    """Identity store"""
    identity_group: Optional[str] = field(default=None)
    """Identity group"""
    audit_session_id: Optional[str] = field(default=None)
    """Unique numeric string identifying the server session"""
    authentication_method: Optional[str] = field(default=None)
    """Authentication method"""
    authentication_protocol: Optional[str] = field(default=None)
    """Authentication protocol"""
    service_type: Optional[str] = field(default=None)
    """The Type of Service the user has requested"""
    network_device_name: Optional[str] = field(default=None)
    """Network device name"""
    device_type: Optional[str] = field(default=None)
    """Device type"""
    location: Optional[str] = field(default=None)
    """Location"""
    nas_ip_address: Optional[str] = field(default=None)
    """IP address of NAS"""
    nas_port_id: Optional[str] = field(default=None)
    """NAS port ID"""
    nas_port_type: Optional[str] = field(default=None)
    """NAS port type"""
    selected_authorization_profiles: Optional[str] = field(default=None)
    """Authorization profile used after authentication"""
    posture_status: Optional[str] = field(default=None)
    """Posture status"""
    security_group: Optional[str] = field(default=None)
    """Security group"""
    failure_reason: Optional[str] = field(default=None)
    """Failure reason"""
    response: Optional[str] = field(default=None)
    """Displays the response"""
    execution_steps: Optional[str] = field(default=None)
    """Execution steps"""
    other_attributes: Optional[str] = field(default=None)
    """Other attributes"""
    response_time: Optional[int] = field(default=None)
    """Response time"""
    passed: Optional[int] = field(default=None)
    """Passed flag"""
    failed: Optional[int] = field(default=None)
    """Failed flag"""
    credential_check: Optional[str] = field(default=None)
    """Credential check"""
    endpoint_profile: Optional[str] = field(default=None)
    """Endpoint matched profile"""
    mdm_server_name: Optional[str] = field(default=None)
    """MDM server name"""
    nas_ipv6_address: Optional[str] = field(default=None)
    """NAS IPV6 address"""


@dataclass
class NetworkAccessUsers:
    """List of all the internal users in ISE"""

    id: Optional[str] = field(default=None)
    """Database ID of Internal User"""
    status: Optional[str] = field(default=None)
    """Enabled or Disabled"""
    username: Optional[str] = field(default=None)
    """Name of User"""
    description: Optional[str] = field(default=None)
    """Description of User"""
    first_name: Optional[str] = field(default=None)
    """First Name of User"""
    last_name: Optional[str] = field(default=None)
    """Last Name of User"""
    email_address: Optional[str] = field(default=None)
    """Email Address of User"""
    identity_group: Optional[str] = field(default=None)
    """List of Identity Group ID to which user belongs"""
    is_admin: Optional[str] = field(default=None)
    """Shows if user is admin"""
    allow_password_change_after_login: Optional[int] = field(default=None)
    """Specifies if password change is allowed after login"""
    current_successful_login_time: Optional[str] = field(default=None)
    """Specifies the current successful login time"""
    last_successful_login_time: Optional[str] = field(default=None)
    """Specifies the last successful login time"""
    last_unsuccessful_login_time: Optional[str] = field(default=None)
    """Specifies the last unsuccessful login time"""
    success_login_ipaddress: Optional[str] = field(default=None)
    """Specifies the success login IP address"""
    failed_login_ipaddress: Optional[str] = field(default=None)
    """Specifies the failed login IP address"""
    expiry_date_enabled: Optional[int] = field(default=None)
    """Specifies the expiry date enabled"""
    expiry_date: Optional[int] = field(default=None)
    """Specifies the expiry date"""
    account_name_alias: Optional[str] = field(default=None)
    """Specifies the account name alias"""
    password_last_updated_on: Optional[int] = field(default=None)
    """Specifies when the password was last updated"""
    password_never_expires: Optional[int] = field(default=None)
    """Specifies if the password expired or not"""
    alarm_emailable: Optional[int] = field(default=None)
    """Specifies if the user receives system alarms"""


@dataclass
class NetworkDevices:
    """Gives the network device information which is configured in ISE"""

    id: Optional[str] = field(default=None)
    """Database unique ID"""
    name: Optional[str] = field(default=None)
    """Name"""
    ip_mask: Optional[str] = field(default=None)
    """IP address/mask"""
    profile_name: Optional[str] = field(default=None)
    """Name of the profile"""
    location: Optional[str] = field(default=None)
    """Device location"""
    type: Optional[str] = field(default=None)
    """Device type"""


@dataclass
class NetworkDeviceGroups:
    """This provides details of all the network device groups"""

    id: Optional[str] = field(default=None)
    """Database unique ID"""
    name: Optional[str] = field(default=None)
    """Name"""
    description: Optional[str] = field(default=None)
    """Description"""
    created_by: Optional[str] = field(default=None)
    """Name of the user"""
    create_time: Optional[datetime] = field(default=None)
    """Time of creation"""
    update_time: Optional[datetime] = field(default=None)
    """Time of updating"""
    active_status: Optional[str] = field(default=None)
    """Active/Inactive"""


@dataclass
class NodeList:
    """Provide information of all the nodes of deployment"""

    hostname: Optional[str] = field(default=None)
    """Hostname"""
    node_type: Optional[str] = field(default=None)
    """Personas enabled on the node"""
    gateway: Optional[str] = field(default=None)
    """Default gateway configured"""
    node_role: Optional[str] = field(default=None)
    """Standalone or multi-node"""
    active_status: Optional[str] = field(default=None)
    """Active/Inactive"""
    replication_status: Optional[str] = field(default=None)
    """Status of replication"""
    pdp_services: Optional[str] = field(default=None)
    """Services enabled on the node"""
    host_alias: Optional[str] = field(default=None)
    """FQDN"""
    create_time: Optional[datetime] = field(default=None)
    """Time of creation of record"""
    update_time: Optional[datetime] = field(default=None)
    """Time of updating"""
    xgrid_enabled: Optional[int] = field(default=None)
    """PxGrid enabled status"""
    xgrid_peer: Optional[str] = field(default=None)
    """PxGrid peer"""
    udi_pid: Optional[str] = field(default=None)
    """Product Identifier"""
    udi_vid: Optional[str] = field(default=None)
    """Version Identifier"""
    udi_sn: Optional[str] = field(default=None)
    """Serial Number"""
    udi_pt: Optional[str] = field(default=None)
    """Node type virtual or physical"""
    patch_version: Optional[str] = field(default=None)
    """Patch version"""
    pic_node: Optional[int] = field(default=None)
    """PIC node"""
    installation_type: Optional[str] = field(default=None)
    """Installation type"""
    vm_info: Optional[str] = field(default=None)
    """Virtual machine details"""
    api_node: Optional[int] = field(default=None)
    """API node"""


@dataclass
class OpenapiOperations:
    """Provides details about any configuration changes or data access performed using the OpenAPI framework"""

    logged_at: Optional[datetime] = field(default=None)
    """Time when record logged"""
    message_text: Optional[str] = field(default=None)
    """Displays the message text"""
    request_time: Optional[datetime] = field(default=None)
    """Displays the request time"""
    request_name: Optional[str] = field(default=None)
    """Displays the request name"""
    http_method: Optional[str] = field(default=None)
    """Displays the http method"""
    request_id: Optional[str] = field(default=None)
    """Displays the request ID"""
    request_body: Optional[str] = field(default=None)
    """Displays the request body"""
    response: Optional[str] = field(default=None)
    """Displays the response"""
    http_code: Optional[int] = field(default=None)
    """Displays the http code"""
    http_status: Optional[str] = field(default=None)
    """Displays the http status"""
    error_message: Optional[str] = field(default=None)
    """Displays the error if any"""
    server: Optional[str] = field(default=None)
    """Displays the ISE hostname"""
    response_duration: Optional[int] = field(default=None)
    """Displays the response duration"""
    client_ip: Optional[str] = field(default=None)
    """Displays the client IP address"""
    administrator: Optional[str] = field(default=None)
    """Displays the admin name"""


@dataclass
class PolicySets:
    """Provides a list of all policy sets currently configured in the system"""

    id: Optional[str] = field(default=None)
    """Database unique ID"""
    create_time: Optional[datetime] = field(default=None)
    """Time when record was created"""
    update_time: Optional[datetime] = field(default=None)
    """Time when record was last updated"""
    policyset_status: Optional[str] = field(default=None)
    """Specifies if the policy set status is active"""
    policyset_name: Optional[str] = field(default=None)
    """Specifies the policy set name"""
    description: Optional[str] = field(default=None)
    """Specifies the policy sets description"""


@dataclass
class PostureAssessmentByCondition:
    """The report provides details about policy condition and their status"""

    logged_at: Optional[datetime] = field(default=None)
    """Specifies the time at which policy was enforced"""
    policy: Optional[str] = field(default=None)
    """Specifies the posture policy"""
    policy_status: Optional[str] = field(default=None)
    """Displays the policy condition status"""
    enforcement_name: Optional[str] = field(default=None)
    """Displays the posture requirement name"""
    enforcement_type: Optional[str] = field(default=None)
    """Enforcement type of the requirement i.e. mandatory, optional or audit"""
    enforcement_status: Optional[str] = field(default=None)
    """Displays the status of the posture requirement enforcement"""
    ise_node: Optional[str] = field(default=None)
    """Displays the hostname of the ISE server"""
    message_code: Optional[str] = field(default=None)
    """Displays the message code of the posture syslog"""
    request_time: Optional[str] = field(default=None)
    """Displays the request time"""
    response_time: Optional[str] = field(default=None)
    """Displays the response time"""
    endpoint_id: Optional[str] = field(default=None)
    """Endpoint MAC address"""
    endpoint_os: Optional[str] = field(default=None)
    """Endpoint operating system"""
    posture_agent_version: Optional[str] = field(default=None)
    """Displays the version of the posture agent"""
    posture_status: Optional[str] = field(default=None)
    """Posture status i.e. pending, compliant, non-compliant etc"""
    posture_policy_matched: Optional[str] = field(default=None)
    """Displays the posture policy matched"""
    posture_report: Optional[str] = field(default=None)
    """Displays the posture report"""
    anti_virus_installed: Optional[str] = field(default=None)
    """Displays the installed anti-virus"""
    anti_spyware_installed: Optional[str] = field(default=None)
    """Displays the installed anti-spyware"""
    failure_reason: Optional[str] = field(default=None)
    """Specifies the reason for failure"""
    pra_enforcement: Optional[int] = field(default=None)
    """Displays the status of periodic reassessment enforcement"""
    pra_interval: Optional[int] = field(default=None)
    """Periodic reassessment interval configured"""
    pra_action: Optional[str] = field(default=None)
    """Periodic reassessment action configured"""
    pra_grace_time: Optional[str] = field(default=None)
    """Periodic reassessment grace time configured"""
    identity: Optional[str] = field(default=None)
    """Displays the user name"""
    session_id: Optional[str] = field(default=None)
    """Shows the session ID"""
    feed_url: Optional[str] = field(default=None)
    """Shows the update feed URL"""
    num_of_updates: Optional[int] = field(default=None)
    """Displays the number of updates"""
    user_agreement_status: Optional[str] = field(default=None)
    """Displays the status of the user agreement"""
    system_name: Optional[str] = field(default=None)
    """Hostname of the endpoint"""
    system_domain: Optional[str] = field(default=None)
    """Displays the domain name of the endpoint"""
    system_user: Optional[str] = field(default=None)
    """Displays the system user"""
    system_user_domain: Optional[str] = field(default=None)
    """Displays the system user domain"""
    ip_address: Optional[str] = field(default=None)
    """IP address of the endpoint"""
    am_installed: Optional[str] = field(default=None)
    """Displays the anti-malware installed on the endpoint"""
    condition_name: Optional[str] = field(default=None)
    """Specifies the posture condition which was matched"""
    condition_status: Optional[str] = field(default=None)
    """Displays the status of the condition i.e. passed, failed or skipped"""
    location: Optional[str] = field(default=None)
    """Displays the network device group location"""


@dataclass
class PostureAssessmentByEndpoint:
    """This view shows which endpoints have been subject to posture assessment and also gives the administrator the ability to view the details of each endpoint's posture assessment"""

    id: Optional[int] = field(default=None)
    """Database unique ID"""
    timestamp_timezone: Optional[datetime] = field(default=None)
    """Time with timezone when record added"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    ise_node: Optional[str] = field(default=None)
    """Hostname of ISE node"""
    message_code: Optional[str] = field(default=None)
    """Displays the message code of the posture syslog"""
    request_time: Optional[str] = field(default=None)
    """Displays the request time"""
    response_time: Optional[str] = field(default=None)
    """Displays the response time"""
    endpoint_mac_address: Optional[str] = field(default=None)
    """MAC address of the endpoint"""
    endpoint_operating_system: Optional[str] = field(default=None)
    """Operating system of the endpoint"""
    posture_agent_version: Optional[str] = field(default=None)
    """Displays the version of the posture agent"""
    posture_status: Optional[str] = field(default=None)
    """Posture status i.e. pending, compliant, non-compliant etc"""
    posture_policy_matched: Optional[str] = field(default=None)
    """Displays the posture policy matched"""
    posture_report: Optional[str] = field(default=None)
    """Displays the posture report"""
    anti_virus_installed: Optional[str] = field(default=None)
    """Displays the installed anti-virus"""
    anti_spyware_installed: Optional[str] = field(default=None)
    """Displays the installed anti-spyware"""
    failure_reason: Optional[str] = field(default=None)
    """Specifies the reason for failure"""
    pra_enforcement_flag: Optional[int] = field(default=None)
    """Displays the status of periodic reassessment enforcement"""
    pra_interval: Optional[int] = field(default=None)
    """Periodic reassessment interval configured"""
    pra_action: Optional[str] = field(default=None)
    """Periodic reassessment action configured"""
    username: Optional[str] = field(default=None)
    """Displays the username"""
    session_id: Optional[str] = field(default=None)
    """Shows the session ID"""
    feed_url: Optional[str] = field(default=None)
    """Shows the update feed URL"""
    num_of_updates: Optional[int] = field(default=None)
    """Number of updates"""
    user_agreement_status: Optional[str] = field(default=None)
    """Displays the status of the user agreement"""
    system_name: Optional[str] = field(default=None)
    """Hostname of the endpoint"""
    system_domain: Optional[str] = field(default=None)
    """Displays the domain name of the endpoint"""
    system_user: Optional[str] = field(default=None)
    """Displays the system user"""
    system_user_domain: Optional[str] = field(default=None)
    """Displays the system user domain"""
    ip_address: Optional[str] = field(default=None)
    """IP address of the endpoint"""
    pra_grace_time: Optional[str] = field(default=None)
    """Periodic reassessment grace time configured"""
    nad_location: Optional[str] = field(default=None)
    """Location of NAD"""
    am_installed: Optional[str] = field(default=None)
    """Displays the anti-malware installed on the endpoint"""
    message_text: Optional[str] = field(default=None)
    """Displays the message text"""


@dataclass
class PostureGracePeriod:
    """Lists the MAC address and the  posture grace period expiration"""

    mac_list: Optional[str] = field(default=None)
    """Specifies the list of MAC address"""
    last_grace_expiry: Optional[str] = field(default=None)
    """Specifies the posture grace period expiration time"""


@dataclass
class PostureScriptCondition:
    """Provides execution status for each requirement that uses script condition."""

    logged_at: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was processed and stored by the Monitoring node"""
    ise_node: Optional[str] = field(default=None)
    """The name of the ISE Node"""
    status: Optional[str] = field(default=None)
    """The execution status of the condition"""
    policy_name: Optional[str] = field(default=None)
    """The name of the policy being applied"""
    requirement_name: Optional[str] = field(default=None)
    """The name of the requirement"""
    session_id: Optional[str] = field(default=None)
    """The Session ID"""
    endpoint_id: Optional[str] = field(default=None)
    """The Endpoint ID"""
    udid: Optional[str] = field(default=None)
    """The UDID"""
    condition_name: Optional[str] = field(default=None)
    """The name of the condition"""


@dataclass
class PostureScriptRemediation:
    """Provides execution status for each requirement that uses script  remediation."""

    logged_at: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was processed and stored by the Monitoring node"""
    ise_node: Optional[str] = field(default=None)
    """The name of the ISE Node"""
    status: Optional[str] = field(default=None)
    """The execution status of the remediation"""
    policy_name: Optional[str] = field(default=None)
    """The name of the policy being applied"""
    requirement_name: Optional[str] = field(default=None)
    """The name of the requirement"""
    session_id: Optional[str] = field(default=None)
    """The Session ID"""
    endpoint_id: Optional[str] = field(default=None)
    """The Endpoint ID"""
    udid: Optional[str] = field(default=None)
    """The UDID"""


@dataclass
class PrimaryGuest:
    """The Primary Guest report combines data from various guest reports into a single view. This report collects all guest activity and provides details about the website guest users visit"""

    mac_address: Optional[str] = field(default=None)
    """Specifies the MAC address"""
    ip_address: Optional[str] = field(default=None)
    """Specifies the IP address"""
    sponsor_username: Optional[str] = field(default=None)
    """Specifies the sponsor user name"""
    guest_username: Optional[str] = field(default=None)
    """Specifies the guest user name"""
    guest_users: Optional[str] = field(default=None)
    """Specifies the guest users"""
    operation: Optional[str] = field(default=None)
    """Specifies the operation"""
    aup_acceptance: Optional[str] = field(default=None)
    """Specifies the AUP acceptance"""
    logged_at: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was stored"""
    message: Optional[str] = field(default=None)
    """Message for guest"""
    portal_name: Optional[str] = field(default=None)
    """Specifies the portal name"""
    result: Optional[str] = field(default=None)
    """Specifies the result"""
    sponsor_first_name: Optional[str] = field(default=None)
    """Specifies the sponsor first name"""
    sponsor_last_name: Optional[str] = field(default=None)
    """Specifies the sponsor last name"""
    identity_group: Optional[str] = field(default=None)
    """Specifies the identity group to which user belongs"""
    sponsor_email_address: Optional[str] = field(default=None)
    """Specifies the sponsor email address"""
    sponsor_phone_number: Optional[str] = field(default=None)
    """Specifies the sponsor phone number"""
    sponsor_company: Optional[str] = field(default=None)
    """Specifies the sponsor company"""
    guest_last_name: Optional[str] = field(default=None)
    """Specifies the guest last name"""
    guest_first_name: Optional[str] = field(default=None)
    """Specifies the guest first name"""
    guest_email_address: Optional[str] = field(default=None)
    """Specifies the guest email address"""
    guest_phone_number: Optional[str] = field(default=None)
    """Specifies the guest phone number"""
    guest_company: Optional[str] = field(default=None)
    """Specifies the guest company"""
    guest_status: Optional[str] = field(default=None)
    """Specifies the guest status"""
    guest_type: Optional[str] = field(default=None)
    """Specifies the guest type"""
    valid_days: Optional[str] = field(default=None)
    """Specifies the number of days guest user is valid"""
    from_date: Optional[str] = field(default=None)
    """Specifies the start date of the guest user"""
    to_date: Optional[str] = field(default=None)
    """Specifies the end date of the guest user"""
    location: Optional[str] = field(default=None)
    """Specifies the location of the guest user"""
    ssid: Optional[str] = field(default=None)
    """Specifies the SSID of guest user"""
    group_tag: Optional[str] = field(default=None)
    """Specifies the group tag of guest user"""
    guest_person_visited: Optional[str] = field(default=None)
    """Specifies the guest person visited"""
    guest_reason_for_visit: Optional[str] = field(default=None)
    """Specifies the guest reason for visit"""
    nas_ip_address: Optional[str] = field(default=None)
    """Specifies the NAS IP address"""
    user_link: Optional[str] = field(default=None)
    """Specifies the user link"""
    guest_link: Optional[str] = field(default=None)
    """Specifies the guest link"""
    failure_reason: Optional[str] = field(default=None)
    """Specifies the reason for failure"""
    time_spent: Optional[str] = field(default=None)
    """Specifies the time spent"""
    logged_in: Optional[str] = field(default=None)
    """Specifies when logged in"""
    logged_out: Optional[str] = field(default=None)
    """Specifies when logged out"""
    optional_data: Optional[str] = field(default=None)
    """Specifies the optional data"""
    identity_store: Optional[str] = field(default=None)
    """Specifies the identity store to which the user belongs"""
    nad_address: Optional[str] = field(default=None)
    """Specifies the NAD address"""
    server: Optional[str] = field(default=None)
    """Specifies the ISE node"""
    sponsor_user_details: Optional[str] = field(default=None)
    """Specifies the sponsor user details"""
    guest_user_details: Optional[str] = field(default=None)
    """Specifies the guest user details"""
    details: Optional[str] = field(default=None)
    """Specifies the details"""


@dataclass
class ProfiledEndpointsSummary:
    """Displays profiling details about endpoints that are accessing the network"""

    id: Optional[int] = field(default=None)
    """Database unique ID"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    endpoint_id: Optional[str] = field(default=None)
    """Endpoint ID"""
    endpoint_profile: Optional[str] = field(default=None)
    """Endpoint profile"""
    source: Optional[str] = field(default=None)
    """Source name"""
    host: Optional[str] = field(default=None)
    """Host name"""
    endpoint_action_name: Optional[str] = field(default=None)
    """Endpoint action name"""
    message_code: Optional[str] = field(default=None)
    """Message code"""
    identity_group: Optional[str] = field(default=None)
    """Identity group name"""


@dataclass
class ProfilingPolicies:
    """List and details of all endpoint profiles present on ISE"""

    profiling_policy_name: Optional[str] = field(default=None)
    """Name of Profiling Policy"""
    description: Optional[str] = field(default=None)
    """Description of Profiling Policy"""


@dataclass
class PxgridDirectData:
    """None"""

    edda_id: Optional[str] = field(default=None)
    """The correlation identifier as specified in the connector configuration"""
    connector_type: Optional[str] = field(default=None)
    unique_id: Optional[str] = field(default=None)
    """The unique identifier as specified in the connector configuration"""
    create_time: Optional[str] = field(default=None)
    bulk_id: Optional[str] = field(default=None)
    version: Optional[str] = field(default=None)
    version_type: Optional[str] = field(default=None)
    name: Optional[str] = field(default=None)
    data: Optional[str] = field(default=None)


@dataclass
class RadiusAccounting:
    """This provides details of all the radius accounting records"""

    id: Optional[int] = field(default=None)
    """Database unique ID"""
    timestamp_timezone: Optional[datetime] = field(default=None)
    """Time with timezone when record added"""
    ise_node: Optional[str] = field(default=None)
    """ISE node"""
    syslog_message_code: Optional[str] = field(default=None)
    """Message code"""
    session_id: Optional[str] = field(default=None)
    """Session ID"""
    username: Optional[str] = field(default=None)
    """User's claimed identity"""
    user_type: Optional[str] = field(default=None)
    """User type"""
    calling_station_id: Optional[str] = field(default=None)
    """Calling station ID"""
    acct_session_id: Optional[str] = field(default=None)
    """Unique numeric string identifying the server session"""
    acct_status_type: Optional[str] = field(default=None)
    """Specifies whether accounting packet starts or stops a bridging, routing, or terminal server session."""
    acct_session_time: Optional[int] = field(default=None)
    """Length of time (in seconds) for which the session has been logged in"""
    service_type: Optional[str] = field(default=None)
    """The Type of Service the user has requested"""
    framed_protocol: Optional[str] = field(default=None)
    """Framed protocol"""
    acct_input_octets: Optional[str] = field(default=None)
    """Number of octets received during the session"""
    acct_output_octets: Optional[str] = field(default=None)
    """Number of octets sent during the session"""
    acct_input_packets: Optional[int] = field(default=None)
    """Number of packets received during the session"""
    acct_output_packets: Optional[int] = field(default=None)
    """Number of octets sent during the session"""
    framed_ip_address: Optional[str] = field(default=None)
    """Framed IP address"""
    nas_port: Optional[str] = field(default=None)
    """Physical port number of the NAS (Network Access Server) originating the request"""
    nas_ip_address: Optional[str] = field(default=None)
    """The IP address of the NAS originating the request"""
    acct_terminate_cause: Optional[str] = field(default=None)
    """Reason a connection was terminated"""
    access_service: Optional[str] = field(default=None)
    """Access service"""
    audit_session_id: Optional[str] = field(default=None)
    """Audit session ID"""
    acct_multi_session_id: Optional[str] = field(default=None)
    """Multi session ID"""
    acct_authentic: Optional[str] = field(default=None)
    """Authentication"""
    termination_action: Optional[str] = field(default=None)
    """0 Default 1 RADIUS-Request"""
    session_timeout: Optional[str] = field(default=None)
    """Session timeout"""
    idle_timeout: Optional[str] = field(default=None)
    """Idle timeout"""
    acct_interim_interval: Optional[str] = field(default=None)
    """Number of seconds between each transmittal of an interim update for a specific session"""
    acct_delay_time: Optional[str] = field(default=None)
    """Length of time (in seconds) for which the NAS has been sending the same accounting packet"""
    event_timestamp: Optional[str] = field(default=None)
    """The date and time that this event occurred on the NAS"""
    nas_identifier: Optional[str] = field(default=None)
    """NAS ID"""
    nas_port_id: Optional[str] = field(default=None)
    """NAS port ID"""
    acct_tunnel_connection: Optional[str] = field(default=None)
    """Tunnel connection"""
    acct_tunnel_packet_lost: Optional[str] = field(default=None)
    """Packet lost"""
    device_name: Optional[str] = field(default=None)
    """Network device name"""
    device_groups: Optional[str] = field(default=None)
    """Network device group"""
    service_selection_policy: Optional[str] = field(default=None)
    """Service selection policy"""
    identity_store: Optional[str] = field(default=None)
    """Identity store"""
    ad_domain: Optional[str] = field(default=None)
    """AD domain"""
    identity_group: Optional[str] = field(default=None)
    """Identity group"""
    authorization_policy: Optional[str] = field(default=None)
    """Authorization policy"""
    failure_reason: Optional[str] = field(default=None)
    """Failure reason"""
    security_group: Optional[str] = field(default=None)
    """Security group"""
    cisco_h323_setup_time: Optional[datetime] = field(default=None)
    """Cisco H323 setup time"""
    cisco_h323_connect_time: Optional[datetime] = field(default=None)
    """Cisco H323 connect time"""
    cisco_h323_disconnect_time: Optional[datetime] = field(default=None)
    """Cisco H323 disconnect time"""
    response_time: Optional[int] = field(default=None)
    """Response time"""
    started: Optional[int] = field(default=None)
    """Started"""
    stopped: Optional[int] = field(default=None)
    """Stopped"""
    nas_ipv6_address: Optional[str] = field(default=None)
    """NAS IPV6 address"""
    framed_ipv6_address: Optional[str] = field(default=None)
    """FRAMED IPV6 address"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    vn: Optional[str] = field(default=None)
    """Information of Virtual Network"""


@dataclass
class RadiusAccountingWeek:
    """This is performance oriented view which contains all the radius accounting records for the last seven days"""

    id: Optional[int] = field(default=None)
    """Database unique ID"""
    timestamp_timezone: Optional[datetime] = field(default=None)
    """Time with timezone when record added"""
    ise_node: Optional[str] = field(default=None)
    """ISE node"""
    syslog_message_code: Optional[str] = field(default=None)
    """Message code"""
    session_id: Optional[str] = field(default=None)
    """Established ISE session ID"""
    username: Optional[str] = field(default=None)
    """User's claimed identity"""
    user_type: Optional[str] = field(default=None)
    """User type"""
    calling_station_id: Optional[str] = field(default=None)
    """Calling station ID"""
    acct_session_id: Optional[str] = field(default=None)
    """Unique numeric string identifying the server session"""
    acct_status_type: Optional[str] = field(default=None)
    """Specifies whether accounting packet starts or stops a bridging, routing, or terminal server session."""
    acct_session_time: Optional[int] = field(default=None)
    """Length of time (in seconds) for which the session has been logged in"""
    service_type: Optional[str] = field(default=None)
    """The Type of Service the user has requested"""
    framed_protocol: Optional[str] = field(default=None)
    """Framed protocol"""
    acct_input_octets: Optional[str] = field(default=None)
    """Number of octets received during the session"""
    acct_output_octets: Optional[str] = field(default=None)
    """Number of octets sent during the session"""
    acct_input_packets: Optional[int] = field(default=None)
    """Number of packets received during the session"""
    acct_output_packets: Optional[int] = field(default=None)
    """Number of octets sent during the session"""
    framed_ip_address: Optional[str] = field(default=None)
    """Framed IP address"""
    nas_port: Optional[str] = field(default=None)
    """Physical port number of the NAS (Network Access Server) originating the request"""
    nas_ip_address: Optional[str] = field(default=None)
    """The IP address of the NAS originating the request"""
    acct_terminate_cause: Optional[str] = field(default=None)
    """Reason a connection was terminated"""
    access_service: Optional[str] = field(default=None)
    """Access service"""
    audit_session_id: Optional[str] = field(default=None)
    """Audit session ID"""
    acct_multi_session_id: Optional[str] = field(default=None)
    """Multi session ID"""
    acct_authentic: Optional[str] = field(default=None)
    """Authentication"""
    termination_action: Optional[str] = field(default=None)
    """0 Default 1 RADIUS-Request"""
    session_timeout: Optional[str] = field(default=None)
    """Session timeout"""
    idle_timeout: Optional[str] = field(default=None)
    """Idle timeout"""
    acct_interim_interval: Optional[str] = field(default=None)
    """Number of seconds between each transmittal of an interim update for a specific session"""
    acct_delay_time: Optional[str] = field(default=None)
    """Length of time (in seconds) for which the NAS has been sending the same accounting packet"""
    event_timestamp: Optional[str] = field(default=None)
    """The date and time that this event occurred on the NAS"""
    nas_identifier: Optional[str] = field(default=None)
    """NAS ID"""
    nas_port_id: Optional[str] = field(default=None)
    """NAS port ID"""
    acct_tunnel_connection: Optional[str] = field(default=None)
    """Tunnel connection"""
    acct_tunnel_packet_lost: Optional[str] = field(default=None)
    """Packet lost"""
    device_name: Optional[str] = field(default=None)
    """Network device name"""
    device_groups: Optional[str] = field(default=None)
    """Network device group"""
    service_selection_policy: Optional[str] = field(default=None)
    """Service selection policy"""
    identity_store: Optional[str] = field(default=None)
    """Identity store"""
    ad_domain: Optional[str] = field(default=None)
    """AD domain"""
    identity_group: Optional[str] = field(default=None)
    """Identity group"""
    authorization_policy: Optional[str] = field(default=None)
    """Displays the authorization policy matched"""
    failure_reason: Optional[str] = field(default=None)
    """Failure reason"""
    security_group: Optional[str] = field(default=None)
    """Security group"""
    cisco_h323_setup_time: Optional[datetime] = field(default=None)
    """Cisco H323 setup time"""
    cisco_h323_connect_time: Optional[datetime] = field(default=None)
    """Cisco H323 connect time"""
    cisco_h323_disconnect_time: Optional[datetime] = field(default=None)
    """Cisco H323 disconnect time"""
    response_time: Optional[int] = field(default=None)
    """Response time"""
    started: Optional[int] = field(default=None)
    """Started"""
    stopped: Optional[int] = field(default=None)
    """Stopped"""
    nas_ipv6_address: Optional[str] = field(default=None)
    """NAS IPV6 address"""
    framed_ipv6_address: Optional[str] = field(default=None)
    """Framed IPV6 address"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    vn: Optional[str] = field(default=None)
    """Information of Virtual Network"""


@dataclass
class RadiusAuthentications:
    """This provides details of all the radius authentication records"""

    id: Optional[int] = field(default=None)
    """Database unique ID"""
    timestamp_timezone: Optional[datetime] = field(default=None)
    """Time with timezone when record added"""
    ise_node: Optional[str] = field(default=None)
    """ISE node"""
    syslog_message_code: Optional[int] = field(default=None)
    """Message code"""
    username: Optional[str] = field(default=None)
    """User's claimed identity"""
    user_type: Optional[str] = field(default=None)
    """User type"""
    calling_station_id: Optional[str] = field(default=None)
    """Calling station ID"""
    access_service: Optional[str] = field(default=None)
    """Access service"""
    framed_ip_address: Optional[str] = field(default=None)
    """Framed IP address of user"""
    identity_store: Optional[str] = field(default=None)
    """Identity store of user"""
    identity_group: Optional[str] = field(default=None)
    """User identity group"""
    audit_session_id: Optional[str] = field(default=None)
    """Audit session ID"""
    authentication_method: Optional[str] = field(default=None)
    """Method of authentication"""
    authentication_protocol: Optional[str] = field(default=None)
    """Protocol of authentication"""
    service_type: Optional[str] = field(default=None)
    """The Type of Service the user has requested"""
    device_name: Optional[str] = field(default=None)
    """Network device name"""
    device_type: Optional[str] = field(default=None)
    """Network device type"""
    location: Optional[str] = field(default=None)
    """Network device location"""
    nas_ip_address: Optional[str] = field(default=None)
    """The IP address of the NAS originating the request"""
    nas_port_id: Optional[str] = field(default=None)
    """Physical port number of the NAS (Network Access Server) originating the request"""
    nas_port_type: Optional[str] = field(default=None)
    """NAS port type"""
    authorization_profiles: Optional[str] = field(default=None)
    """Authorization profiles"""
    posture_status: Optional[str] = field(default=None)
    """Posture status"""
    security_group: Optional[str] = field(default=None)
    """Security group"""
    failure_reason: Optional[str] = field(default=None)
    """Reason of failure"""
    response_time: Optional[int] = field(default=None)
    """Response time"""
    passed: Optional[str] = field(default=None)
    """Passed flag"""
    failed: Optional[int] = field(default=None)
    """Failed flag"""
    credential_check: Optional[str] = field(default=None)
    """Credential check"""
    endpoint_profile: Optional[str] = field(default=None)
    """Endpoint matched profile"""
    mdm_server_name: Optional[str] = field(default=None)
    """MDM server name"""
    policy_set_name: Optional[str] = field(default=None)
    """Policy set name"""
    authorization_rule: Optional[str] = field(default=None)
    """Authorization rule"""
    nas_ipv6_address: Optional[str] = field(default=None)
    """NAS IPV6 address"""
    framed_ipv6_address: Optional[str] = field(default=None)
    """Framed ipv6 address"""
    orig_calling_station_id: Optional[str] = field(default=None)
    """Calling station ID"""
    checksum: Optional[str] = field(default=None)
    """Checksum"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""


@dataclass
class RadiusAuthenticationsWeek:
    """This is performance oriented view which contains all the radius authentication records for the last seven days"""

    id: Optional[int] = field(default=None)
    """Database unique ID"""
    timestamp_timezone: Optional[datetime] = field(default=None)
    """Time with timezone when record added"""
    ise_node: Optional[str] = field(default=None)
    """ISE node"""
    syslog_message_code: Optional[int] = field(default=None)
    """Message code"""
    username: Optional[str] = field(default=None)
    """User's claimed identity"""
    user_type: Optional[str] = field(default=None)
    """User type"""
    calling_station_id: Optional[str] = field(default=None)
    """Calling station ID"""
    access_service: Optional[str] = field(default=None)
    """Access service"""
    framed_ip_address: Optional[str] = field(default=None)
    """Framed IP address of user"""
    identity_store: Optional[str] = field(default=None)
    """Identity store of user"""
    identity_group: Optional[str] = field(default=None)
    """User identity group"""
    audit_session_id: Optional[str] = field(default=None)
    """Audit session ID"""
    authentication_method: Optional[str] = field(default=None)
    """Method of authentication"""
    authentication_protocol: Optional[str] = field(default=None)
    """Protocol of authentication"""
    service_type: Optional[str] = field(default=None)
    """The Type of Service the user has requested"""
    device_name: Optional[str] = field(default=None)
    """Network device name"""
    device_type: Optional[str] = field(default=None)
    """Network device type"""
    location: Optional[str] = field(default=None)
    """Network device location"""
    nas_ip_address: Optional[str] = field(default=None)
    """The IP address of the NAS originating the request"""
    nas_port_id: Optional[str] = field(default=None)
    """Physical port number of the NAS (Network Access Server) originating the request"""
    nas_port_type: Optional[str] = field(default=None)
    """NAS port type"""
    authorization_profiles: Optional[str] = field(default=None)
    """Authorization profiles"""
    posture_status: Optional[str] = field(default=None)
    """Posture status"""
    security_group: Optional[str] = field(default=None)
    """Security group"""
    failure_reason: Optional[str] = field(default=None)
    """Reason of failure"""
    response_time: Optional[int] = field(default=None)
    """Response time"""
    passed: Optional[int] = field(default=None)
    """Passed flag"""
    failed: Optional[int] = field(default=None)
    """Failed flag"""
    credential_check: Optional[str] = field(default=None)
    """Credential check"""
    endpoint_profile: Optional[str] = field(default=None)
    """Endpoint matched profile"""
    mdm_server_name: Optional[str] = field(default=None)
    """MDM server name"""
    policy_set_name: Optional[str] = field(default=None)
    """Policy set name"""
    authorization_rule: Optional[str] = field(default=None)
    """Authorization rule"""
    nas_ipv6_address: Optional[str] = field(default=None)
    """NAS IPV6 address"""
    framed_ipv6_address: Optional[str] = field(default=None)
    """Framed ipv6 address"""
    orig_calling_station_id: Optional[str] = field(default=None)
    """Calling station ID"""
    checksum: Optional[str] = field(default=None)
    """Checksum"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    authentication_policy: Optional[str] = field(default=None)
    """Displays the authentication policy matched"""
    authorization_policy: Optional[str] = field(default=None)
    """Displays the authorization policy matched"""
    nad_profile_name: Optional[str] = field(default=None)
    """Displays the network device profile"""


@dataclass
class RadiusAuthenticationSummary:
    """Displays an aggregate view of radius authentications"""

    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    ise_node: Optional[str] = field(default=None)
    """ISE node"""
    username: Optional[str] = field(default=None)
    """User name"""
    calling_station_id: Optional[str] = field(default=None)
    """Calling station ID"""
    identity_store: Optional[str] = field(default=None)
    """Identity store"""
    identity_group: Optional[str] = field(default=None)
    """Identity group"""
    device_name: Optional[str] = field(default=None)
    """Network device name"""
    device_type: Optional[str] = field(default=None)
    """Network device type"""
    location: Optional[str] = field(default=None)
    """Network device location"""
    access_service: Optional[str] = field(default=None)
    """Access service"""
    nas_port_id: Optional[str] = field(default=None)
    """NAS port ID"""
    authorization_profiles: Optional[str] = field(default=None)
    """Authorization profile"""
    failure_reason: Optional[str] = field(default=None)
    """Reason of failure"""
    security_group: Optional[str] = field(default=None)
    """Security group"""
    total_response_time: Optional[int] = field(default=None)
    """Total response time"""
    max_response_time: Optional[int] = field(default=None)
    """Max response time"""
    passed_count: Optional[int] = field(default=None)
    """Number of passed authentication"""
    failed_count: Optional[int] = field(default=None)
    """Number of failed authentication"""


@dataclass
class RadiusErrorsView:
    """Enables you to check for RADIUS Requests Dropped, EAP connection time outs and unknown NADs"""

    authentication_policy: Optional[str] = field(default=None)
    """Authentication policy"""
    authorization_policy: Optional[str] = field(default=None)
    """Authorization policy"""
    other_attributes_string: Optional[str] = field(default=None)
    """Other attributes"""
    response_time: Optional[int] = field(default=None)
    """Response time"""
    passed: Optional[str] = field(default=None)
    """Passed flag"""
    failed: Optional[int] = field(default=None)
    """Failed flag"""
    credential_check: Optional[str] = field(default=None)
    """Credential check"""
    endpoint_profile: Optional[str] = field(default=None)
    """Endpoint matched profile"""
    mdm_server_name: Optional[str] = field(default=None)
    """MDM server name"""
    nas_ipv6_address: Optional[str] = field(default=None)
    """NAS IPV6 address"""
    framed_ipv6_address: Optional[str] = field(default=None)
    """Framed IPV6 address"""
    id: Optional[int] = field(default=None)
    """Database unique ID"""
    timestamp_timezone: Optional[datetime] = field(default=None)
    """Time with timezone when record added"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    ise_node: Optional[str] = field(default=None)
    """Displays the hostname of the ISE server"""
    message_code: Optional[int] = field(default=None)
    """Displays the message code"""
    message_text: Optional[str] = field(default=None)
    """Message text"""
    username: Optional[str] = field(default=None)
    """User's claimed identity"""
    user_type: Optional[str] = field(default=None)
    """User type"""
    calling_station_id: Optional[str] = field(default=None)
    """Calling station ID"""
    access_service: Optional[str] = field(default=None)
    """Access service"""
    framed_ip_address: Optional[str] = field(default=None)
    """Framed IP address"""
    identity_store: Optional[str] = field(default=None)
    """Identity store"""
    identity_group: Optional[str] = field(default=None)
    """Identity group"""
    audit_session_id: Optional[str] = field(default=None)
    """Unique numeric string identifying the server session"""
    authentication_method: Optional[str] = field(default=None)
    """Authentication method"""
    authentication_protocol: Optional[str] = field(default=None)
    """Authentication protocol"""
    service_type: Optional[str] = field(default=None)
    """The Type of Service the user has requested"""
    network_device_name: Optional[str] = field(default=None)
    """Network device name"""
    device_type: Optional[str] = field(default=None)
    """Device type"""
    location: Optional[str] = field(default=None)
    """Location"""
    nas_ip_address: Optional[str] = field(default=None)
    """IP address of NAS"""
    nas_port_id: Optional[str] = field(default=None)
    """NAS port ID"""
    nas_port_type: Optional[str] = field(default=None)
    """NAS port type"""
    selected_authorization_profiles: Optional[str] = field(default=None)
    """Authorization profile used after authentication"""
    posture_status: Optional[str] = field(default=None)
    """Posture status"""
    security_group: Optional[str] = field(default=None)
    """Security group"""
    failure_reason: Optional[str] = field(default=None)
    """Failure reason"""
    response: Optional[str] = field(default=None)
    """Displays the response"""
    execution_steps: Optional[str] = field(default=None)
    """Execution steps"""
    other_attributes: Optional[str] = field(default=None)
    """Other attributes"""


@dataclass
class RegisteredEndpoints:
    """Displays all personal devices registered by the employees"""

    endpoint_id: Optional[str] = field(default=None)
    """Specifies the MAC address of endpoint"""
    endpoint_profile: Optional[str] = field(default=None)
    """Specifies the profiling policy under which endpoint got profiled"""
    endpoint_static_assignment: Optional[str] = field(default=None)
    """Specifies the endpoint static assignment status"""
    static_assignment_group: Optional[str] = field(default=None)
    """Specifies If endpoint statically assigned to user identity group"""
    nmap_subnet_scanid: Optional[int] = field(default=None)
    """NMAP subnet of registered end points"""
    create_time: Optional[datetime] = field(default=None)
    """Time when record was created"""
    logged_at: Optional[datetime] = field(default=None)
    """Time when the record was last updated"""
    identity: Optional[str] = field(default=None)
    """Specifies the portal user"""
    device_registration_status: Optional[str] = field(default=None)
    """Specifies if device is registered"""
    identity_group: Optional[str] = field(default=None)
    """Specifies the identity group"""
    server: Optional[str] = field(default=None)
    """Specifies the ISE node"""


@dataclass
class SecurityGroups:
    """List and details of security groups"""

    name: Optional[str] = field(default=None)
    """Specified the name of the security group"""
    sgt_dec: Optional[int] = field(default=None)
    """Specifies the Security Group Tag in decimal"""
    sgt_hex: Optional[str] = field(default=None)
    """Specifies the Security Group Tag in hexadecimal"""
    description: Optional[str] = field(default=None)
    """Describes the security group"""
    learned_from: Optional[str] = field(default=None)
    """Specifies where learned from"""


@dataclass
class SecurityGroupAcls:
    """List and details of Security group ACLs"""

    name: Optional[str] = field(default=None)
    """Name of the Security group ACL"""
    description: Optional[str] = field(default=None)
    """Description of the security group ACL"""
    ip_version: Optional[str] = field(default=None)
    """Specifies the IP version (ipv4 or ipv6)"""


@dataclass
class SponsorLoginAndAudit:
    """Tracks login activity by sponsor at the sponsor portal and guest related operation performed by sponsor"""

    id: Optional[int] = field(default=None)
    """Database unique ID"""
    timestamp_timezone: Optional[datetime] = field(default=None)
    """Time with timezone when record added"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    sponser_user_name: Optional[str] = field(default=None)
    """User name of sponsor"""
    ip_address: Optional[str] = field(default=None)
    """IP address"""
    mac_address: Optional[str] = field(default=None)
    """MAC address"""
    portal_name: Optional[str] = field(default=None)
    """Portal name"""
    result: Optional[str] = field(default=None)
    """Result"""
    identity_store: Optional[str] = field(default=None)
    """Identity store"""
    operation: Optional[str] = field(default=None)
    """Operation"""
    guest_username: Optional[str] = field(default=None)
    """User name of guest"""
    guest_status: Optional[str] = field(default=None)
    """Status of guest"""
    failure_reason: Optional[str] = field(default=None)
    """Reason of failure"""
    optional_data: Optional[str] = field(default=None)
    """Optional data"""
    psn_hostname: Optional[str] = field(default=None)
    """Hostname of PSN"""
    user_details: Optional[str] = field(default=None)
    """Details of user"""
    guest_details: Optional[str] = field(default=None)
    """Details of guest"""
    guest_users: Optional[str] = field(default=None)
    """Guest users"""


@dataclass
class SystemDiagnosticsView:
    """Provides details about the status of the Cisco ISE nodes. If a Cisco ISE node is unable to register, you can review this report to troubleshoot the issue"""

    id: Optional[int] = field(default=None)
    """Database unique ID"""
    timestamp_timezone: Optional[datetime] = field(default=None)
    """Time with timezone when record added"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    ise_node: Optional[str] = field(default=None)
    """Displays the hostname of the ISE server"""
    message_severity: Optional[str] = field(default=None)
    """Displays the severity of message"""
    message_code: Optional[str] = field(default=None)
    """Displays the message code"""
    message_text: Optional[str] = field(default=None)
    """Displays the message text"""
    category: Optional[str] = field(default=None)
    """Displays the category"""
    diagnostic_info: Optional[str] = field(default=None)
    """Displays the diagnostic info"""


@dataclass
class SystemSummary:
    """Displays system health information like CPU utilisation , storage utilisation , number of CPU etc"""

    timestamp: Optional[datetime] = field(default=None)
    """Time when record made"""
    ise_node: Optional[str] = field(default=None)
    """Name of ISE node"""
    cpu_utilization: Optional[int] = field(default=None)
    """Specifies the CPU utilization in percentage"""
    cpu_count: Optional[int] = field(default=None)
    """Specifies the number of CPU cores"""
    memory_utilization: Optional[int] = field(default=None)
    """Specifies the percentage of memory utilization"""
    diskspace_root: Optional[int] = field(default=None)
    """Specifies the percentage of storage utilized in root folder"""
    diskspace_boot: Optional[int] = field(default=None)
    """Specifies the percentage of storage utilized in boot folder"""
    diskspace_opt: Optional[int] = field(default=None)
    """Specifies the percentage of storage utilized in opt folder"""
    diskspace_storedconfig: Optional[int] = field(default=None)
    """Specifies the percentage of storage utilized in storedconfig folder"""
    diskspace_tmp: Optional[int] = field(default=None)
    """Specifies the percentage of storage utilized in tmp folder"""
    diskspace_runtime: Optional[int] = field(default=None)
    """Specifies the percentage of storage utilized in runtime"""


@dataclass
class TacacsAccounting:
    """This view contains details of TACACS accounting records"""

    id: Optional[int] = field(default=None)
    """Database record primary key for the table"""
    username: Optional[str] = field(default=None)
    """Shows the user name of the device administrator."""
    identity_group: Optional[str] = field(default=None)
    """Identity group to which users belongs to"""
    generated_time: Optional[str] = field(default=None)
    """Shows the syslog generation time based on when a particular event was triggered"""
    logged_time: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was processed and stored by the Monitoring node"""
    ise_node: Optional[str] = field(default=None)
    """Shows the name of the ISE node through which the access request is processed."""
    authentication_service: Optional[str] = field(default=None)
    """Specifies the authentication service"""
    authentication_method: Optional[str] = field(default=None)
    """Protocol used for authentication"""
    authentication_privilege_level: Optional[str] = field(default=None)
    """Specifies the Authentication Privilege Level"""
    attributes: Optional[str] = field(default=None)
    """Specifies the attributes"""
    message_text: Optional[str] = field(default=None)
    """Specifies the message text"""
    execution_steps: Optional[str] = field(default=None)
    """Specifies the execution steps"""
    authentication_type: Optional[str] = field(default=None)
    """Specifies the authentication type"""
    status: Optional[str] = field(default=None)
    """Shows if the status is pass or failed"""
    message_code: Optional[int] = field(default=None)
    """Syslog message code"""
    command: Optional[str] = field(default=None)
    """Specifies the command"""
    command_args: Optional[str] = field(default=None)
    """Specifies the command arguments"""
    device_type: Optional[str] = field(default=None)
    """Shows the device group device type of the AAA client"""
    location: Optional[str] = field(default=None)
    """Shows the device group device location of the AAA client"""
    accounting_type: Optional[str] = field(default=None)
    """Specifies the accounting type"""
    device_ipv6: Optional[str] = field(default=None)
    """IPV6 address of the network device (The AAA Client)"""
    epoch_time: Optional[int] = field(default=None)
    """Specifies the unix epoch time"""
    failure_reason: Optional[str] = field(default=None)
    """Specifies the reason for failure"""
    session_key: Optional[str] = field(default=None)
    """Shows the session keys (found in the EAP success or EAP failure messages) returned by ISE to the network device."""
    event: Optional[str] = field(default=None)
    """Specifies the event like Accounting"""
    device_name: Optional[str] = field(default=None)
    """Name of the network device (The AAA client)"""
    device_ip: Optional[str] = field(default=None)
    """IP of the network device (The AAA client)"""
    device_groups: Optional[str] = field(default=None)
    """To which network device group the AAA client belongs to"""
    device_port: Optional[str] = field(default=None)
    """Shows the network device port number through which the access request is made."""
    remote_address: Optional[str] = field(default=None)
    """Shows the IP address, MAC address, or any other string that uniquely identifies the end station"""


@dataclass
class TacacsAccountingLastTwoDays:
    """This is performance oriented view which contains all the TACACS accounting records for the last two days"""

    id: Optional[int] = field(default=None)
    """Database record primary key for the table"""
    username: Optional[str] = field(default=None)
    """Shows the user name of the device administrator."""
    identity_group: Optional[str] = field(default=None)
    """Identity group to which users belongs to"""
    generated_time: Optional[datetime] = field(default=None)
    """Shows the syslog generation time based on when a particular event was triggered"""
    logged_time: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was processed and stored by the Monitoring node"""
    ise_node: Optional[str] = field(default=None)
    """Shows the name of the ISE node through which the access request is processed."""
    authentication_service: Optional[str] = field(default=None)
    """Specifies the authentication service"""
    authentication_method: Optional[str] = field(default=None)
    """Protocol used for authentication"""
    authentication_privilege_level: Optional[str] = field(default=None)
    """Specifies the authentication privilege level"""
    authentication_type: Optional[str] = field(default=None)
    """Specifies the authentication type"""
    status: Optional[str] = field(default=None)
    """Shows if the status is pass or failed"""
    message_code: Optional[int] = field(default=None)
    """Syslog message code"""
    command: Optional[str] = field(default=None)
    """Specifies the command"""
    command_args: Optional[str] = field(default=None)
    """Specifies the command arguments"""
    device_type: Optional[str] = field(default=None)
    """Shows the device group device type of the AAA client"""
    location: Optional[str] = field(default=None)
    """Shows the device group device location of the AAA client"""
    accounting_type: Optional[str] = field(default=None)
    """Specifies the accounting type"""
    device_ipv6: Optional[str] = field(default=None)
    """IPV6 address of the network device (The AAA Client)"""
    epoch_time: Optional[int] = field(default=None)
    """Specifies the unix epoch time"""
    failure_reason: Optional[str] = field(default=None)
    """Specifies the reason for failure"""
    session_key: Optional[str] = field(default=None)
    """Shows the session keys (found in the EAP success or EAP failure messages) returned by ISE to the network device."""
    event: Optional[str] = field(default=None)
    """Specifies the event like Accounting"""
    device_name: Optional[str] = field(default=None)
    """Name of the network device (The AAA client)"""
    device_ip: Optional[str] = field(default=None)
    """IP of the network device (The AAA client)"""
    device_groups: Optional[str] = field(default=None)
    """To which network device group the AAA client belongs to"""
    device_port: Optional[str] = field(default=None)
    """Shows the network device port number through which the access request is made."""
    remote_address: Optional[str] = field(default=None)
    """Shows the IP address, MAC address, or any other string that uniquely identifies the end station"""


@dataclass
class TacacsAuthentication:
    """This provides details of all the TACACS authentication records"""

    id: Optional[int] = field(default=None)
    """Database record primary key for the table"""
    generated_time: Optional[str] = field(default=None)
    """Shows the syslog generation time based on when a particular event was triggered"""
    logged_time: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was processed and stored by the Monitoring node"""
    ise_node: Optional[str] = field(default=None)
    """Shows the name of the ISE node through which the access request is processed."""
    message_code: Optional[int] = field(default=None)
    """Syslog message code"""
    username: Optional[str] = field(default=None)
    """Shows the user name of the device administrator."""
    failure_reason: Optional[str] = field(default=None)
    """Specifies the reason for failure"""
    authentication_policy: Optional[str] = field(default=None)
    """Specifies the authentication policy"""
    authentication_privilege_level: Optional[str] = field(default=None)
    """Specifies the Authentication Privilege Level"""
    attributes: Optional[str] = field(default=None)
    """Specifies the attributes"""
    message_text: Optional[str] = field(default=None)
    """Specifies the message text"""
    execution_steps: Optional[str] = field(default=None)
    """Specifies the execution steps"""
    authentication_action: Optional[str] = field(default=None)
    """Specifies the authentication action"""
    authentication_type: Optional[str] = field(default=None)
    """Specifies the authentication type"""
    authentication_service: Optional[str] = field(default=None)
    """Specifies the authentication service"""
    session_key: Optional[str] = field(default=None)
    """Shows the session keys (found in the EAP success or EAP failure messages) returned by ISE to the network device."""
    event: Optional[str] = field(default=None)
    """Specifies the event like Accounting"""
    device_name: Optional[str] = field(default=None)
    """Name of the network device (The AAA client)"""
    device_ip: Optional[str] = field(default=None)
    """IP of the network device (The AAA client)"""
    device_groups: Optional[str] = field(default=None)
    """To which network device group the AAA client belongs to"""
    device_port: Optional[str] = field(default=None)
    """Shows the network device port number through which the access request is made."""
    remote_address: Optional[str] = field(default=None)
    """Shows the IP address, MAC address, or any other string that uniquely identifies the end station"""
    selected_authorization_profile: Optional[str] = field(default=None)
    """Authorization profile used after authentication"""
    destination_ip_address: Optional[str] = field(default=None)
    """Specifies the destination IP address"""
    status: Optional[str] = field(default=None)
    """Shows if the authentication succeeded or failed"""
    device_type: Optional[str] = field(default=None)
    """Shows the device group device type of the AAA client"""
    location: Optional[str] = field(default=None)
    """Shows the device group device location of the AAA client"""
    identity_store: Optional[str] = field(default=None)
    """Identity store to which users belongs to"""
    device_ipv6: Optional[str] = field(default=None)
    """IPV6 address of the network device (The AAA Client)"""
    epoch_time: Optional[int] = field(default=None)
    """Specifies the unix epoch time"""


@dataclass
class TacacsAuthenticationLastTwoDays:
    """This is performance oriented view which contains all the TACACS authentication records for the last two days"""

    id: Optional[int] = field(default=None)
    """Database record primary key for the table"""
    generated_time: Optional[datetime] = field(default=None)
    """Shows the syslog generation time based on when a particular event was triggered"""
    logged_time: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was processed and stored by the Monitoring node"""
    ise_node: Optional[str] = field(default=None)
    """Shows the name of the ISE node through which the access request is processed."""
    message_code: Optional[int] = field(default=None)
    """Syslog message code"""
    username: Optional[str] = field(default=None)
    """Shows the user name of the device administrator."""
    failure_reason: Optional[str] = field(default=None)
    """Specifies the reason for failure"""
    authentication_policy: Optional[str] = field(default=None)
    """Specifies the authentication policy"""
    authentication_privilege_level: Optional[str] = field(default=None)
    """Specifies the authentication privilege level"""
    authentication_action: Optional[str] = field(default=None)
    """Specifies the authentication action"""
    authentication_type: Optional[str] = field(default=None)
    """Specifies the authentication type"""
    authentication_service: Optional[str] = field(default=None)
    """Specifies the authentication service"""
    session_key: Optional[str] = field(default=None)
    """Shows the session keys (found in the EAP success or EAP failure messages) returned by ISE to the network device."""
    event: Optional[str] = field(default=None)
    """Specifies the event like Accounting"""
    device_name: Optional[str] = field(default=None)
    """Name of the network device (The AAA client)"""
    device_ip: Optional[str] = field(default=None)
    """IP of the network device (The AAA client)"""
    device_groups: Optional[str] = field(default=None)
    """To which network device group the AAA client belongs to"""
    device_port: Optional[str] = field(default=None)
    """Shows the network device port number through which the access request is made."""
    remote_address: Optional[str] = field(default=None)
    """Shows the IP address, MAC address, or any other string that uniquely identifies the end station"""
    selected_authorization_profile: Optional[str] = field(default=None)
    """Authorization profile used after authentication"""
    destination_ip_address: Optional[str] = field(default=None)
    """Specifies the destination IP address"""
    status: Optional[str] = field(default=None)
    """Shows if the authentication succeeded or failed"""
    device_type: Optional[str] = field(default=None)
    """Shows the device group device type of the AAA client"""
    location: Optional[str] = field(default=None)
    """Shows the device group device location of the AAA client"""
    identity_store: Optional[str] = field(default=None)
    """Identity store to which users belongs to"""
    device_ipv6: Optional[str] = field(default=None)
    """IPV6 address of the network device (The AAA Client)"""
    epoch_time: Optional[int] = field(default=None)
    """Specifies the unix epoch time"""


@dataclass
class TacacsAuthenticationSummary:
    """Display aggregate view of TACACS authentications"""

    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    ise_node: Optional[str] = field(default=None)
    """Shows the name of the ISE node through which the access request is processed."""
    username: Optional[str] = field(default=None)
    """Shows the user name of the device administrator."""
    identity_store: Optional[str] = field(default=None)
    """Identity store to which users belongs to"""
    device_name: Optional[str] = field(default=None)
    """Name of the network device (The AAA client)"""
    device_group: Optional[str] = field(default=None)
    """To which network device group the AAA client belongs to"""
    device_type: Optional[str] = field(default=None)
    """Shows the device group device type of the AAA client"""
    location: Optional[str] = field(default=None)
    """Shows the device group device location of the AAA client"""
    authorization_profiles: Optional[str] = field(default=None)
    """Specifies the authorization profiles"""
    failure_reason: Optional[str] = field(default=None)
    """Specifies the reason for failure"""
    passed_count: Optional[int] = field(default=None)
    """Number of successful authentication"""
    failed_count: Optional[int] = field(default=None)
    """Number of failed authentication"""


@dataclass
class TacacsAuthorization:
    """This provides details of all the TACACS authorization records"""

    id: Optional[int] = field(default=None)
    """Database unique ID"""
    generated_time: Optional[str] = field(default=None)
    """Shows the syslog generation time based on when a particular event was triggered"""
    logged_time: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was processed and stored by the Monitoring node"""
    ise_node: Optional[str] = field(default=None)
    """Shows the name of the ISE node through which the access request is processed."""
    attributes: Optional[str] = field(default=None)
    """Specifies the attributes"""
    execution_steps: Optional[str] = field(default=None)
    """Specifies the execution steps"""
    status: Optional[str] = field(default=None)
    """Shows if the status is pass or failed"""
    event: Optional[str] = field(default=None)
    """Specifies the event like Accounting"""
    message_text: Optional[str] = field(default=None)
    """Specifies the operational message text"""
    device_ipv6: Optional[str] = field(default=None)
    """IPV6 address of the network device (The AAA Client)"""
    device_name: Optional[str] = field(default=None)
    """Name of the network device (The AAA client)"""
    device_ip: Optional[str] = field(default=None)
    """IP of the network device (The AAA client)"""
    device_group: Optional[str] = field(default=None)
    """To which network device group the AAA client belongs to"""
    device_port: Optional[str] = field(default=None)
    """Shows the network device port number through which the access request is made."""
    epoch_time: Optional[int] = field(default=None)
    """Specifies the unix epoch time"""
    failure_reason: Optional[str] = field(default=None)
    """Specifies the reason for failure"""
    username: Optional[str] = field(default=None)
    """Shows the user name of the device administrator."""
    authorization_policy: Optional[str] = field(default=None)
    """Specifies the authorization policy"""
    authentication_privilege_level: Optional[str] = field(default=None)
    """Specifies the Authentication Privilege Level"""
    authorization_request_attr: Optional[str] = field(default=None)
    """Specifies the request attribute"""
    authorization_response_attr: Optional[str] = field(default=None)
    """Specifies the response attribute"""
    session_key: Optional[str] = field(default=None)
    """Shows the session keys (found in the EAP success or EAP failure messages) returned by ISE to the network device."""
    remote_address: Optional[str] = field(default=None)
    """Shows the IP address, MAC address, or any other string that uniquely identifies the end station"""
    shell_profile: Optional[str] = field(default=None)
    """Specifies the TACACS Profiles"""
    authentication_method: Optional[str] = field(default=None)
    """Specifies the authentication method"""
    authentication_type: Optional[str] = field(default=None)
    """Specifies the authentication type"""
    authentication_service: Optional[str] = field(default=None)
    """Specifies the authentication type"""
    device_type: Optional[str] = field(default=None)
    """Shows the device group device type of the AAA client"""
    location: Optional[str] = field(default=None)
    """Shows the device group device location of the AAA client"""
    matched_command_set: Optional[str] = field(default=None)
    """Matched TACACS command sets"""
    command_from_device: Optional[str] = field(default=None)
    """Specifies the command in the matched command set"""


@dataclass
class TacacsCommandAccounting:
    """Displays details of TACACS command accounting"""

    id: Optional[int] = field(default=None)
    """Unique database ID"""
    username: Optional[str] = field(default=None)
    """Shows the user name of the device administrator."""
    generated_time: Optional[str] = field(default=None)
    """Shows the syslog generation time based on when a particular event was triggered"""
    logged_time: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was processed and stored by the Monitoring node"""
    ise_node: Optional[str] = field(default=None)
    """Shows the name of the ISE node through which the access request is processed."""
    authentication_privilege_level: Optional[str] = field(default=None)
    """Specifies the Authentication Privilege Level"""
    attributes: Optional[str] = field(default=None)
    """Specifies the attributes"""
    execution_steps: Optional[str] = field(default=None)
    """Specifies the execution steps"""
    status: Optional[str] = field(default=None)
    """Shows if the status pass or failed"""
    event: Optional[str] = field(default=None)
    """Specifies the event like Accounting"""
    message_text: Optional[str] = field(default=None)
    """Specifies the message text"""
    failure_reason: Optional[str] = field(default=None)
    """Specifies the failure reason"""
    identity_group: Optional[str] = field(default=None)
    """Identity group to which users belongs to"""
    session_key: Optional[str] = field(default=None)
    """Shows the session keys (found in the EAP success or EAP failure messages) returned by ISE to the network device."""
    device_name: Optional[str] = field(default=None)
    """IPV6 address of the network device (The AAA Client)"""
    device_ip: Optional[str] = field(default=None)
    """IP of the network device (The AAA client)"""
    device_groups: Optional[str] = field(default=None)
    """To which network device group the AAA client belongs to"""
    device_port: Optional[str] = field(default=None)
    """Shows the network device port number through which the access request is made."""
    device_ipv6: Optional[str] = field(default=None)
    """IPV6 address of the network device (The AAA Client)"""
    remote_address: Optional[str] = field(default=None)
    """Shows the IP address, MAC address, or any other string that uniquely identifies the end station"""
    authentication_method: Optional[str] = field(default=None)
    """Specifies the authentication method"""
    authentication_type: Optional[str] = field(default=None)
    """Specifies the authentication type"""
    authentication_service: Optional[str] = field(default=None)
    """Specifies the authentication service"""
    command: Optional[str] = field(default=None)
    """Specifies the command"""
    command_args: Optional[str] = field(default=None)
    """Specifies the command arguments"""
    device_type: Optional[str] = field(default=None)
    """Shows the device group device type of the AAA client"""
    location: Optional[str] = field(default=None)
    """Shows the device group device location of the AAA client"""
    epoch_time: Optional[int] = field(default=None)
    """Specifies the unix epoch time"""


@dataclass
class ThreatEvents:
    """Log of threat events received from various sources"""

    logged_at: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was processed and stored by the Monitoring node"""
    mac_address: Optional[str] = field(default=None)
    """Specifies the MAC address"""
    ip_address: Optional[str] = field(default=None)
    """Specifies the IP address"""
    id: Optional[str] = field(default=None)
    """Unique database identifier"""
    severity: Optional[str] = field(default=None)
    """Specifies the severity"""
    title: Optional[str] = field(default=None)
    """Specifies the title"""
    event_time: Optional[str] = field(default=None)
    """Specifies the event time"""
    vendor_name: Optional[str] = field(default=None)
    """Specifies the vendor name"""
    source: Optional[str] = field(default=None)
    """Specifies the source"""
    incident_type: Optional[str] = field(default=None)
    """Specifies the incident type"""
    details: Optional[str] = field(default=None)
    """Gives further details"""


@dataclass
class Upspolicy:
    """None"""

    id: Optional[str] = field(default=None)
    edf_version: Optional[int] = field(default=None)
    edf_create_time: Optional[datetime] = field(default=None)
    edf_update_time: Optional[datetime] = field(default=None)
    combiningalgorithm: Optional[str] = field(default=None)
    policytypeenum: Optional[str] = field(default=None)
    policyid: Optional[str] = field(default=None)
    policystatus: Optional[str] = field(default=None)
    displayname: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    target: Optional[str] = field(default=None)


@dataclass
class Upspolicyset:
    """None"""

    id: Optional[str] = field(default=None)
    edf_version: Optional[int] = field(default=None)
    edf_create_time: Optional[datetime] = field(default=None)
    edf_update_time: Optional[datetime] = field(default=None)
    combiningalgorithm: Optional[str] = field(default=None)
    policysettypeenum: Optional[str] = field(default=None)
    policysetid: Optional[str] = field(default=None)
    parentpolicysetid: Optional[str] = field(default=None)
    policysetstatus: Optional[str] = field(default=None)
    displayname: Optional[str] = field(default=None)
    description: Optional[str] = field(default=None)
    selfreference: Optional[int] = field(default=None)
    evaluatetarget: Optional[int] = field(default=None)
    referencedpolicysetid: Optional[str] = field(default=None)
    target: Optional[str] = field(default=None)


@dataclass
class UpspolicysetPolicies:
    """None"""

    upspolicyset: Optional[str] = field(default=None)
    policies: Optional[str] = field(default=None)


@dataclass
class UserIdentityGroups:
    """This will provide details of all the user identity groups"""

    id: Optional[str] = field(default=None)
    """Primary key for user identity groups"""
    name: Optional[str] = field(default=None)
    """Name of the group"""
    description: Optional[str] = field(default=None)
    """Description of the group"""
    created_by: Optional[str] = field(default=None)
    """The group was created by whom"""
    create_time: Optional[datetime] = field(default=None)
    """When the record was created"""
    update_time: Optional[datetime] = field(default=None)
    """When the record was updated"""
    status: Optional[str] = field(default=None)
    """Shows if the group is active"""


@dataclass
class UserPasswordChanges:
    """Displays verification about employees password changes"""

    timestamp_timezone: Optional[datetime] = field(default=None)
    """Time with timezone when record added"""
    timestamp: Optional[datetime] = field(default=None)
    """Time when record added"""
    ise_node: Optional[str] = field(default=None)
    """Displays the hostname of the ISE server"""
    message_code: Optional[str] = field(default=None)
    """Displays the message code"""
    admin_name: Optional[str] = field(default=None)
    """Admin name"""
    admin_ip_address: Optional[str] = field(default=None)
    """Admin IP address"""
    admin_ipv6_address: Optional[str] = field(default=None)
    """Admin IPV6 address"""
    admin_interface: Optional[str] = field(default=None)
    """Admin interface used"""
    message_class: Optional[str] = field(default=None)
    """Message class"""
    message_text: Optional[str] = field(default=None)
    """Displays the message text"""
    operator_name: Optional[str] = field(default=None)
    """Operator name"""
    user_admin_flag: Optional[str] = field(default=None)
    """User admin flag"""
    account_name: Optional[str] = field(default=None)
    """Account name"""
    device_ip: Optional[str] = field(default=None)
    """Device IP"""
    identity_store_name: Optional[str] = field(default=None)
    """Identity store name"""
    change_password_method: Optional[str] = field(default=None)
    """Method of password change"""
    audit_password_type: Optional[str] = field(default=None)
    """Password type"""


@dataclass
class VulnerabilityAssessmentFailures:
    """This report contains details of endpoints for which Vulnerability Assessment failed"""

    logged_at: Optional[datetime] = field(default=None)
    """Shows the time when the syslog was processed and stored by the Monitoring node"""
    id: Optional[str] = field(default=None)
    """Unique database ID"""
    adapter_instance_name: Optional[str] = field(default=None)
    """Specifies the adapter instance name"""
    adapter_instance_id: Optional[str] = field(default=None)
    """Specifies the adapter instance ID"""
    vendor_name: Optional[str] = field(default=None)
    """Specifies the vendor name"""
    ise_node: Optional[str] = field(default=None)
    """Specifies the ACS instance"""
    mac_address: Optional[str] = field(default=None)
    """Specifies the MAC address"""
    ip_address: Optional[str] = field(default=None)
    """Specifies the IP address"""
    operation_messsage_text: Optional[str] = field(default=None)
    """Specifies the operation message text"""
    message_type: Optional[str] = field(default=None)
    """Specifies the message type"""
