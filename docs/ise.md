# Cisco ISE Data Connect

<a id="data_connect"></a>

# data\_connect

Cisco ISE Data Connect

<a id="data_connect.IseDataConnect"></a>

## IseDataConnect Objects

```python
class IseDataConnect(
    hostname: str,
    port: str,
    user: str,
    password: str,
    **kwargs: Any
)
```

Cisco ISE Data Connect

For all the tables available, a `get_<table_name>` method is supported, e.g.
- `NODE_LIST`: `get_node_list`
- `ADMIN_USERS`: `get_admin_users`

**Arguments**:

- `hostname` _str_ - ISE hostname for Data Connect connection
- `port` _str_ - ISE port for Data Connect connection
- `user` _str_ - ISE Data Connect username
- `password` _str_ - ISE Data Connect password
- `jar` _str_ - Thick client JAR filename
- `trust_store` _str_ - Java key store filename, required for thick client
- `trust_store_password` _str_ - Java key store password, required for thick client
- `verify` _bool, optional_ - Verify ISE Data Connect certificate, Defaults to True.

<a id="data_connect.IseDataConnect.execute_query"></a>

#### execute\_query

```python
def execute_query(query: str, params: list | tuple | dict = None) -> list
```

Execute SQL query against the database.

**Arguments**:

- `query` _str_ - SQL query string
- `params` _list | tuple | dict_ - Named query parameters
  

**Returns**:

- `list` - All records from the query result.

<a id="data_connect.IseDataConnect.get_all_records"></a>

#### get\_all\_records

```python
def get_all_records(table_name: str) -> list
```

Get all records from the table.

**Arguments**:

- `table_name` _str_ - Table name from ISE Data Connect
  

**Returns**:

- `list` - All records from the table.

<a id="exceptions"></a>

# exceptions

Exceptions for ISE Data Connect

<a id="exceptions.IseDataConnectException"></a>

## IseDataConnectException Objects

```python
class IseDataConnectException(Exception)
```

ISE Data Connect Exception

<a id="models"></a>

# models

Python Data Models for ISE Data Connect table views

This is an auto-generated file

<a id="models.AaaDiagnosticsView"></a>

## AaaDiagnosticsView Objects

```python
@dataclass
class AaaDiagnosticsView()
```

Provides details of all network sessions between Cisco ISE and users

<a id="models.AaaDiagnosticsView.timestamp_timezone"></a>

#### timestamp\_timezone

Time with timezone when record added

<a id="models.AaaDiagnosticsView.timestamp"></a>

#### timestamp

Time when record added

<a id="models.AaaDiagnosticsView.session_id"></a>

#### session\_id

Shows the session ID

<a id="models.AaaDiagnosticsView.ise_node"></a>

#### ise\_node

Displays the hostname of the ISE server

<a id="models.AaaDiagnosticsView.username"></a>

#### username

Displays the username

<a id="models.AaaDiagnosticsView.message_severity"></a>

#### message\_severity

Displays the severity of message

<a id="models.AaaDiagnosticsView.message_code"></a>

#### message\_code

Displays the message code

<a id="models.AaaDiagnosticsView.message_text"></a>

#### message\_text

Displays the message text

<a id="models.AaaDiagnosticsView.category"></a>

#### category

Displays the category

<a id="models.AaaDiagnosticsView.info"></a>

#### info

Displays the diagnostic info

<a id="models.AdapterStatus"></a>

## AdapterStatus Objects

```python
@dataclass
class AdapterStatus()
```

Adapter Status Report

<a id="models.AdapterStatus.logged_at"></a>

#### logged\_at

Shows the time when the syslog was processed and stored by the Monitoring node

<a id="models.AdapterStatus.status"></a>

#### status

Specifies the adapter status

<a id="models.AdapterStatus.id"></a>

#### id

Unique database ID

<a id="models.AdapterStatus.adapter_name"></a>

#### adapter\_name

Specifies the adapter name

<a id="models.AdapterStatus.connectivity"></a>

#### connectivity

Specifies the connectivity

<a id="models.AdaptiveNetworkControl"></a>

## AdaptiveNetworkControl Objects

```python
@dataclass
class AdaptiveNetworkControl()
```

The Adaptive Network Control Audit report is based on the RADIUS accounting. It displays historical reporting of all network sessions for each endpoint

<a id="models.AdaptiveNetworkControl.logged_at"></a>

#### logged\_at

Shows the time when the syslog was processed and stored by the Monitoring node

<a id="models.AdaptiveNetworkControl.endpoint_id"></a>

#### endpoint\_id

Specifies the endpoint ID

<a id="models.AdaptiveNetworkControl.id"></a>

#### id

Unique Database ID

<a id="models.AdaptiveNetworkControl.ip_address"></a>

#### ip\_address

Specifies the IP address

<a id="models.AdaptiveNetworkControl.ipv6_address"></a>

#### ipv6\_address

Specifies the IPV6 IP address

<a id="models.AdaptiveNetworkControl.operation_type"></a>

#### operation\_type

Specifies the operation type

<a id="models.AdaptiveNetworkControl.operation_status"></a>

#### operation\_status

Specifies the operation status

<a id="models.AdaptiveNetworkControl.audit_session"></a>

#### audit\_session

Specifies the audit session

<a id="models.AdaptiveNetworkControl.admin_identity"></a>

#### admin\_identity

Specifies the admin identity

<a id="models.AdaptiveNetworkControl.admin_ip"></a>

#### admin\_ip

Specifies the admin IP

<a id="models.AdaptiveNetworkControl.ise_node"></a>

#### ise\_node

Specifies the ISE node

<a id="models.AdministratorLogins"></a>

## AdministratorLogins Objects

```python
@dataclass
class AdministratorLogins()
```

Gives the data about the administrator logins to the ISE

<a id="models.AdministratorLogins.timestamp_timezone"></a>

#### timestamp\_timezone

Time with timezone when administrator logged in

<a id="models.AdministratorLogins.timestamp"></a>

#### timestamp

Time when administrator logged in

<a id="models.AdministratorLogins.ise_node"></a>

#### ise\_node

Hostname of ISE node

<a id="models.AdministratorLogins.admin_name"></a>

#### admin\_name

Name of the admin

<a id="models.AdministratorLogins.ip_address"></a>

#### ip\_address

IP address of the client from where the admin logged in

<a id="models.AdministratorLogins.ipv6_address"></a>

#### ipv6\_address

IPV6 address

<a id="models.AdministratorLogins.interface"></a>

#### interface

Interface used for login GUI/CLI

<a id="models.AdministratorLogins.admin_session"></a>

#### admin\_session

admin session

<a id="models.AdministratorLogins.event_details"></a>

#### event\_details

Details of the event

<a id="models.AdministratorLogins.event"></a>

#### event

Admin logged in or logged out

<a id="models.AdminUsers"></a>

## AdminUsers Objects

```python
@dataclass
class AdminUsers()
```

This provides details of all the administrators of ISE

<a id="models.AdminUsers.id"></a>

#### id

Database unique ID

<a id="models.AdminUsers.status"></a>

#### status

Admin user is enabled or disabled

<a id="models.AdminUsers.name"></a>

#### name

Name of the admin user

<a id="models.AdminUsers.description"></a>

#### description

Description

<a id="models.AdminUsers.first_name"></a>

#### first\_name

First name of the admin user

<a id="models.AdminUsers.last_name"></a>

#### last\_name

Last name of the admin user

<a id="models.AdminUsers.email_address"></a>

#### email\_address

Email address of the admin user

<a id="models.AdminUsers.admin_group"></a>

#### admin\_group

Group to which admin user belongs

<a id="models.AupAcceptanceStatus"></a>

## AupAcceptanceStatus Objects

```python
@dataclass
class AupAcceptanceStatus()
```

Track all accepted and denied AUP connections

<a id="models.AupAcceptanceStatus.id"></a>

#### id

Database unique ID

<a id="models.AupAcceptanceStatus.timestamp_timezone"></a>

#### timestamp\_timezone

Time with timezone when record added

<a id="models.AupAcceptanceStatus.timestamp"></a>

#### timestamp

Time when record added

<a id="models.AupAcceptanceStatus.message_code"></a>

#### message\_code

Message code

<a id="models.AupAcceptanceStatus.username"></a>

#### username

User name

<a id="models.AupAcceptanceStatus.ip_address"></a>

#### ip\_address

IP address of the endpoint

<a id="models.AupAcceptanceStatus.mac_address"></a>

#### mac\_address

MAC address of the endpoint

<a id="models.AupAcceptanceStatus.portal_name"></a>

#### portal\_name

Portal name

<a id="models.AupAcceptanceStatus.aup_acceptance"></a>

#### aup\_acceptance

AUP acceptance status

<a id="models.AupAcceptanceStatus.first_name"></a>

#### first\_name

First name of user

<a id="models.AupAcceptanceStatus.last_name"></a>

#### last\_name

Last name of user

<a id="models.AupAcceptanceStatus.identity_group"></a>

#### identity\_group

Identity group

<a id="models.AupAcceptanceStatus.email_address"></a>

#### email\_address

Email address of user

<a id="models.AupAcceptanceStatus.phone_number"></a>

#### phone\_number

Phone number of user

<a id="models.AupAcceptanceStatus.company"></a>

#### company

Company of user

<a id="models.AupAcceptanceStatus.identity_store"></a>

#### identity\_store

Identify store

<a id="models.AupAcceptanceStatus.nad_address"></a>

#### nad\_address

IP address of NAD

<a id="models.AupAcceptanceStatus.nas_ip_address"></a>

#### nas\_ip\_address

IP address of NAS

<a id="models.AupAcceptanceStatus.user_details"></a>

#### user\_details

Details of the user

<a id="models.AuthorizationProfiles"></a>

## AuthorizationProfiles Objects

```python
@dataclass
class AuthorizationProfiles()
```

Displays all existing authorization profiles

<a id="models.AuthorizationProfiles.name"></a>

#### name

Name of the authorization profiles

<a id="models.AuthorizationProfiles.description"></a>

#### description

Description of the authorization profiles

<a id="models.ChangeConfigurationAudit"></a>

## ChangeConfigurationAudit Objects

```python
@dataclass
class ChangeConfigurationAudit()
```

Displays the configuration audit data

<a id="models.ChangeConfigurationAudit.id"></a>

#### id

Database unique ID

<a id="models.ChangeConfigurationAudit.timestamp_timezone"></a>

#### timestamp\_timezone

Time with timezone when record added

<a id="models.ChangeConfigurationAudit.timestamp"></a>

#### timestamp

Time when record added

<a id="models.ChangeConfigurationAudit.ise_node"></a>

#### ise\_node

Hostname of ISE node

<a id="models.ChangeConfigurationAudit.message_code"></a>

#### message\_code

Message code

<a id="models.ChangeConfigurationAudit.admin_name"></a>

#### admin\_name

Name of the admin who made config change

<a id="models.ChangeConfigurationAudit.nas_ip_address"></a>

#### nas\_ip\_address

IP address of NAD

<a id="models.ChangeConfigurationAudit.nas_ipv6_address"></a>

#### nas\_ipv6\_address

IPV6 address of NAD

<a id="models.ChangeConfigurationAudit.interface"></a>

#### interface

Interface used for login GUI/CLI

<a id="models.ChangeConfigurationAudit.object_name"></a>

#### object\_name

Name of object for which config is changed

<a id="models.ChangeConfigurationAudit.object_type"></a>

#### object\_type

Type of object for which config is changed

<a id="models.ChangeConfigurationAudit.message_class"></a>

#### message\_class

Message class

<a id="models.ChangeConfigurationAudit.event"></a>

#### event

Config change done

<a id="models.ChangeConfigurationAudit.requested_operation"></a>

#### requested\_operation

Operation done

<a id="models.ChangeConfigurationAudit.operation_message_text"></a>

#### operation\_message\_text

Operation details

<a id="models.ChangeConfigurationAudit.host_id"></a>

#### host\_id

Hostname of ISE node on which change is done

<a id="models.ChangeConfigurationAudit.request_response_type"></a>

#### request\_response\_type

Type of request response

<a id="models.ChangeConfigurationAudit.failure_flag"></a>

#### failure\_flag

Failure flag

<a id="models.ChangeConfigurationAudit.modified_properties"></a>

#### modified\_properties

Modified properties

<a id="models.ChangeConfigurationAudit.details"></a>

#### details

Details of the event

<a id="models.ChangeConfigurationAudit.object_id"></a>

#### object\_id

Object ID

<a id="models.ChangeConfigurationAudit.applied_to_acs_instance"></a>

#### applied\_to\_acs\_instance

ISE nodes to which change is applied

<a id="models.ChangeConfigurationAudit.local_mode"></a>

#### local\_mode

Local mode

<a id="models.CoaEvents"></a>

## CoaEvents Objects

```python
@dataclass
class CoaEvents()
```

Log of change of authorization issued based on threat events received from various adapters

<a id="models.CoaEvents.logged_at"></a>

#### logged\_at

Shows the time when the syslog was processed and stored by the Monitoring node

<a id="models.CoaEvents.coa_event_id"></a>

#### coa\_event\_id

Specifies the COA event ID

<a id="models.CoaEvents.coa_status"></a>

#### coa\_status

Specifies the COA status

<a id="models.CoaEvents.calling_station_id"></a>

#### calling\_station\_id

Specifies the calling station ID

<a id="models.CoaEvents.ip_address"></a>

#### ip\_address

Specifies the IP address

<a id="models.CoaEvents.username"></a>

#### username

Specifies the user name

<a id="models.CoaEvents.new_authz_rule"></a>

#### new\_authz\_rule

Specifies the Network Authorization Rule

<a id="models.CoaEvents.old_authz_profile"></a>

#### old\_authz\_profile

Specifies the old Authorization profile

<a id="models.CoaEvents.new_authz_profile"></a>

#### new\_authz\_profile

Specifies the new Authorization profile

<a id="models.CoaEvents.vendor_name"></a>

#### vendor\_name

Specifies the vendor name

<a id="models.CoaEvents.incident_type"></a>

#### incident\_type

Specifies the incident type

<a id="models.CoaEvents.threat_events"></a>

#### threat\_events

Specifies the threat events

<a id="models.CoaEvents.operation_message_text"></a>

#### operation\_message\_text

Specifies the operation message text

<a id="models.EndpointsData"></a>

## EndpointsData Objects

```python
@dataclass
class EndpointsData()
```

Collection of all data related to endpoint that ISE collects

<a id="models.EndpointsData.id"></a>

#### id

Database unique ID

<a id="models.EndpointsData.mac_address"></a>

#### mac\_address

Specifies MAC address of the endpoint

<a id="models.EndpointsData.endpoint_policy"></a>

#### endpoint\_policy

Specifies the profiling policy under which endpoint got profiled

<a id="models.EndpointsData.static_assignment"></a>

#### static\_assignment

Specifies the endpoint static assignment status

<a id="models.EndpointsData.static_group_assignment"></a>

#### static\_group\_assignment

Specifies if endpoint statically assigned to user identity group

<a id="models.EndpointsData.identity_group_id"></a>

#### identity\_group\_id

Specifies the unique ID of the User identity Group the endpoint belongs to

<a id="models.EndpointsData.endpoint_ip"></a>

#### endpoint\_ip

Specifies the IP address of the endpoint

<a id="models.EndpointsData.endpoint_policy_version"></a>

#### endpoint\_policy\_version

The version of endpoint policy used

<a id="models.EndpointsData.matched_value"></a>

#### matched\_value

Matched Certainty Factor

<a id="models.EndpointsData.endpoint_policy_id"></a>

#### endpoint\_policy\_id

Specifies the unique ID of the endpoint policy used

<a id="models.EndpointsData.matched_policy_id"></a>

#### matched\_policy\_id

Specifies the ID of profiling used

<a id="models.EndpointsData.nmap_subnet_scanid"></a>

#### nmap\_subnet\_scanid

NMAP subnet can ID of end points

<a id="models.EndpointsData.portal_user"></a>

#### portal\_user

Specifies the portal user

<a id="models.EndpointsData.auth_store_id"></a>

#### auth\_store\_id

Specifies the auth store ID

<a id="models.EndpointsData.device_registrations_status"></a>

#### device\_registrations\_status

Specifies if device is registered

<a id="models.EndpointsData.reg_timestamp"></a>

#### reg\_timestamp

Specifies the registered timestamp

<a id="models.EndpointsData.posture_applicable"></a>

#### posture\_applicable

Specifies if Posture is Applicable

<a id="models.EndpointsData.create_time"></a>

#### create\_time

Time when record added

<a id="models.EndpointsData.update_time"></a>

#### update\_time

Time when record last updated

<a id="models.EndpointsData.profile_server"></a>

#### profile\_server

Specifies the ISE node that profiled the endpoint

<a id="models.EndpointsData.byod_reg"></a>

#### byod\_reg

Specifies the BYOD Registration status

<a id="models.EndpointsData.hostname"></a>

#### hostname

Specifies the hostname of the endpoint

<a id="models.EndpointsData.version"></a>

#### version

Specifies the version

<a id="models.EndpointsData.posture_expiry"></a>

#### posture\_expiry

Specifies the posture expiry

<a id="models.EndpointsData.native_udid"></a>

#### native\_udid

Endpoint native UDID

<a id="models.EndpointsData.phone_id"></a>

#### phone\_id

Endpoint phone ID

<a id="models.EndpointsData.phone_id_type"></a>

#### phone\_id\_type

Endpoint phone ID type

<a id="models.EndpointsData.mdm_server_id"></a>

#### mdm\_server\_id

Endpoint MDM server ID

<a id="models.EndpointsData.unique_subject_id"></a>

#### unique\_subject\_id

Endpoint subject ID

<a id="models.EndpointsData.mdm_guid"></a>

#### mdm\_guid

Endpoint MDM GUID

<a id="models.EndpointsData.endpoint_unique_id"></a>

#### endpoint\_unique\_id

Endpoint unique ID

<a id="models.EndpointsData.endpoint_id"></a>

#### endpoint\_id

Specifies the EPID of the endpoint

<a id="models.EndpointsData.probe_data"></a>

#### probe\_data

Specifies all the probe data acquired during profiling

<a id="models.EndpointsData.custom_attributes"></a>

#### custom\_attributes

Specifies the custom attributes

<a id="models.EndpointIdentityGroups"></a>

## EndpointIdentityGroups Objects

```python
@dataclass
class EndpointIdentityGroups()
```

This will provide details of all the endpoint identity groups

<a id="models.EndpointIdentityGroups.id"></a>

#### id

Database unique ID

<a id="models.EndpointIdentityGroups.name"></a>

#### name

Name

<a id="models.EndpointIdentityGroups.description"></a>

#### description

Description

<a id="models.EndpointIdentityGroups.created_by"></a>

#### created\_by

Name of the user

<a id="models.EndpointIdentityGroups.create_time"></a>

#### create\_time

Time of creation

<a id="models.EndpointIdentityGroups.update_time"></a>

#### update\_time

Time of updating

<a id="models.EndpointIdentityGroups.status"></a>

#### status

Active/Inactive

<a id="models.EndpointPurgeView"></a>

## EndpointPurgeView Objects

```python
@dataclass
class EndpointPurgeView()
```

Enables the user to review the history of endpoints purge activities

<a id="models.EndpointPurgeView.id"></a>

#### id

Database unique ID

<a id="models.EndpointPurgeView.endpoint_purge_id"></a>

#### endpoint\_purge\_id

Endpoint purge ID

<a id="models.EndpointPurgeView.run_time"></a>

#### run\_time

Run time

<a id="models.EndpointPurgeView.timestamp"></a>

#### timestamp

Time when record added

<a id="models.EndpointPurgeView.profiler_server"></a>

#### profiler\_server

Profiler server

<a id="models.EndpointPurgeView.endpoint_purge_rule"></a>

#### endpoint\_purge\_rule

Endpoint purge rule

<a id="models.EndpointPurgeView.endpoint_count"></a>

#### endpoint\_count

Number of endpoints

<a id="models.ExtIdSrcActiveDirectory"></a>

## ExtIdSrcActiveDirectory Objects

```python
@dataclass
class ExtIdSrcActiveDirectory()
```

List of Active Directory Identity Stores

<a id="models.ExtIdSrcActiveDirectory.name"></a>

#### name

Name of active directory

<a id="models.ExtIdSrcCertAuthProfile"></a>

## ExtIdSrcCertAuthProfile Objects

```python
@dataclass
class ExtIdSrcCertAuthProfile()
```

List of Certificate Authentication Profiles

<a id="models.ExtIdSrcCertAuthProfile.name"></a>

#### name

Name of Certificate Authentication Profile

<a id="models.ExtIdSrcCertAuthProfile.description"></a>

#### description

Description of Certificate Authentication Profile

<a id="models.ExtIdSrcLdap"></a>

## ExtIdSrcLdap Objects

```python
@dataclass
class ExtIdSrcLdap()
```

List of LDAP Identity Sources

<a id="models.ExtIdSrcLdap.name"></a>

#### name

Name of LDAP Identity Store

<a id="models.ExtIdSrcLdap.description"></a>

#### description

Description of LDAP Identity Store

<a id="models.ExtIdSrcOdbc"></a>

## ExtIdSrcOdbc Objects

```python
@dataclass
class ExtIdSrcOdbc()
```

List of ODBC Identity Sources

<a id="models.ExtIdSrcOdbc.name"></a>

#### name

Name of ODBC Identity Store

<a id="models.ExtIdSrcOdbc.description"></a>

#### description

Description of ODBC Identity Store

<a id="models.ExtIdSrcRadiusToken"></a>

## ExtIdSrcRadiusToken Objects

```python
@dataclass
class ExtIdSrcRadiusToken()
```

List of RADIUS Token Identity Sources

<a id="models.ExtIdSrcRadiusToken.name"></a>

#### name

Name of RADIUS Token Identity Sources

<a id="models.ExtIdSrcRadiusToken.description"></a>

#### description

Description of RADIUS Token Identity Sources

<a id="models.ExtIdSrcRest"></a>

## ExtIdSrcRest Objects

```python
@dataclass
class ExtIdSrcRest()
```

List of REST ID Stores

<a id="models.ExtIdSrcRest.name"></a>

#### name

Name of REST ID store

<a id="models.ExtIdSrcRest.description"></a>

#### description

Description of REST ID store

<a id="models.ExtIdSrcRsaSecurid"></a>

## ExtIdSrcRsaSecurid Objects

```python
@dataclass
class ExtIdSrcRsaSecurid()
```

List of RSA SecurID Identity Sources

<a id="models.ExtIdSrcRsaSecurid.name"></a>

#### name

Name of RSA SecurID Identity Sources

<a id="models.ExtIdSrcSamlIdProviders"></a>

## ExtIdSrcSamlIdProviders Objects

```python
@dataclass
class ExtIdSrcSamlIdProviders()
```

List of SAML Identity Providers

<a id="models.ExtIdSrcSamlIdProviders.name"></a>

#### name

Name of SAML Identity Providers

<a id="models.ExtIdSrcSamlIdProviders.description"></a>

#### description

Description of SAML Identity Providers

<a id="models.ExtIdSrcSocialLogin"></a>

## ExtIdSrcSocialLogin Objects

```python
@dataclass
class ExtIdSrcSocialLogin()
```

List of Social Login Identity Stores

<a id="models.ExtIdSrcSocialLogin.name"></a>

#### name

Name of Social Login Identity Store

<a id="models.ExtIdSrcSocialLogin.description"></a>

#### description

Description of Social Login Identity Store

<a id="models.FailureCodeCause"></a>

## FailureCodeCause Objects

```python
@dataclass
class FailureCodeCause()
```

Provides details of various failure causes and respective codes

<a id="models.FailureCodeCause.failure_code"></a>

#### failure\_code

Specifies the failure code

<a id="models.FailureCodeCause.failure_cause"></a>

#### failure\_cause

Specifies the failure cause

<a id="models.GuestAccounting"></a>

## GuestAccounting Objects

```python
@dataclass
class GuestAccounting()
```

Details of all users assigned to guest identity groups appear in this report

<a id="models.GuestAccounting.logged_at"></a>

#### logged\_at

Shows the time when the syslog was processed and stored by the Monitoring node

<a id="models.GuestAccounting.identity"></a>

#### identity

Specifies the identity of the user

<a id="models.GuestAccounting.time_spent"></a>

#### time\_spent

Specifies the time spent

<a id="models.GuestAccounting.logged_in"></a>

#### logged\_in

Specifies the logged in time

<a id="models.GuestAccounting.logged_out"></a>

#### logged\_out

Specifies the logged out time

<a id="models.GuestAccounting.endpoint_id"></a>

#### endpoint\_id

Specifies the endpoint ID

<a id="models.GuestAccounting.ip_address"></a>

#### ip\_address

Specifies the IP address

<a id="models.GuestDeviceloginAudit"></a>

## GuestDeviceloginAudit Objects

```python
@dataclass
class GuestDeviceloginAudit()
```

Tracks login activity by employees at the my device portal and device related operation performed by the users in the my device portal

<a id="models.GuestDeviceloginAudit.logged_at"></a>

#### logged\_at

Shows the time when the syslog was processed and stored by the Monitoring node

<a id="models.GuestDeviceloginAudit.username"></a>

#### username

User name of user

<a id="models.GuestDeviceloginAudit.message_code"></a>

#### message\_code

Syslog message code

<a id="models.GuestDeviceloginAudit.first_name"></a>

#### first\_name

First Name of user

<a id="models.GuestDeviceloginAudit.last_name"></a>

#### last\_name

Last Name of user

<a id="models.GuestDeviceloginAudit.identity_group"></a>

#### identity\_group

Identity group to which users belongs to

<a id="models.GuestDeviceloginAudit.email_address"></a>

#### email\_address

Email address of the user

<a id="models.GuestDeviceloginAudit.phone_number"></a>

#### phone\_number

Phone Number of user

<a id="models.GuestDeviceloginAudit.company"></a>

#### company

Company of the user

<a id="models.GuestDeviceloginAudit.static_assignment"></a>

#### static\_assignment

Specifies the endpoint static assignment status

<a id="models.GuestDeviceloginAudit.endpoint_profiler_server"></a>

#### endpoint\_profiler\_server

ISE node which profiled the endpoint

<a id="models.GuestDeviceloginAudit.nad_address"></a>

#### nad\_address

IP address of NAD

<a id="models.GuestDeviceloginAudit.nas_ip_address"></a>

#### nas\_ip\_address

IP address of NAS

<a id="models.GuestDeviceloginAudit.identity_store_name"></a>

#### identity\_store\_name

Specifies the name of the identity store

<a id="models.GuestDeviceloginAudit.identity_store_guid"></a>

#### identity\_store\_guid

ID of Identity store in which user belongs

<a id="models.GuestDeviceloginAudit.description"></a>

#### description

Description of user

<a id="models.GuestDeviceloginAudit.user_details"></a>

#### user\_details

Details of the user

<a id="models.GuestDeviceloginAudit.portal_name"></a>

#### portal\_name

Name of guest portal used

<a id="models.GuestDeviceloginAudit.device_name"></a>

#### device\_name

Name of device used

<a id="models.GuestDeviceloginAudit.device_details"></a>

#### device\_details

Details of the device

<a id="models.GuestDeviceloginAudit.mac_address"></a>

#### mac\_address

MAC address of Device

<a id="models.GuestDeviceloginAudit.ip_address"></a>

#### ip\_address

IP address of Device

<a id="models.GuestDeviceloginAudit.operation"></a>

#### operation

Operation that the user performed

<a id="models.GuestDeviceloginAudit.result"></a>

#### result

Status of the user operation

<a id="models.GuestDeviceloginAudit.failure_reason"></a>

#### failure\_reason

Specifies the failure reason

<a id="models.GuestDeviceloginAudit.auth_identity_store"></a>

#### auth\_identity\_store

Specifies the authentication identity store

<a id="models.GuestDeviceloginAudit.server"></a>

#### server

Shows the name of the ISE node through which the access request is processed.

<a id="models.KeyPerformanceMetrics"></a>

## KeyPerformanceMetrics Objects

```python
@dataclass
class KeyPerformanceMetrics()
```

It will provides details of key performance metrics like average TPS, average load etc.,

<a id="models.KeyPerformanceMetrics.logged_time"></a>

#### logged\_time

Time data is collected

<a id="models.KeyPerformanceMetrics.ise_node"></a>

#### ise\_node

ISE Node in deployment

<a id="models.KeyPerformanceMetrics.radius_requests_hr"></a>

#### radius\_requests\_hr

Number of radius requests per hour for selected PSN server

<a id="models.KeyPerformanceMetrics.logged_to_mnt_hr"></a>

#### logged\_to\_mnt\_hr

Number of requests logged to MNT database for selected PSN server

<a id="models.KeyPerformanceMetrics.noise_hr"></a>

#### noise\_hr

Calculated as difference between radius requests and logged to MnT per hour

<a id="models.KeyPerformanceMetrics.suppression_hr"></a>

#### suppression\_hr

Calculated as percentage of Noise w.r.t. radius requests per hour for selected PSN server

<a id="models.KeyPerformanceMetrics.avg_load"></a>

#### avg\_load

Average server load for selected server

<a id="models.KeyPerformanceMetrics.max_load"></a>

#### max\_load

Maximum server load for selected server

<a id="models.KeyPerformanceMetrics.avg_latency_per_req"></a>

#### avg\_latency\_per\_req

Average latency per radius request for selected PSN server

<a id="models.KeyPerformanceMetrics.avg_tps"></a>

#### avg\_tps

Average transactions per second

<a id="models.LogicalProfiles"></a>

## LogicalProfiles Objects

```python
@dataclass
class LogicalProfiles()
```

Displays all the logical profiles that exist along with their assigned policies

<a id="models.LogicalProfiles.logical_profile"></a>

#### logical\_profile

Name of logical Profile

<a id="models.LogicalProfiles.system_type"></a>

#### system\_type

Type of logical profile like admin created or Cisco provided

<a id="models.LogicalProfiles.description"></a>

#### description

Description

<a id="models.LogicalProfiles.assigned_policies"></a>

#### assigned\_policies

Profiling policy assigned to logical profile.

<a id="models.MisconfiguredNasView"></a>

## MisconfiguredNasView Objects

```python
@dataclass
class MisconfiguredNasView()
```

Provides information about NADs with inaccurate accounting frequency typically when sending accounting information frequently

<a id="models.MisconfiguredNasView.id"></a>

#### id

Database unique ID

<a id="models.MisconfiguredNasView.timestamp"></a>

#### timestamp

Time when record added

<a id="models.MisconfiguredNasView.ise_node"></a>

#### ise\_node

Displays the hostname of the ISE server

<a id="models.MisconfiguredNasView.message_code"></a>

#### message\_code

Displays the message code

<a id="models.MisconfiguredNasView.nas_ip_address"></a>

#### nas\_ip\_address

IP address of NAS

<a id="models.MisconfiguredNasView.calling_station_id"></a>

#### calling\_station\_id

Calling station ID

<a id="models.MisconfiguredNasView.detail_info"></a>

#### detail\_info

Displays the detailed info

<a id="models.MisconfiguredNasView.failed_attempts"></a>

#### failed\_attempts

Failed attempts

<a id="models.MisconfiguredNasView.failed_times"></a>

#### failed\_times

Failed times

<a id="models.MisconfiguredNasView.other_attributes"></a>

#### other\_attributes

Other attributes

<a id="models.MisconfiguredNasView.nas_ipv6_address"></a>

#### nas\_ipv6\_address

NAS IPV6 address

<a id="models.MisconfiguredNasView.timestamp_timezone"></a>

#### timestamp\_timezone

Time with timezone when record added

<a id="models.MisconfiguredNasView.failed_times_hours"></a>

#### failed\_times\_hours

Failed times in hours

<a id="models.MisconfiguredNasView.message_text"></a>

#### message\_text

Displays the message text

<a id="models.MisconfiguredSupplicantsView"></a>

## MisconfiguredSupplicantsView Objects

```python
@dataclass
class MisconfiguredSupplicantsView()
```

Provides a list of mis-configured supplicants along with the statistics due to failed attempts that are performed by a specific supplicant

<a id="models.MisconfiguredSupplicantsView.message_text"></a>

#### message\_text

Displays the message text

<a id="models.MisconfiguredSupplicantsView.framed_ipv6_address"></a>

#### framed\_ipv6\_address

Framed IPV6 address

<a id="models.MisconfiguredSupplicantsView.id"></a>

#### id

Database unique ID

<a id="models.MisconfiguredSupplicantsView.timestamp_timezone"></a>

#### timestamp\_timezone

Time with timezone when record added

<a id="models.MisconfiguredSupplicantsView.timestamp"></a>

#### timestamp

Time when record added

<a id="models.MisconfiguredSupplicantsView.ise_node"></a>

#### ise\_node

Displays the hostname of the ISE server

<a id="models.MisconfiguredSupplicantsView.message_code"></a>

#### message\_code

Displays the message code

<a id="models.MisconfiguredSupplicantsView.username"></a>

#### username

User's claimed identity

<a id="models.MisconfiguredSupplicantsView.user_type"></a>

#### user\_type

User type

<a id="models.MisconfiguredSupplicantsView.calling_station_id"></a>

#### calling\_station\_id

Calling station ID

<a id="models.MisconfiguredSupplicantsView.access_service"></a>

#### access\_service

Access service

<a id="models.MisconfiguredSupplicantsView.framed_ip_address"></a>

#### framed\_ip\_address

Framed IP address

<a id="models.MisconfiguredSupplicantsView.identity_store"></a>

#### identity\_store

Identity store

<a id="models.MisconfiguredSupplicantsView.identity_group"></a>

#### identity\_group

Identity group

<a id="models.MisconfiguredSupplicantsView.audit_session_id"></a>

#### audit\_session\_id

Unique numeric string identifying the server session

<a id="models.MisconfiguredSupplicantsView.authentication_method"></a>

#### authentication\_method

Authentication method

<a id="models.MisconfiguredSupplicantsView.authentication_protocol"></a>

#### authentication\_protocol

Authentication protocol

<a id="models.MisconfiguredSupplicantsView.service_type"></a>

#### service\_type

The Type of Service the user has requested

<a id="models.MisconfiguredSupplicantsView.network_device_name"></a>

#### network\_device\_name

Network device name

<a id="models.MisconfiguredSupplicantsView.device_type"></a>

#### device\_type

Device type

<a id="models.MisconfiguredSupplicantsView.location"></a>

#### location

Location

<a id="models.MisconfiguredSupplicantsView.nas_ip_address"></a>

#### nas\_ip\_address

IP address of NAS

<a id="models.MisconfiguredSupplicantsView.nas_port_id"></a>

#### nas\_port\_id

NAS port ID

<a id="models.MisconfiguredSupplicantsView.nas_port_type"></a>

#### nas\_port\_type

NAS port type

<a id="models.MisconfiguredSupplicantsView.selected_authorization_profiles"></a>

#### selected\_authorization\_profiles

Authorization profile used after authentication

<a id="models.MisconfiguredSupplicantsView.posture_status"></a>

#### posture\_status

Posture status

<a id="models.MisconfiguredSupplicantsView.security_group"></a>

#### security\_group

Security group

<a id="models.MisconfiguredSupplicantsView.failure_reason"></a>

#### failure\_reason

Failure reason

<a id="models.MisconfiguredSupplicantsView.response"></a>

#### response

Displays the response

<a id="models.MisconfiguredSupplicantsView.execution_steps"></a>

#### execution\_steps

Execution steps

<a id="models.MisconfiguredSupplicantsView.other_attributes"></a>

#### other\_attributes

Other attributes

<a id="models.MisconfiguredSupplicantsView.response_time"></a>

#### response\_time

Response time

<a id="models.MisconfiguredSupplicantsView.passed"></a>

#### passed

Passed flag

<a id="models.MisconfiguredSupplicantsView.failed"></a>

#### failed

Failed flag

<a id="models.MisconfiguredSupplicantsView.credential_check"></a>

#### credential\_check

Credential check

<a id="models.MisconfiguredSupplicantsView.endpoint_profile"></a>

#### endpoint\_profile

Endpoint matched profile

<a id="models.MisconfiguredSupplicantsView.mdm_server_name"></a>

#### mdm\_server\_name

MDM server name

<a id="models.MisconfiguredSupplicantsView.nas_ipv6_address"></a>

#### nas\_ipv6\_address

NAS IPV6 address

<a id="models.NetworkAccessUsers"></a>

## NetworkAccessUsers Objects

```python
@dataclass
class NetworkAccessUsers()
```

List of all the internal users in ISE

<a id="models.NetworkAccessUsers.id"></a>

#### id

Database ID of Internal User

<a id="models.NetworkAccessUsers.status"></a>

#### status

Enabled or Disabled

<a id="models.NetworkAccessUsers.username"></a>

#### username

Name of User

<a id="models.NetworkAccessUsers.description"></a>

#### description

Description of User

<a id="models.NetworkAccessUsers.first_name"></a>

#### first\_name

First Name of User

<a id="models.NetworkAccessUsers.last_name"></a>

#### last\_name

Last Name of User

<a id="models.NetworkAccessUsers.email_address"></a>

#### email\_address

Email Address of User

<a id="models.NetworkAccessUsers.identity_group"></a>

#### identity\_group

List of Identity Group ID to which user belongs

<a id="models.NetworkAccessUsers.is_admin"></a>

#### is\_admin

Shows if user is admin

<a id="models.NetworkAccessUsers.allow_password_change_after_login"></a>

#### allow\_password\_change\_after\_login

Specifies if password change is allowed after login

<a id="models.NetworkAccessUsers.current_successful_login_time"></a>

#### current\_successful\_login\_time

Specifies the current successful login time

<a id="models.NetworkAccessUsers.last_successful_login_time"></a>

#### last\_successful\_login\_time

Specifies the last successful login time

<a id="models.NetworkAccessUsers.last_unsuccessful_login_time"></a>

#### last\_unsuccessful\_login\_time

Specifies the last unsuccessful login time

<a id="models.NetworkAccessUsers.success_login_ipaddress"></a>

#### success\_login\_ipaddress

Specifies the success login IP address

<a id="models.NetworkAccessUsers.failed_login_ipaddress"></a>

#### failed\_login\_ipaddress

Specifies the failed login IP address

<a id="models.NetworkAccessUsers.expiry_date_enabled"></a>

#### expiry\_date\_enabled

Specifies the expiry date enabled

<a id="models.NetworkAccessUsers.expiry_date"></a>

#### expiry\_date

Specifies the expiry date

<a id="models.NetworkAccessUsers.account_name_alias"></a>

#### account\_name\_alias

Specifies the account name alias

<a id="models.NetworkAccessUsers.password_last_updated_on"></a>

#### password\_last\_updated\_on

Specifies when the password was last updated

<a id="models.NetworkAccessUsers.password_never_expires"></a>

#### password\_never\_expires

Specifies if the password expired or not

<a id="models.NetworkAccessUsers.alarm_emailable"></a>

#### alarm\_emailable

Specifies if the user receives system alarms

<a id="models.NetworkDevices"></a>

## NetworkDevices Objects

```python
@dataclass
class NetworkDevices()
```

Gives the network device information which is configured in ISE

<a id="models.NetworkDevices.id"></a>

#### id

Database unique ID

<a id="models.NetworkDevices.name"></a>

#### name

Name

<a id="models.NetworkDevices.ip_mask"></a>

#### ip\_mask

IP address/mask

<a id="models.NetworkDevices.profile_name"></a>

#### profile\_name

Name of the profile

<a id="models.NetworkDevices.location"></a>

#### location

Device location

<a id="models.NetworkDevices.type"></a>

#### type

Device type

<a id="models.NetworkDeviceGroups"></a>

## NetworkDeviceGroups Objects

```python
@dataclass
class NetworkDeviceGroups()
```

This provides details of all the network device groups

<a id="models.NetworkDeviceGroups.id"></a>

#### id

Database unique ID

<a id="models.NetworkDeviceGroups.name"></a>

#### name

Name

<a id="models.NetworkDeviceGroups.description"></a>

#### description

Description

<a id="models.NetworkDeviceGroups.created_by"></a>

#### created\_by

Name of the user

<a id="models.NetworkDeviceGroups.create_time"></a>

#### create\_time

Time of creation

<a id="models.NetworkDeviceGroups.update_time"></a>

#### update\_time

Time of updating

<a id="models.NetworkDeviceGroups.active_status"></a>

#### active\_status

Active/Inactive

<a id="models.NodeList"></a>

## NodeList Objects

```python
@dataclass
class NodeList()
```

Provide information of all the nodes of deployment

<a id="models.NodeList.hostname"></a>

#### hostname

Hostname

<a id="models.NodeList.node_type"></a>

#### node\_type

Personas enabled on the node

<a id="models.NodeList.gateway"></a>

#### gateway

Default gateway configured

<a id="models.NodeList.node_role"></a>

#### node\_role

Standalone or multi-node

<a id="models.NodeList.active_status"></a>

#### active\_status

Active/Inactive

<a id="models.NodeList.replication_status"></a>

#### replication\_status

Status of replication

<a id="models.NodeList.pdp_services"></a>

#### pdp\_services

Services enabled on the node

<a id="models.NodeList.host_alias"></a>

#### host\_alias

FQDN

<a id="models.NodeList.create_time"></a>

#### create\_time

Time of creation of record

<a id="models.NodeList.update_time"></a>

#### update\_time

Time of updating

<a id="models.NodeList.xgrid_enabled"></a>

#### xgrid\_enabled

PxGrid enabled status

<a id="models.NodeList.xgrid_peer"></a>

#### xgrid\_peer

PxGrid peer

<a id="models.NodeList.udi_pid"></a>

#### udi\_pid

Product Identifier

<a id="models.NodeList.udi_vid"></a>

#### udi\_vid

Version Identifier

<a id="models.NodeList.udi_sn"></a>

#### udi\_sn

Serial Number

<a id="models.NodeList.udi_pt"></a>

#### udi\_pt

Node type virtual or physical

<a id="models.NodeList.patch_version"></a>

#### patch\_version

Patch version

<a id="models.NodeList.pic_node"></a>

#### pic\_node

PIC node

<a id="models.NodeList.installation_type"></a>

#### installation\_type

Installation type

<a id="models.NodeList.vm_info"></a>

#### vm\_info

Virtual machine details

<a id="models.NodeList.api_node"></a>

#### api\_node

API node

<a id="models.OpenapiOperations"></a>

## OpenapiOperations Objects

```python
@dataclass
class OpenapiOperations()
```

Provides details about any configuration changes or data access performed using the OpenAPI framework

<a id="models.OpenapiOperations.logged_at"></a>

#### logged\_at

Time when record logged

<a id="models.OpenapiOperations.message_text"></a>

#### message\_text

Displays the message text

<a id="models.OpenapiOperations.request_time"></a>

#### request\_time

Displays the request time

<a id="models.OpenapiOperations.request_name"></a>

#### request\_name

Displays the request name

<a id="models.OpenapiOperations.http_method"></a>

#### http\_method

Displays the http method

<a id="models.OpenapiOperations.request_id"></a>

#### request\_id

Displays the request ID

<a id="models.OpenapiOperations.request_body"></a>

#### request\_body

Displays the request body

<a id="models.OpenapiOperations.response"></a>

#### response

Displays the response

<a id="models.OpenapiOperations.http_code"></a>

#### http\_code

Displays the http code

<a id="models.OpenapiOperations.http_status"></a>

#### http\_status

Displays the http status

<a id="models.OpenapiOperations.error_message"></a>

#### error\_message

Displays the error if any

<a id="models.OpenapiOperations.server"></a>

#### server

Displays the ISE hostname

<a id="models.OpenapiOperations.response_duration"></a>

#### response\_duration

Displays the response duration

<a id="models.OpenapiOperations.client_ip"></a>

#### client\_ip

Displays the client IP address

<a id="models.OpenapiOperations.administrator"></a>

#### administrator

Displays the admin name

<a id="models.PolicySets"></a>

## PolicySets Objects

```python
@dataclass
class PolicySets()
```

Provides a list of all policy sets currently configured in the system

<a id="models.PolicySets.id"></a>

#### id

Database unique ID

<a id="models.PolicySets.create_time"></a>

#### create\_time

Time when record was created

<a id="models.PolicySets.update_time"></a>

#### update\_time

Time when record was last updated

<a id="models.PolicySets.policyset_status"></a>

#### policyset\_status

Specifies if the policy set status is active

<a id="models.PolicySets.policyset_name"></a>

#### policyset\_name

Specifies the policy set name

<a id="models.PolicySets.description"></a>

#### description

Specifies the policy sets description

<a id="models.PostureAssessmentByCondition"></a>

## PostureAssessmentByCondition Objects

```python
@dataclass
class PostureAssessmentByCondition()
```

The report provides details about policy condition and their status

<a id="models.PostureAssessmentByCondition.logged_at"></a>

#### logged\_at

Specifies the time at which policy was enforced

<a id="models.PostureAssessmentByCondition.policy"></a>

#### policy

Specifies the posture policy

<a id="models.PostureAssessmentByCondition.policy_status"></a>

#### policy\_status

Displays the policy condition status

<a id="models.PostureAssessmentByCondition.enforcement_name"></a>

#### enforcement\_name

Displays the posture requirement name

<a id="models.PostureAssessmentByCondition.enforcement_type"></a>

#### enforcement\_type

Enforcement type of the requirement i.e. mandatory, optional or audit

<a id="models.PostureAssessmentByCondition.enforcement_status"></a>

#### enforcement\_status

Displays the status of the posture requirement enforcement

<a id="models.PostureAssessmentByCondition.ise_node"></a>

#### ise\_node

Displays the hostname of the ISE server

<a id="models.PostureAssessmentByCondition.message_code"></a>

#### message\_code

Displays the message code of the posture syslog

<a id="models.PostureAssessmentByCondition.request_time"></a>

#### request\_time

Displays the request time

<a id="models.PostureAssessmentByCondition.response_time"></a>

#### response\_time

Displays the response time

<a id="models.PostureAssessmentByCondition.endpoint_id"></a>

#### endpoint\_id

Endpoint MAC address

<a id="models.PostureAssessmentByCondition.endpoint_os"></a>

#### endpoint\_os

Endpoint operating system

<a id="models.PostureAssessmentByCondition.posture_agent_version"></a>

#### posture\_agent\_version

Displays the version of the posture agent

<a id="models.PostureAssessmentByCondition.posture_status"></a>

#### posture\_status

Posture status i.e. pending, compliant, non-compliant etc

<a id="models.PostureAssessmentByCondition.posture_policy_matched"></a>

#### posture\_policy\_matched

Displays the posture policy matched

<a id="models.PostureAssessmentByCondition.posture_report"></a>

#### posture\_report

Displays the posture report

<a id="models.PostureAssessmentByCondition.anti_virus_installed"></a>

#### anti\_virus\_installed

Displays the installed anti-virus

<a id="models.PostureAssessmentByCondition.anti_spyware_installed"></a>

#### anti\_spyware\_installed

Displays the installed anti-spyware

<a id="models.PostureAssessmentByCondition.failure_reason"></a>

#### failure\_reason

Specifies the reason for failure

<a id="models.PostureAssessmentByCondition.pra_enforcement"></a>

#### pra\_enforcement

Displays the status of periodic reassessment enforcement

<a id="models.PostureAssessmentByCondition.pra_interval"></a>

#### pra\_interval

Periodic reassessment interval configured

<a id="models.PostureAssessmentByCondition.pra_action"></a>

#### pra\_action

Periodic reassessment action configured

<a id="models.PostureAssessmentByCondition.pra_grace_time"></a>

#### pra\_grace\_time

Periodic reassessment grace time configured

<a id="models.PostureAssessmentByCondition.identity"></a>

#### identity

Displays the user name

<a id="models.PostureAssessmentByCondition.session_id"></a>

#### session\_id

Shows the session ID

<a id="models.PostureAssessmentByCondition.feed_url"></a>

#### feed\_url

Shows the update feed URL

<a id="models.PostureAssessmentByCondition.num_of_updates"></a>

#### num\_of\_updates

Displays the number of updates

<a id="models.PostureAssessmentByCondition.user_agreement_status"></a>

#### user\_agreement\_status

Displays the status of the user agreement

<a id="models.PostureAssessmentByCondition.system_name"></a>

#### system\_name

Hostname of the endpoint

<a id="models.PostureAssessmentByCondition.system_domain"></a>

#### system\_domain

Displays the domain name of the endpoint

<a id="models.PostureAssessmentByCondition.system_user"></a>

#### system\_user

Displays the system user

<a id="models.PostureAssessmentByCondition.system_user_domain"></a>

#### system\_user\_domain

Displays the system user domain

<a id="models.PostureAssessmentByCondition.ip_address"></a>

#### ip\_address

IP address of the endpoint

<a id="models.PostureAssessmentByCondition.am_installed"></a>

#### am\_installed

Displays the anti-malware installed on the endpoint

<a id="models.PostureAssessmentByCondition.condition_name"></a>

#### condition\_name

Specifies the posture condition which was matched

<a id="models.PostureAssessmentByCondition.condition_status"></a>

#### condition\_status

Displays the status of the condition i.e. passed, failed or skipped

<a id="models.PostureAssessmentByCondition.location"></a>

#### location

Displays the network device group location

<a id="models.PostureAssessmentByEndpoint"></a>

## PostureAssessmentByEndpoint Objects

```python
@dataclass
class PostureAssessmentByEndpoint()
```

This view shows which endpoints have been subject to posture assessment and also gives the administrator the ability to view the details of each endpoint's posture assessment

<a id="models.PostureAssessmentByEndpoint.id"></a>

#### id

Database unique ID

<a id="models.PostureAssessmentByEndpoint.timestamp_timezone"></a>

#### timestamp\_timezone

Time with timezone when record added

<a id="models.PostureAssessmentByEndpoint.timestamp"></a>

#### timestamp

Time when record added

<a id="models.PostureAssessmentByEndpoint.ise_node"></a>

#### ise\_node

Hostname of ISE node

<a id="models.PostureAssessmentByEndpoint.message_code"></a>

#### message\_code

Displays the message code of the posture syslog

<a id="models.PostureAssessmentByEndpoint.request_time"></a>

#### request\_time

Displays the request time

<a id="models.PostureAssessmentByEndpoint.response_time"></a>

#### response\_time

Displays the response time

<a id="models.PostureAssessmentByEndpoint.endpoint_mac_address"></a>

#### endpoint\_mac\_address

MAC address of the endpoint

<a id="models.PostureAssessmentByEndpoint.endpoint_operating_system"></a>

#### endpoint\_operating\_system

Operating system of the endpoint

<a id="models.PostureAssessmentByEndpoint.posture_agent_version"></a>

#### posture\_agent\_version

Displays the version of the posture agent

<a id="models.PostureAssessmentByEndpoint.posture_status"></a>

#### posture\_status

Posture status i.e. pending, compliant, non-compliant etc

<a id="models.PostureAssessmentByEndpoint.posture_policy_matched"></a>

#### posture\_policy\_matched

Displays the posture policy matched

<a id="models.PostureAssessmentByEndpoint.posture_report"></a>

#### posture\_report

Displays the posture report

<a id="models.PostureAssessmentByEndpoint.anti_virus_installed"></a>

#### anti\_virus\_installed

Displays the installed anti-virus

<a id="models.PostureAssessmentByEndpoint.anti_spyware_installed"></a>

#### anti\_spyware\_installed

Displays the installed anti-spyware

<a id="models.PostureAssessmentByEndpoint.failure_reason"></a>

#### failure\_reason

Specifies the reason for failure

<a id="models.PostureAssessmentByEndpoint.pra_enforcement_flag"></a>

#### pra\_enforcement\_flag

Displays the status of periodic reassessment enforcement

<a id="models.PostureAssessmentByEndpoint.pra_interval"></a>

#### pra\_interval

Periodic reassessment interval configured

<a id="models.PostureAssessmentByEndpoint.pra_action"></a>

#### pra\_action

Periodic reassessment action configured

<a id="models.PostureAssessmentByEndpoint.username"></a>

#### username

Displays the username

<a id="models.PostureAssessmentByEndpoint.session_id"></a>

#### session\_id

Shows the session ID

<a id="models.PostureAssessmentByEndpoint.feed_url"></a>

#### feed\_url

Shows the update feed URL

<a id="models.PostureAssessmentByEndpoint.num_of_updates"></a>

#### num\_of\_updates

Number of updates

<a id="models.PostureAssessmentByEndpoint.user_agreement_status"></a>

#### user\_agreement\_status

Displays the status of the user agreement

<a id="models.PostureAssessmentByEndpoint.system_name"></a>

#### system\_name

Hostname of the endpoint

<a id="models.PostureAssessmentByEndpoint.system_domain"></a>

#### system\_domain

Displays the domain name of the endpoint

<a id="models.PostureAssessmentByEndpoint.system_user"></a>

#### system\_user

Displays the system user

<a id="models.PostureAssessmentByEndpoint.system_user_domain"></a>

#### system\_user\_domain

Displays the system user domain

<a id="models.PostureAssessmentByEndpoint.ip_address"></a>

#### ip\_address

IP address of the endpoint

<a id="models.PostureAssessmentByEndpoint.pra_grace_time"></a>

#### pra\_grace\_time

Periodic reassessment grace time configured

<a id="models.PostureAssessmentByEndpoint.nad_location"></a>

#### nad\_location

Location of NAD

<a id="models.PostureAssessmentByEndpoint.am_installed"></a>

#### am\_installed

Displays the anti-malware installed on the endpoint

<a id="models.PostureAssessmentByEndpoint.message_text"></a>

#### message\_text

Displays the message text

<a id="models.PostureGracePeriod"></a>

## PostureGracePeriod Objects

```python
@dataclass
class PostureGracePeriod()
```

Lists the MAC address and the  posture grace period expiration

<a id="models.PostureGracePeriod.mac_list"></a>

#### mac\_list

Specifies the list of MAC address

<a id="models.PostureGracePeriod.last_grace_expiry"></a>

#### last\_grace\_expiry

Specifies the posture grace period expiration time

<a id="models.PostureScriptCondition"></a>

## PostureScriptCondition Objects

```python
@dataclass
class PostureScriptCondition()
```

Provides execution status for each requirement that uses script condition.

<a id="models.PostureScriptCondition.logged_at"></a>

#### logged\_at

Shows the time when the syslog was processed and stored by the Monitoring node

<a id="models.PostureScriptCondition.ise_node"></a>

#### ise\_node

The name of the ISE Node

<a id="models.PostureScriptCondition.status"></a>

#### status

The execution status of the condition

<a id="models.PostureScriptCondition.policy_name"></a>

#### policy\_name

The name of the policy being applied

<a id="models.PostureScriptCondition.requirement_name"></a>

#### requirement\_name

The name of the requirement

<a id="models.PostureScriptCondition.session_id"></a>

#### session\_id

The Session ID

<a id="models.PostureScriptCondition.endpoint_id"></a>

#### endpoint\_id

The Endpoint ID

<a id="models.PostureScriptCondition.udid"></a>

#### udid

The UDID

<a id="models.PostureScriptCondition.condition_name"></a>

#### condition\_name

The name of the condition

<a id="models.PostureScriptRemediation"></a>

## PostureScriptRemediation Objects

```python
@dataclass
class PostureScriptRemediation()
```

Provides execution status for each requirement that uses script  remediation.

<a id="models.PostureScriptRemediation.logged_at"></a>

#### logged\_at

Shows the time when the syslog was processed and stored by the Monitoring node

<a id="models.PostureScriptRemediation.ise_node"></a>

#### ise\_node

The name of the ISE Node

<a id="models.PostureScriptRemediation.status"></a>

#### status

The execution status of the remediation

<a id="models.PostureScriptRemediation.policy_name"></a>

#### policy\_name

The name of the policy being applied

<a id="models.PostureScriptRemediation.requirement_name"></a>

#### requirement\_name

The name of the requirement

<a id="models.PostureScriptRemediation.session_id"></a>

#### session\_id

The Session ID

<a id="models.PostureScriptRemediation.endpoint_id"></a>

#### endpoint\_id

The Endpoint ID

<a id="models.PostureScriptRemediation.udid"></a>

#### udid

The UDID

<a id="models.PrimaryGuest"></a>

## PrimaryGuest Objects

```python
@dataclass
class PrimaryGuest()
```

The Primary Guest report combines data from various guest reports into a single view. This report collects all guest activity and provides details about the website guest users visit

<a id="models.PrimaryGuest.mac_address"></a>

#### mac\_address

Specifies the MAC address

<a id="models.PrimaryGuest.ip_address"></a>

#### ip\_address

Specifies the IP address

<a id="models.PrimaryGuest.sponsor_username"></a>

#### sponsor\_username

Specifies the sponsor user name

<a id="models.PrimaryGuest.guest_username"></a>

#### guest\_username

Specifies the guest user name

<a id="models.PrimaryGuest.guest_users"></a>

#### guest\_users

Specifies the guest users

<a id="models.PrimaryGuest.operation"></a>

#### operation

Specifies the operation

<a id="models.PrimaryGuest.aup_acceptance"></a>

#### aup\_acceptance

Specifies the AUP acceptance

<a id="models.PrimaryGuest.logged_at"></a>

#### logged\_at

Shows the time when the syslog was stored

<a id="models.PrimaryGuest.message"></a>

#### message

Message for guest

<a id="models.PrimaryGuest.portal_name"></a>

#### portal\_name

Specifies the portal name

<a id="models.PrimaryGuest.result"></a>

#### result

Specifies the result

<a id="models.PrimaryGuest.sponsor_first_name"></a>

#### sponsor\_first\_name

Specifies the sponsor first name

<a id="models.PrimaryGuest.sponsor_last_name"></a>

#### sponsor\_last\_name

Specifies the sponsor last name

<a id="models.PrimaryGuest.identity_group"></a>

#### identity\_group

Specifies the identity group to which user belongs

<a id="models.PrimaryGuest.sponsor_email_address"></a>

#### sponsor\_email\_address

Specifies the sponsor email address

<a id="models.PrimaryGuest.sponsor_phone_number"></a>

#### sponsor\_phone\_number

Specifies the sponsor phone number

<a id="models.PrimaryGuest.sponsor_company"></a>

#### sponsor\_company

Specifies the sponsor company

<a id="models.PrimaryGuest.guest_last_name"></a>

#### guest\_last\_name

Specifies the guest last name

<a id="models.PrimaryGuest.guest_first_name"></a>

#### guest\_first\_name

Specifies the guest first name

<a id="models.PrimaryGuest.guest_email_address"></a>

#### guest\_email\_address

Specifies the guest email address

<a id="models.PrimaryGuest.guest_phone_number"></a>

#### guest\_phone\_number

Specifies the guest phone number

<a id="models.PrimaryGuest.guest_company"></a>

#### guest\_company

Specifies the guest company

<a id="models.PrimaryGuest.guest_status"></a>

#### guest\_status

Specifies the guest status

<a id="models.PrimaryGuest.guest_type"></a>

#### guest\_type

Specifies the guest type

<a id="models.PrimaryGuest.valid_days"></a>

#### valid\_days

Specifies the number of days guest user is valid

<a id="models.PrimaryGuest.from_date"></a>

#### from\_date

Specifies the start date of the guest user

<a id="models.PrimaryGuest.to_date"></a>

#### to\_date

Specifies the end date of the guest user

<a id="models.PrimaryGuest.location"></a>

#### location

Specifies the location of the guest user

<a id="models.PrimaryGuest.ssid"></a>

#### ssid

Specifies the SSID of guest user

<a id="models.PrimaryGuest.group_tag"></a>

#### group\_tag

Specifies the group tag of guest user

<a id="models.PrimaryGuest.guest_person_visited"></a>

#### guest\_person\_visited

Specifies the guest person visited

<a id="models.PrimaryGuest.guest_reason_for_visit"></a>

#### guest\_reason\_for\_visit

Specifies the guest reason for visit

<a id="models.PrimaryGuest.nas_ip_address"></a>

#### nas\_ip\_address

Specifies the NAS IP address

<a id="models.PrimaryGuest.user_link"></a>

#### user\_link

Specifies the user link

<a id="models.PrimaryGuest.guest_link"></a>

#### guest\_link

Specifies the guest link

<a id="models.PrimaryGuest.failure_reason"></a>

#### failure\_reason

Specifies the reason for failure

<a id="models.PrimaryGuest.time_spent"></a>

#### time\_spent

Specifies the time spent

<a id="models.PrimaryGuest.logged_in"></a>

#### logged\_in

Specifies when logged in

<a id="models.PrimaryGuest.logged_out"></a>

#### logged\_out

Specifies when logged out

<a id="models.PrimaryGuest.optional_data"></a>

#### optional\_data

Specifies the optional data

<a id="models.PrimaryGuest.identity_store"></a>

#### identity\_store

Specifies the identity store to which the user belongs

<a id="models.PrimaryGuest.nad_address"></a>

#### nad\_address

Specifies the NAD address

<a id="models.PrimaryGuest.server"></a>

#### server

Specifies the ISE node

<a id="models.PrimaryGuest.sponsor_user_details"></a>

#### sponsor\_user\_details

Specifies the sponsor user details

<a id="models.PrimaryGuest.guest_user_details"></a>

#### guest\_user\_details

Specifies the guest user details

<a id="models.PrimaryGuest.details"></a>

#### details

Specifies the details

<a id="models.ProfiledEndpointsSummary"></a>

## ProfiledEndpointsSummary Objects

```python
@dataclass
class ProfiledEndpointsSummary()
```

Displays profiling details about endpoints that are accessing the network

<a id="models.ProfiledEndpointsSummary.id"></a>

#### id

Database unique ID

<a id="models.ProfiledEndpointsSummary.timestamp"></a>

#### timestamp

Time when record added

<a id="models.ProfiledEndpointsSummary.endpoint_id"></a>

#### endpoint\_id

Endpoint ID

<a id="models.ProfiledEndpointsSummary.endpoint_profile"></a>

#### endpoint\_profile

Endpoint profile

<a id="models.ProfiledEndpointsSummary.source"></a>

#### source

Source name

<a id="models.ProfiledEndpointsSummary.host"></a>

#### host

Host name

<a id="models.ProfiledEndpointsSummary.endpoint_action_name"></a>

#### endpoint\_action\_name

Endpoint action name

<a id="models.ProfiledEndpointsSummary.message_code"></a>

#### message\_code

Message code

<a id="models.ProfiledEndpointsSummary.identity_group"></a>

#### identity\_group

Identity group name

<a id="models.ProfilingPolicies"></a>

## ProfilingPolicies Objects

```python
@dataclass
class ProfilingPolicies()
```

List and details of all endpoint profiles present on ISE

<a id="models.ProfilingPolicies.profiling_policy_name"></a>

#### profiling\_policy\_name

Name of Profiling Policy

<a id="models.ProfilingPolicies.description"></a>

#### description

Description of Profiling Policy

<a id="models.PxgridDirectData"></a>

## PxgridDirectData Objects

```python
@dataclass
class PxgridDirectData()
```

None

<a id="models.PxgridDirectData.edda_id"></a>

#### edda\_id

The correlation identifier as specified in the connector configuration

<a id="models.PxgridDirectData.unique_id"></a>

#### unique\_id

The unique identifier as specified in the connector configuration

<a id="models.RadiusAccounting"></a>

## RadiusAccounting Objects

```python
@dataclass
class RadiusAccounting()
```

This provides details of all the radius accounting records

<a id="models.RadiusAccounting.id"></a>

#### id

Database unique ID

<a id="models.RadiusAccounting.timestamp_timezone"></a>

#### timestamp\_timezone

Time with timezone when record added

<a id="models.RadiusAccounting.ise_node"></a>

#### ise\_node

ISE node

<a id="models.RadiusAccounting.syslog_message_code"></a>

#### syslog\_message\_code

Message code

<a id="models.RadiusAccounting.session_id"></a>

#### session\_id

Session ID

<a id="models.RadiusAccounting.username"></a>

#### username

User's claimed identity

<a id="models.RadiusAccounting.user_type"></a>

#### user\_type

User type

<a id="models.RadiusAccounting.calling_station_id"></a>

#### calling\_station\_id

Calling station ID

<a id="models.RadiusAccounting.acct_session_id"></a>

#### acct\_session\_id

Unique numeric string identifying the server session

<a id="models.RadiusAccounting.acct_status_type"></a>

#### acct\_status\_type

Specifies whether accounting packet starts or stops a bridging, routing, or terminal server session.

<a id="models.RadiusAccounting.acct_session_time"></a>

#### acct\_session\_time

Length of time (in seconds) for which the session has been logged in

<a id="models.RadiusAccounting.service_type"></a>

#### service\_type

The Type of Service the user has requested

<a id="models.RadiusAccounting.framed_protocol"></a>

#### framed\_protocol

Framed protocol

<a id="models.RadiusAccounting.acct_input_octets"></a>

#### acct\_input\_octets

Number of octets received during the session

<a id="models.RadiusAccounting.acct_output_octets"></a>

#### acct\_output\_octets

Number of octets sent during the session

<a id="models.RadiusAccounting.acct_input_packets"></a>

#### acct\_input\_packets

Number of packets received during the session

<a id="models.RadiusAccounting.acct_output_packets"></a>

#### acct\_output\_packets

Number of octets sent during the session

<a id="models.RadiusAccounting.framed_ip_address"></a>

#### framed\_ip\_address

Framed IP address

<a id="models.RadiusAccounting.nas_port"></a>

#### nas\_port

Physical port number of the NAS (Network Access Server) originating the request

<a id="models.RadiusAccounting.nas_ip_address"></a>

#### nas\_ip\_address

The IP address of the NAS originating the request

<a id="models.RadiusAccounting.acct_terminate_cause"></a>

#### acct\_terminate\_cause

Reason a connection was terminated

<a id="models.RadiusAccounting.access_service"></a>

#### access\_service

Access service

<a id="models.RadiusAccounting.audit_session_id"></a>

#### audit\_session\_id

Audit session ID

<a id="models.RadiusAccounting.acct_multi_session_id"></a>

#### acct\_multi\_session\_id

Multi session ID

<a id="models.RadiusAccounting.acct_authentic"></a>

#### acct\_authentic

Authentication

<a id="models.RadiusAccounting.termination_action"></a>

#### termination\_action

0 Default 1 RADIUS-Request

<a id="models.RadiusAccounting.session_timeout"></a>

#### session\_timeout

Session timeout

<a id="models.RadiusAccounting.idle_timeout"></a>

#### idle\_timeout

Idle timeout

<a id="models.RadiusAccounting.acct_interim_interval"></a>

#### acct\_interim\_interval

Number of seconds between each transmittal of an interim update for a specific session

<a id="models.RadiusAccounting.acct_delay_time"></a>

#### acct\_delay\_time

Length of time (in seconds) for which the NAS has been sending the same accounting packet

<a id="models.RadiusAccounting.event_timestamp"></a>

#### event\_timestamp

The date and time that this event occurred on the NAS

<a id="models.RadiusAccounting.nas_identifier"></a>

#### nas\_identifier

NAS ID

<a id="models.RadiusAccounting.nas_port_id"></a>

#### nas\_port\_id

NAS port ID

<a id="models.RadiusAccounting.acct_tunnel_connection"></a>

#### acct\_tunnel\_connection

Tunnel connection

<a id="models.RadiusAccounting.acct_tunnel_packet_lost"></a>

#### acct\_tunnel\_packet\_lost

Packet lost

<a id="models.RadiusAccounting.device_name"></a>

#### device\_name

Network device name

<a id="models.RadiusAccounting.device_groups"></a>

#### device\_groups

Network device group

<a id="models.RadiusAccounting.service_selection_policy"></a>

#### service\_selection\_policy

Service selection policy

<a id="models.RadiusAccounting.identity_store"></a>

#### identity\_store

Identity store

<a id="models.RadiusAccounting.ad_domain"></a>

#### ad\_domain

AD domain

<a id="models.RadiusAccounting.identity_group"></a>

#### identity\_group

Identity group

<a id="models.RadiusAccounting.authorization_policy"></a>

#### authorization\_policy

Authorization policy

<a id="models.RadiusAccounting.failure_reason"></a>

#### failure\_reason

Failure reason

<a id="models.RadiusAccounting.security_group"></a>

#### security\_group

Security group

<a id="models.RadiusAccounting.cisco_h323_setup_time"></a>

#### cisco\_h323\_setup\_time

Cisco H323 setup time

<a id="models.RadiusAccounting.cisco_h323_connect_time"></a>

#### cisco\_h323\_connect\_time

Cisco H323 connect time

<a id="models.RadiusAccounting.cisco_h323_disconnect_time"></a>

#### cisco\_h323\_disconnect\_time

Cisco H323 disconnect time

<a id="models.RadiusAccounting.response_time"></a>

#### response\_time

Response time

<a id="models.RadiusAccounting.started"></a>

#### started

Started

<a id="models.RadiusAccounting.stopped"></a>

#### stopped

Stopped

<a id="models.RadiusAccounting.nas_ipv6_address"></a>

#### nas\_ipv6\_address

NAS IPV6 address

<a id="models.RadiusAccounting.framed_ipv6_address"></a>

#### framed\_ipv6\_address

FRAMED IPV6 address

<a id="models.RadiusAccounting.timestamp"></a>

#### timestamp

Time when record added

<a id="models.RadiusAccounting.vn"></a>

#### vn

Information of Virtual Network

<a id="models.RadiusAccountingWeek"></a>

## RadiusAccountingWeek Objects

```python
@dataclass
class RadiusAccountingWeek()
```

This is performance oriented view which contains all the radius accounting records for the last seven days

<a id="models.RadiusAccountingWeek.id"></a>

#### id

Database unique ID

<a id="models.RadiusAccountingWeek.timestamp_timezone"></a>

#### timestamp\_timezone

Time with timezone when record added

<a id="models.RadiusAccountingWeek.ise_node"></a>

#### ise\_node

ISE node

<a id="models.RadiusAccountingWeek.syslog_message_code"></a>

#### syslog\_message\_code

Message code

<a id="models.RadiusAccountingWeek.session_id"></a>

#### session\_id

Established ISE session ID

<a id="models.RadiusAccountingWeek.username"></a>

#### username

User's claimed identity

<a id="models.RadiusAccountingWeek.user_type"></a>

#### user\_type

User type

<a id="models.RadiusAccountingWeek.calling_station_id"></a>

#### calling\_station\_id

Calling station ID

<a id="models.RadiusAccountingWeek.acct_session_id"></a>

#### acct\_session\_id

Unique numeric string identifying the server session

<a id="models.RadiusAccountingWeek.acct_status_type"></a>

#### acct\_status\_type

Specifies whether accounting packet starts or stops a bridging, routing, or terminal server session.

<a id="models.RadiusAccountingWeek.acct_session_time"></a>

#### acct\_session\_time

Length of time (in seconds) for which the session has been logged in

<a id="models.RadiusAccountingWeek.service_type"></a>

#### service\_type

The Type of Service the user has requested

<a id="models.RadiusAccountingWeek.framed_protocol"></a>

#### framed\_protocol

Framed protocol

<a id="models.RadiusAccountingWeek.acct_input_octets"></a>

#### acct\_input\_octets

Number of octets received during the session

<a id="models.RadiusAccountingWeek.acct_output_octets"></a>

#### acct\_output\_octets

Number of octets sent during the session

<a id="models.RadiusAccountingWeek.acct_input_packets"></a>

#### acct\_input\_packets

Number of packets received during the session

<a id="models.RadiusAccountingWeek.acct_output_packets"></a>

#### acct\_output\_packets

Number of octets sent during the session

<a id="models.RadiusAccountingWeek.framed_ip_address"></a>

#### framed\_ip\_address

Framed IP address

<a id="models.RadiusAccountingWeek.nas_port"></a>

#### nas\_port

Physical port number of the NAS (Network Access Server) originating the request

<a id="models.RadiusAccountingWeek.nas_ip_address"></a>

#### nas\_ip\_address

The IP address of the NAS originating the request

<a id="models.RadiusAccountingWeek.acct_terminate_cause"></a>

#### acct\_terminate\_cause

Reason a connection was terminated

<a id="models.RadiusAccountingWeek.access_service"></a>

#### access\_service

Access service

<a id="models.RadiusAccountingWeek.audit_session_id"></a>

#### audit\_session\_id

Audit session ID

<a id="models.RadiusAccountingWeek.acct_multi_session_id"></a>

#### acct\_multi\_session\_id

Multi session ID

<a id="models.RadiusAccountingWeek.acct_authentic"></a>

#### acct\_authentic

Authentication

<a id="models.RadiusAccountingWeek.termination_action"></a>

#### termination\_action

0 Default 1 RADIUS-Request

<a id="models.RadiusAccountingWeek.session_timeout"></a>

#### session\_timeout

Session timeout

<a id="models.RadiusAccountingWeek.idle_timeout"></a>

#### idle\_timeout

Idle timeout

<a id="models.RadiusAccountingWeek.acct_interim_interval"></a>

#### acct\_interim\_interval

Number of seconds between each transmittal of an interim update for a specific session

<a id="models.RadiusAccountingWeek.acct_delay_time"></a>

#### acct\_delay\_time

Length of time (in seconds) for which the NAS has been sending the same accounting packet

<a id="models.RadiusAccountingWeek.event_timestamp"></a>

#### event\_timestamp

The date and time that this event occurred on the NAS

<a id="models.RadiusAccountingWeek.nas_identifier"></a>

#### nas\_identifier

NAS ID

<a id="models.RadiusAccountingWeek.nas_port_id"></a>

#### nas\_port\_id

NAS port ID

<a id="models.RadiusAccountingWeek.acct_tunnel_connection"></a>

#### acct\_tunnel\_connection

Tunnel connection

<a id="models.RadiusAccountingWeek.acct_tunnel_packet_lost"></a>

#### acct\_tunnel\_packet\_lost

Packet lost

<a id="models.RadiusAccountingWeek.device_name"></a>

#### device\_name

Network device name

<a id="models.RadiusAccountingWeek.device_groups"></a>

#### device\_groups

Network device group

<a id="models.RadiusAccountingWeek.service_selection_policy"></a>

#### service\_selection\_policy

Service selection policy

<a id="models.RadiusAccountingWeek.identity_store"></a>

#### identity\_store

Identity store

<a id="models.RadiusAccountingWeek.ad_domain"></a>

#### ad\_domain

AD domain

<a id="models.RadiusAccountingWeek.identity_group"></a>

#### identity\_group

Identity group

<a id="models.RadiusAccountingWeek.authorization_policy"></a>

#### authorization\_policy

Displays the authorization policy matched

<a id="models.RadiusAccountingWeek.failure_reason"></a>

#### failure\_reason

Failure reason

<a id="models.RadiusAccountingWeek.security_group"></a>

#### security\_group

Security group

<a id="models.RadiusAccountingWeek.cisco_h323_setup_time"></a>

#### cisco\_h323\_setup\_time

Cisco H323 setup time

<a id="models.RadiusAccountingWeek.cisco_h323_connect_time"></a>

#### cisco\_h323\_connect\_time

Cisco H323 connect time

<a id="models.RadiusAccountingWeek.cisco_h323_disconnect_time"></a>

#### cisco\_h323\_disconnect\_time

Cisco H323 disconnect time

<a id="models.RadiusAccountingWeek.response_time"></a>

#### response\_time

Response time

<a id="models.RadiusAccountingWeek.started"></a>

#### started

Started

<a id="models.RadiusAccountingWeek.stopped"></a>

#### stopped

Stopped

<a id="models.RadiusAccountingWeek.nas_ipv6_address"></a>

#### nas\_ipv6\_address

NAS IPV6 address

<a id="models.RadiusAccountingWeek.framed_ipv6_address"></a>

#### framed\_ipv6\_address

Framed IPV6 address

<a id="models.RadiusAccountingWeek.timestamp"></a>

#### timestamp

Time when record added

<a id="models.RadiusAccountingWeek.vn"></a>

#### vn

Information of Virtual Network

<a id="models.RadiusAuthentications"></a>

## RadiusAuthentications Objects

```python
@dataclass
class RadiusAuthentications()
```

This provides details of all the radius authentication records

<a id="models.RadiusAuthentications.id"></a>

#### id

Database unique ID

<a id="models.RadiusAuthentications.timestamp_timezone"></a>

#### timestamp\_timezone

Time with timezone when record added

<a id="models.RadiusAuthentications.ise_node"></a>

#### ise\_node

ISE node

<a id="models.RadiusAuthentications.syslog_message_code"></a>

#### syslog\_message\_code

Message code

<a id="models.RadiusAuthentications.username"></a>

#### username

User's claimed identity

<a id="models.RadiusAuthentications.user_type"></a>

#### user\_type

User type

<a id="models.RadiusAuthentications.calling_station_id"></a>

#### calling\_station\_id

Calling station ID

<a id="models.RadiusAuthentications.access_service"></a>

#### access\_service

Access service

<a id="models.RadiusAuthentications.framed_ip_address"></a>

#### framed\_ip\_address

Framed IP address of user

<a id="models.RadiusAuthentications.identity_store"></a>

#### identity\_store

Identity store of user

<a id="models.RadiusAuthentications.identity_group"></a>

#### identity\_group

User identity group

<a id="models.RadiusAuthentications.audit_session_id"></a>

#### audit\_session\_id

Audit session ID

<a id="models.RadiusAuthentications.authentication_method"></a>

#### authentication\_method

Method of authentication

<a id="models.RadiusAuthentications.authentication_protocol"></a>

#### authentication\_protocol

Protocol of authentication

<a id="models.RadiusAuthentications.service_type"></a>

#### service\_type

The Type of Service the user has requested

<a id="models.RadiusAuthentications.device_name"></a>

#### device\_name

Network device name

<a id="models.RadiusAuthentications.device_type"></a>

#### device\_type

Network device type

<a id="models.RadiusAuthentications.location"></a>

#### location

Network device location

<a id="models.RadiusAuthentications.nas_ip_address"></a>

#### nas\_ip\_address

The IP address of the NAS originating the request

<a id="models.RadiusAuthentications.nas_port_id"></a>

#### nas\_port\_id

Physical port number of the NAS (Network Access Server) originating the request

<a id="models.RadiusAuthentications.nas_port_type"></a>

#### nas\_port\_type

NAS port type

<a id="models.RadiusAuthentications.authorization_profiles"></a>

#### authorization\_profiles

Authorization profiles

<a id="models.RadiusAuthentications.posture_status"></a>

#### posture\_status

Posture status

<a id="models.RadiusAuthentications.security_group"></a>

#### security\_group

Security group

<a id="models.RadiusAuthentications.failure_reason"></a>

#### failure\_reason

Reason of failure

<a id="models.RadiusAuthentications.response_time"></a>

#### response\_time

Response time

<a id="models.RadiusAuthentications.passed"></a>

#### passed

Passed flag

<a id="models.RadiusAuthentications.failed"></a>

#### failed

Failed flag

<a id="models.RadiusAuthentications.credential_check"></a>

#### credential\_check

Credential check

<a id="models.RadiusAuthentications.endpoint_profile"></a>

#### endpoint\_profile

Endpoint matched profile

<a id="models.RadiusAuthentications.mdm_server_name"></a>

#### mdm\_server\_name

MDM server name

<a id="models.RadiusAuthentications.policy_set_name"></a>

#### policy\_set\_name

Policy set name

<a id="models.RadiusAuthentications.authorization_rule"></a>

#### authorization\_rule

Authorization rule

<a id="models.RadiusAuthentications.nas_ipv6_address"></a>

#### nas\_ipv6\_address

NAS IPV6 address

<a id="models.RadiusAuthentications.framed_ipv6_address"></a>

#### framed\_ipv6\_address

Framed ipv6 address

<a id="models.RadiusAuthentications.orig_calling_station_id"></a>

#### orig\_calling\_station\_id

Calling station ID

<a id="models.RadiusAuthentications.checksum"></a>

#### checksum

Checksum

<a id="models.RadiusAuthentications.timestamp"></a>

#### timestamp

Time when record added

<a id="models.RadiusAuthenticationsWeek"></a>

## RadiusAuthenticationsWeek Objects

```python
@dataclass
class RadiusAuthenticationsWeek()
```

This is performance oriented view which contains all the radius authentication records for the last seven days

<a id="models.RadiusAuthenticationsWeek.id"></a>

#### id

Database unique ID

<a id="models.RadiusAuthenticationsWeek.timestamp_timezone"></a>

#### timestamp\_timezone

Time with timezone when record added

<a id="models.RadiusAuthenticationsWeek.ise_node"></a>

#### ise\_node

ISE node

<a id="models.RadiusAuthenticationsWeek.syslog_message_code"></a>

#### syslog\_message\_code

Message code

<a id="models.RadiusAuthenticationsWeek.username"></a>

#### username

User's claimed identity

<a id="models.RadiusAuthenticationsWeek.user_type"></a>

#### user\_type

User type

<a id="models.RadiusAuthenticationsWeek.calling_station_id"></a>

#### calling\_station\_id

Calling station ID

<a id="models.RadiusAuthenticationsWeek.access_service"></a>

#### access\_service

Access service

<a id="models.RadiusAuthenticationsWeek.framed_ip_address"></a>

#### framed\_ip\_address

Framed IP address of user

<a id="models.RadiusAuthenticationsWeek.identity_store"></a>

#### identity\_store

Identity store of user

<a id="models.RadiusAuthenticationsWeek.identity_group"></a>

#### identity\_group

User identity group

<a id="models.RadiusAuthenticationsWeek.audit_session_id"></a>

#### audit\_session\_id

Audit session ID

<a id="models.RadiusAuthenticationsWeek.authentication_method"></a>

#### authentication\_method

Method of authentication

<a id="models.RadiusAuthenticationsWeek.authentication_protocol"></a>

#### authentication\_protocol

Protocol of authentication

<a id="models.RadiusAuthenticationsWeek.service_type"></a>

#### service\_type

The Type of Service the user has requested

<a id="models.RadiusAuthenticationsWeek.device_name"></a>

#### device\_name

Network device name

<a id="models.RadiusAuthenticationsWeek.device_type"></a>

#### device\_type

Network device type

<a id="models.RadiusAuthenticationsWeek.location"></a>

#### location

Network device location

<a id="models.RadiusAuthenticationsWeek.nas_ip_address"></a>

#### nas\_ip\_address

The IP address of the NAS originating the request

<a id="models.RadiusAuthenticationsWeek.nas_port_id"></a>

#### nas\_port\_id

Physical port number of the NAS (Network Access Server) originating the request

<a id="models.RadiusAuthenticationsWeek.nas_port_type"></a>

#### nas\_port\_type

NAS port type

<a id="models.RadiusAuthenticationsWeek.authorization_profiles"></a>

#### authorization\_profiles

Authorization profiles

<a id="models.RadiusAuthenticationsWeek.posture_status"></a>

#### posture\_status

Posture status

<a id="models.RadiusAuthenticationsWeek.security_group"></a>

#### security\_group

Security group

<a id="models.RadiusAuthenticationsWeek.failure_reason"></a>

#### failure\_reason

Reason of failure

<a id="models.RadiusAuthenticationsWeek.response_time"></a>

#### response\_time

Response time

<a id="models.RadiusAuthenticationsWeek.passed"></a>

#### passed

Passed flag

<a id="models.RadiusAuthenticationsWeek.failed"></a>

#### failed

Failed flag

<a id="models.RadiusAuthenticationsWeek.credential_check"></a>

#### credential\_check

Credential check

<a id="models.RadiusAuthenticationsWeek.endpoint_profile"></a>

#### endpoint\_profile

Endpoint matched profile

<a id="models.RadiusAuthenticationsWeek.mdm_server_name"></a>

#### mdm\_server\_name

MDM server name

<a id="models.RadiusAuthenticationsWeek.policy_set_name"></a>

#### policy\_set\_name

Policy set name

<a id="models.RadiusAuthenticationsWeek.authorization_rule"></a>

#### authorization\_rule

Authorization rule

<a id="models.RadiusAuthenticationsWeek.nas_ipv6_address"></a>

#### nas\_ipv6\_address

NAS IPV6 address

<a id="models.RadiusAuthenticationsWeek.framed_ipv6_address"></a>

#### framed\_ipv6\_address

Framed ipv6 address

<a id="models.RadiusAuthenticationsWeek.orig_calling_station_id"></a>

#### orig\_calling\_station\_id

Calling station ID

<a id="models.RadiusAuthenticationsWeek.checksum"></a>

#### checksum

Checksum

<a id="models.RadiusAuthenticationsWeek.timestamp"></a>

#### timestamp

Time when record added

<a id="models.RadiusAuthenticationsWeek.authentication_policy"></a>

#### authentication\_policy

Displays the authentication policy matched

<a id="models.RadiusAuthenticationsWeek.authorization_policy"></a>

#### authorization\_policy

Displays the authorization policy matched

<a id="models.RadiusAuthenticationsWeek.nad_profile_name"></a>

#### nad\_profile\_name

Displays the network device profile

<a id="models.RadiusAuthenticationSummary"></a>

## RadiusAuthenticationSummary Objects

```python
@dataclass
class RadiusAuthenticationSummary()
```

Displays an aggregate view of radius authentications

<a id="models.RadiusAuthenticationSummary.timestamp"></a>

#### timestamp

Time when record added

<a id="models.RadiusAuthenticationSummary.ise_node"></a>

#### ise\_node

ISE node

<a id="models.RadiusAuthenticationSummary.username"></a>

#### username

User name

<a id="models.RadiusAuthenticationSummary.calling_station_id"></a>

#### calling\_station\_id

Calling station ID

<a id="models.RadiusAuthenticationSummary.identity_store"></a>

#### identity\_store

Identity store

<a id="models.RadiusAuthenticationSummary.identity_group"></a>

#### identity\_group

Identity group

<a id="models.RadiusAuthenticationSummary.device_name"></a>

#### device\_name

Network device name

<a id="models.RadiusAuthenticationSummary.device_type"></a>

#### device\_type

Network device type

<a id="models.RadiusAuthenticationSummary.location"></a>

#### location

Network device location

<a id="models.RadiusAuthenticationSummary.access_service"></a>

#### access\_service

Access service

<a id="models.RadiusAuthenticationSummary.nas_port_id"></a>

#### nas\_port\_id

NAS port ID

<a id="models.RadiusAuthenticationSummary.authorization_profiles"></a>

#### authorization\_profiles

Authorization profile

<a id="models.RadiusAuthenticationSummary.failure_reason"></a>

#### failure\_reason

Reason of failure

<a id="models.RadiusAuthenticationSummary.security_group"></a>

#### security\_group

Security group

<a id="models.RadiusAuthenticationSummary.total_response_time"></a>

#### total\_response\_time

Total response time

<a id="models.RadiusAuthenticationSummary.max_response_time"></a>

#### max\_response\_time

Max response time

<a id="models.RadiusAuthenticationSummary.passed_count"></a>

#### passed\_count

Number of passed authentication

<a id="models.RadiusAuthenticationSummary.failed_count"></a>

#### failed\_count

Number of failed authentication

<a id="models.RadiusErrorsView"></a>

## RadiusErrorsView Objects

```python
@dataclass
class RadiusErrorsView()
```

Enables you to check for RADIUS Requests Dropped, EAP connection time outs and unknown NADs

<a id="models.RadiusErrorsView.authentication_policy"></a>

#### authentication\_policy

Authentication policy

<a id="models.RadiusErrorsView.authorization_policy"></a>

#### authorization\_policy

Authorization policy

<a id="models.RadiusErrorsView.other_attributes_string"></a>

#### other\_attributes\_string

Other attributes

<a id="models.RadiusErrorsView.response_time"></a>

#### response\_time

Response time

<a id="models.RadiusErrorsView.passed"></a>

#### passed

Passed flag

<a id="models.RadiusErrorsView.failed"></a>

#### failed

Failed flag

<a id="models.RadiusErrorsView.credential_check"></a>

#### credential\_check

Credential check

<a id="models.RadiusErrorsView.endpoint_profile"></a>

#### endpoint\_profile

Endpoint matched profile

<a id="models.RadiusErrorsView.mdm_server_name"></a>

#### mdm\_server\_name

MDM server name

<a id="models.RadiusErrorsView.nas_ipv6_address"></a>

#### nas\_ipv6\_address

NAS IPV6 address

<a id="models.RadiusErrorsView.framed_ipv6_address"></a>

#### framed\_ipv6\_address

Framed IPV6 address

<a id="models.RadiusErrorsView.id"></a>

#### id

Database unique ID

<a id="models.RadiusErrorsView.timestamp_timezone"></a>

#### timestamp\_timezone

Time with timezone when record added

<a id="models.RadiusErrorsView.timestamp"></a>

#### timestamp

Time when record added

<a id="models.RadiusErrorsView.ise_node"></a>

#### ise\_node

Displays the hostname of the ISE server

<a id="models.RadiusErrorsView.message_code"></a>

#### message\_code

Displays the message code

<a id="models.RadiusErrorsView.message_text"></a>

#### message\_text

Message text

<a id="models.RadiusErrorsView.username"></a>

#### username

User's claimed identity

<a id="models.RadiusErrorsView.user_type"></a>

#### user\_type

User type

<a id="models.RadiusErrorsView.calling_station_id"></a>

#### calling\_station\_id

Calling station ID

<a id="models.RadiusErrorsView.access_service"></a>

#### access\_service

Access service

<a id="models.RadiusErrorsView.framed_ip_address"></a>

#### framed\_ip\_address

Framed IP address

<a id="models.RadiusErrorsView.identity_store"></a>

#### identity\_store

Identity store

<a id="models.RadiusErrorsView.identity_group"></a>

#### identity\_group

Identity group

<a id="models.RadiusErrorsView.audit_session_id"></a>

#### audit\_session\_id

Unique numeric string identifying the server session

<a id="models.RadiusErrorsView.authentication_method"></a>

#### authentication\_method

Authentication method

<a id="models.RadiusErrorsView.authentication_protocol"></a>

#### authentication\_protocol

Authentication protocol

<a id="models.RadiusErrorsView.service_type"></a>

#### service\_type

The Type of Service the user has requested

<a id="models.RadiusErrorsView.network_device_name"></a>

#### network\_device\_name

Network device name

<a id="models.RadiusErrorsView.device_type"></a>

#### device\_type

Device type

<a id="models.RadiusErrorsView.location"></a>

#### location

Location

<a id="models.RadiusErrorsView.nas_ip_address"></a>

#### nas\_ip\_address

IP address of NAS

<a id="models.RadiusErrorsView.nas_port_id"></a>

#### nas\_port\_id

NAS port ID

<a id="models.RadiusErrorsView.nas_port_type"></a>

#### nas\_port\_type

NAS port type

<a id="models.RadiusErrorsView.selected_authorization_profiles"></a>

#### selected\_authorization\_profiles

Authorization profile used after authentication

<a id="models.RadiusErrorsView.posture_status"></a>

#### posture\_status

Posture status

<a id="models.RadiusErrorsView.security_group"></a>

#### security\_group

Security group

<a id="models.RadiusErrorsView.failure_reason"></a>

#### failure\_reason

Failure reason

<a id="models.RadiusErrorsView.response"></a>

#### response

Displays the response

<a id="models.RadiusErrorsView.execution_steps"></a>

#### execution\_steps

Execution steps

<a id="models.RadiusErrorsView.other_attributes"></a>

#### other\_attributes

Other attributes

<a id="models.RegisteredEndpoints"></a>

## RegisteredEndpoints Objects

```python
@dataclass
class RegisteredEndpoints()
```

Displays all personal devices registered by the employees

<a id="models.RegisteredEndpoints.endpoint_id"></a>

#### endpoint\_id

Specifies the MAC address of endpoint

<a id="models.RegisteredEndpoints.endpoint_profile"></a>

#### endpoint\_profile

Specifies the profiling policy under which endpoint got profiled

<a id="models.RegisteredEndpoints.endpoint_static_assignment"></a>

#### endpoint\_static\_assignment

Specifies the endpoint static assignment status

<a id="models.RegisteredEndpoints.static_assignment_group"></a>

#### static\_assignment\_group

Specifies If endpoint statically assigned to user identity group

<a id="models.RegisteredEndpoints.nmap_subnet_scanid"></a>

#### nmap\_subnet\_scanid

NMAP subnet of registered end points

<a id="models.RegisteredEndpoints.create_time"></a>

#### create\_time

Time when record was created

<a id="models.RegisteredEndpoints.logged_at"></a>

#### logged\_at

Time when the record was last updated

<a id="models.RegisteredEndpoints.identity"></a>

#### identity

Specifies the portal user

<a id="models.RegisteredEndpoints.device_registration_status"></a>

#### device\_registration\_status

Specifies if device is registered

<a id="models.RegisteredEndpoints.identity_group"></a>

#### identity\_group

Specifies the identity group

<a id="models.RegisteredEndpoints.server"></a>

#### server

Specifies the ISE node

<a id="models.SecurityGroups"></a>

## SecurityGroups Objects

```python
@dataclass
class SecurityGroups()
```

List and details of security groups

<a id="models.SecurityGroups.name"></a>

#### name

Specified the name of the security group

<a id="models.SecurityGroups.sgt_dec"></a>

#### sgt\_dec

Specifies the Security Group Tag in decimal

<a id="models.SecurityGroups.sgt_hex"></a>

#### sgt\_hex

Specifies the Security Group Tag in hexadecimal

<a id="models.SecurityGroups.description"></a>

#### description

Describes the security group

<a id="models.SecurityGroups.learned_from"></a>

#### learned\_from

Specifies where learned from

<a id="models.SecurityGroupAcls"></a>

## SecurityGroupAcls Objects

```python
@dataclass
class SecurityGroupAcls()
```

List and details of Security group ACLs

<a id="models.SecurityGroupAcls.name"></a>

#### name

Name of the Security group ACL

<a id="models.SecurityGroupAcls.description"></a>

#### description

Description of the security group ACL

<a id="models.SecurityGroupAcls.ip_version"></a>

#### ip\_version

Specifies the IP version (ipv4 or ipv6)

<a id="models.SponsorLoginAndAudit"></a>

## SponsorLoginAndAudit Objects

```python
@dataclass
class SponsorLoginAndAudit()
```

Tracks login activity by sponsor at the sponsor portal and guest related operation performed by sponsor

<a id="models.SponsorLoginAndAudit.id"></a>

#### id

Database unique ID

<a id="models.SponsorLoginAndAudit.timestamp_timezone"></a>

#### timestamp\_timezone

Time with timezone when record added

<a id="models.SponsorLoginAndAudit.timestamp"></a>

#### timestamp

Time when record added

<a id="models.SponsorLoginAndAudit.sponser_user_name"></a>

#### sponser\_user\_name

User name of sponsor

<a id="models.SponsorLoginAndAudit.ip_address"></a>

#### ip\_address

IP address

<a id="models.SponsorLoginAndAudit.mac_address"></a>

#### mac\_address

MAC address

<a id="models.SponsorLoginAndAudit.portal_name"></a>

#### portal\_name

Portal name

<a id="models.SponsorLoginAndAudit.result"></a>

#### result

Result

<a id="models.SponsorLoginAndAudit.identity_store"></a>

#### identity\_store

Identity store

<a id="models.SponsorLoginAndAudit.operation"></a>

#### operation

Operation

<a id="models.SponsorLoginAndAudit.guest_username"></a>

#### guest\_username

User name of guest

<a id="models.SponsorLoginAndAudit.guest_status"></a>

#### guest\_status

Status of guest

<a id="models.SponsorLoginAndAudit.failure_reason"></a>

#### failure\_reason

Reason of failure

<a id="models.SponsorLoginAndAudit.optional_data"></a>

#### optional\_data

Optional data

<a id="models.SponsorLoginAndAudit.psn_hostname"></a>

#### psn\_hostname

Hostname of PSN

<a id="models.SponsorLoginAndAudit.user_details"></a>

#### user\_details

Details of user

<a id="models.SponsorLoginAndAudit.guest_details"></a>

#### guest\_details

Details of guest

<a id="models.SponsorLoginAndAudit.guest_users"></a>

#### guest\_users

Guest users

<a id="models.SystemDiagnosticsView"></a>

## SystemDiagnosticsView Objects

```python
@dataclass
class SystemDiagnosticsView()
```

Provides details about the status of the Cisco ISE nodes. If a Cisco ISE node is unable to register, you can review this report to troubleshoot the issue

<a id="models.SystemDiagnosticsView.id"></a>

#### id

Database unique ID

<a id="models.SystemDiagnosticsView.timestamp_timezone"></a>

#### timestamp\_timezone

Time with timezone when record added

<a id="models.SystemDiagnosticsView.timestamp"></a>

#### timestamp

Time when record added

<a id="models.SystemDiagnosticsView.ise_node"></a>

#### ise\_node

Displays the hostname of the ISE server

<a id="models.SystemDiagnosticsView.message_severity"></a>

#### message\_severity

Displays the severity of message

<a id="models.SystemDiagnosticsView.message_code"></a>

#### message\_code

Displays the message code

<a id="models.SystemDiagnosticsView.message_text"></a>

#### message\_text

Displays the message text

<a id="models.SystemDiagnosticsView.category"></a>

#### category

Displays the category

<a id="models.SystemDiagnosticsView.diagnostic_info"></a>

#### diagnostic\_info

Displays the diagnostic info

<a id="models.SystemSummary"></a>

## SystemSummary Objects

```python
@dataclass
class SystemSummary()
```

Displays system health information like CPU utilisation , storage utilisation , number of CPU etc

<a id="models.SystemSummary.timestamp"></a>

#### timestamp

Time when record made

<a id="models.SystemSummary.ise_node"></a>

#### ise\_node

Name of ISE node

<a id="models.SystemSummary.cpu_utilization"></a>

#### cpu\_utilization

Specifies the CPU utilization in percentage

<a id="models.SystemSummary.cpu_count"></a>

#### cpu\_count

Specifies the number of CPU cores

<a id="models.SystemSummary.memory_utilization"></a>

#### memory\_utilization

Specifies the percentage of memory utilization

<a id="models.SystemSummary.diskspace_root"></a>

#### diskspace\_root

Specifies the percentage of storage utilized in root folder

<a id="models.SystemSummary.diskspace_boot"></a>

#### diskspace\_boot

Specifies the percentage of storage utilized in boot folder

<a id="models.SystemSummary.diskspace_opt"></a>

#### diskspace\_opt

Specifies the percentage of storage utilized in opt folder

<a id="models.SystemSummary.diskspace_storedconfig"></a>

#### diskspace\_storedconfig

Specifies the percentage of storage utilized in storedconfig folder

<a id="models.SystemSummary.diskspace_tmp"></a>

#### diskspace\_tmp

Specifies the percentage of storage utilized in tmp folder

<a id="models.SystemSummary.diskspace_runtime"></a>

#### diskspace\_runtime

Specifies the percentage of storage utilized in runtime

<a id="models.TacacsAccounting"></a>

## TacacsAccounting Objects

```python
@dataclass
class TacacsAccounting()
```

This view contains details of TACACS accounting records

<a id="models.TacacsAccounting.id"></a>

#### id

Database record primary key for the table

<a id="models.TacacsAccounting.username"></a>

#### username

Shows the user name of the device administrator.

<a id="models.TacacsAccounting.identity_group"></a>

#### identity\_group

Identity group to which users belongs to

<a id="models.TacacsAccounting.generated_time"></a>

#### generated\_time

Shows the syslog generation time based on when a particular event was triggered

<a id="models.TacacsAccounting.logged_time"></a>

#### logged\_time

Shows the time when the syslog was processed and stored by the Monitoring node

<a id="models.TacacsAccounting.ise_node"></a>

#### ise\_node

Shows the name of the ISE node through which the access request is processed.

<a id="models.TacacsAccounting.authentication_service"></a>

#### authentication\_service

Specifies the authentication service

<a id="models.TacacsAccounting.authentication_method"></a>

#### authentication\_method

Protocol used for authentication

<a id="models.TacacsAccounting.authentication_privilege_level"></a>

#### authentication\_privilege\_level

Specifies the Authentication Privilege Level

<a id="models.TacacsAccounting.attributes"></a>

#### attributes

Specifies the attributes

<a id="models.TacacsAccounting.message_text"></a>

#### message\_text

Specifies the message text

<a id="models.TacacsAccounting.execution_steps"></a>

#### execution\_steps

Specifies the execution steps

<a id="models.TacacsAccounting.authentication_type"></a>

#### authentication\_type

Specifies the authentication type

<a id="models.TacacsAccounting.status"></a>

#### status

Shows if the status is pass or failed

<a id="models.TacacsAccounting.message_code"></a>

#### message\_code

Syslog message code

<a id="models.TacacsAccounting.command"></a>

#### command

Specifies the command

<a id="models.TacacsAccounting.command_args"></a>

#### command\_args

Specifies the command arguments

<a id="models.TacacsAccounting.device_type"></a>

#### device\_type

Shows the device group device type of the AAA client

<a id="models.TacacsAccounting.location"></a>

#### location

Shows the device group device location of the AAA client

<a id="models.TacacsAccounting.accounting_type"></a>

#### accounting\_type

Specifies the accounting type

<a id="models.TacacsAccounting.device_ipv6"></a>

#### device\_ipv6

IPV6 address of the network device (The AAA Client)

<a id="models.TacacsAccounting.epoch_time"></a>

#### epoch\_time

Specifies the unix epoch time

<a id="models.TacacsAccounting.failure_reason"></a>

#### failure\_reason

Specifies the reason for failure

<a id="models.TacacsAccounting.session_key"></a>

#### session\_key

Shows the session keys (found in the EAP success or EAP failure messages) returned by ISE to the network device.

<a id="models.TacacsAccounting.event"></a>

#### event

Specifies the event like Accounting

<a id="models.TacacsAccounting.device_name"></a>

#### device\_name

Name of the network device (The AAA client)

<a id="models.TacacsAccounting.device_ip"></a>

#### device\_ip

IP of the network device (The AAA client)

<a id="models.TacacsAccounting.device_groups"></a>

#### device\_groups

To which network device group the AAA client belongs to

<a id="models.TacacsAccounting.device_port"></a>

#### device\_port

Shows the network device port number through which the access request is made.

<a id="models.TacacsAccounting.remote_address"></a>

#### remote\_address

Shows the IP address, MAC address, or any other string that uniquely identifies the end station

<a id="models.TacacsAccountingLastTwoDays"></a>

## TacacsAccountingLastTwoDays Objects

```python
@dataclass
class TacacsAccountingLastTwoDays()
```

This is performance oriented view which contains all the TACACS accounting records for the last two days

<a id="models.TacacsAccountingLastTwoDays.id"></a>

#### id

Database record primary key for the table

<a id="models.TacacsAccountingLastTwoDays.username"></a>

#### username

Shows the user name of the device administrator.

<a id="models.TacacsAccountingLastTwoDays.identity_group"></a>

#### identity\_group

Identity group to which users belongs to

<a id="models.TacacsAccountingLastTwoDays.generated_time"></a>

#### generated\_time

Shows the syslog generation time based on when a particular event was triggered

<a id="models.TacacsAccountingLastTwoDays.logged_time"></a>

#### logged\_time

Shows the time when the syslog was processed and stored by the Monitoring node

<a id="models.TacacsAccountingLastTwoDays.ise_node"></a>

#### ise\_node

Shows the name of the ISE node through which the access request is processed.

<a id="models.TacacsAccountingLastTwoDays.authentication_service"></a>

#### authentication\_service

Specifies the authentication service

<a id="models.TacacsAccountingLastTwoDays.authentication_method"></a>

#### authentication\_method

Protocol used for authentication

<a id="models.TacacsAccountingLastTwoDays.authentication_privilege_level"></a>

#### authentication\_privilege\_level

Specifies the authentication privilege level

<a id="models.TacacsAccountingLastTwoDays.authentication_type"></a>

#### authentication\_type

Specifies the authentication type

<a id="models.TacacsAccountingLastTwoDays.status"></a>

#### status

Shows if the status is pass or failed

<a id="models.TacacsAccountingLastTwoDays.message_code"></a>

#### message\_code

Syslog message code

<a id="models.TacacsAccountingLastTwoDays.command"></a>

#### command

Specifies the command

<a id="models.TacacsAccountingLastTwoDays.command_args"></a>

#### command\_args

Specifies the command arguments

<a id="models.TacacsAccountingLastTwoDays.device_type"></a>

#### device\_type

Shows the device group device type of the AAA client

<a id="models.TacacsAccountingLastTwoDays.location"></a>

#### location

Shows the device group device location of the AAA client

<a id="models.TacacsAccountingLastTwoDays.accounting_type"></a>

#### accounting\_type

Specifies the accounting type

<a id="models.TacacsAccountingLastTwoDays.device_ipv6"></a>

#### device\_ipv6

IPV6 address of the network device (The AAA Client)

<a id="models.TacacsAccountingLastTwoDays.epoch_time"></a>

#### epoch\_time

Specifies the unix epoch time

<a id="models.TacacsAccountingLastTwoDays.failure_reason"></a>

#### failure\_reason

Specifies the reason for failure

<a id="models.TacacsAccountingLastTwoDays.session_key"></a>

#### session\_key

Shows the session keys (found in the EAP success or EAP failure messages) returned by ISE to the network device.

<a id="models.TacacsAccountingLastTwoDays.event"></a>

#### event

Specifies the event like Accounting

<a id="models.TacacsAccountingLastTwoDays.device_name"></a>

#### device\_name

Name of the network device (The AAA client)

<a id="models.TacacsAccountingLastTwoDays.device_ip"></a>

#### device\_ip

IP of the network device (The AAA client)

<a id="models.TacacsAccountingLastTwoDays.device_groups"></a>

#### device\_groups

To which network device group the AAA client belongs to

<a id="models.TacacsAccountingLastTwoDays.device_port"></a>

#### device\_port

Shows the network device port number through which the access request is made.

<a id="models.TacacsAccountingLastTwoDays.remote_address"></a>

#### remote\_address

Shows the IP address, MAC address, or any other string that uniquely identifies the end station

<a id="models.TacacsAuthentication"></a>

## TacacsAuthentication Objects

```python
@dataclass
class TacacsAuthentication()
```

This provides details of all the TACACS authentication records

<a id="models.TacacsAuthentication.id"></a>

#### id

Database record primary key for the table

<a id="models.TacacsAuthentication.generated_time"></a>

#### generated\_time

Shows the syslog generation time based on when a particular event was triggered

<a id="models.TacacsAuthentication.logged_time"></a>

#### logged\_time

Shows the time when the syslog was processed and stored by the Monitoring node

<a id="models.TacacsAuthentication.ise_node"></a>

#### ise\_node

Shows the name of the ISE node through which the access request is processed.

<a id="models.TacacsAuthentication.message_code"></a>

#### message\_code

Syslog message code

<a id="models.TacacsAuthentication.username"></a>

#### username

Shows the user name of the device administrator.

<a id="models.TacacsAuthentication.failure_reason"></a>

#### failure\_reason

Specifies the reason for failure

<a id="models.TacacsAuthentication.authentication_policy"></a>

#### authentication\_policy

Specifies the authentication policy

<a id="models.TacacsAuthentication.authentication_privilege_level"></a>

#### authentication\_privilege\_level

Specifies the Authentication Privilege Level

<a id="models.TacacsAuthentication.attributes"></a>

#### attributes

Specifies the attributes

<a id="models.TacacsAuthentication.message_text"></a>

#### message\_text

Specifies the message text

<a id="models.TacacsAuthentication.execution_steps"></a>

#### execution\_steps

Specifies the execution steps

<a id="models.TacacsAuthentication.authentication_action"></a>

#### authentication\_action

Specifies the authentication action

<a id="models.TacacsAuthentication.authentication_type"></a>

#### authentication\_type

Specifies the authentication type

<a id="models.TacacsAuthentication.authentication_service"></a>

#### authentication\_service

Specifies the authentication service

<a id="models.TacacsAuthentication.session_key"></a>

#### session\_key

Shows the session keys (found in the EAP success or EAP failure messages) returned by ISE to the network device.

<a id="models.TacacsAuthentication.event"></a>

#### event

Specifies the event like Accounting

<a id="models.TacacsAuthentication.device_name"></a>

#### device\_name

Name of the network device (The AAA client)

<a id="models.TacacsAuthentication.device_ip"></a>

#### device\_ip

IP of the network device (The AAA client)

<a id="models.TacacsAuthentication.device_groups"></a>

#### device\_groups

To which network device group the AAA client belongs to

<a id="models.TacacsAuthentication.device_port"></a>

#### device\_port

Shows the network device port number through which the access request is made.

<a id="models.TacacsAuthentication.remote_address"></a>

#### remote\_address

Shows the IP address, MAC address, or any other string that uniquely identifies the end station

<a id="models.TacacsAuthentication.selected_authorization_profile"></a>

#### selected\_authorization\_profile

Authorization profile used after authentication

<a id="models.TacacsAuthentication.destination_ip_address"></a>

#### destination\_ip\_address

Specifies the destination IP address

<a id="models.TacacsAuthentication.status"></a>

#### status

Shows if the authentication succeeded or failed

<a id="models.TacacsAuthentication.device_type"></a>

#### device\_type

Shows the device group device type of the AAA client

<a id="models.TacacsAuthentication.location"></a>

#### location

Shows the device group device location of the AAA client

<a id="models.TacacsAuthentication.identity_store"></a>

#### identity\_store

Identity store to which users belongs to

<a id="models.TacacsAuthentication.device_ipv6"></a>

#### device\_ipv6

IPV6 address of the network device (The AAA Client)

<a id="models.TacacsAuthentication.epoch_time"></a>

#### epoch\_time

Specifies the unix epoch time

<a id="models.TacacsAuthenticationLastTwoDays"></a>

## TacacsAuthenticationLastTwoDays Objects

```python
@dataclass
class TacacsAuthenticationLastTwoDays()
```

This is performance oriented view which contains all the TACACS authentication records for the last two days

<a id="models.TacacsAuthenticationLastTwoDays.id"></a>

#### id

Database record primary key for the table

<a id="models.TacacsAuthenticationLastTwoDays.generated_time"></a>

#### generated\_time

Shows the syslog generation time based on when a particular event was triggered

<a id="models.TacacsAuthenticationLastTwoDays.logged_time"></a>

#### logged\_time

Shows the time when the syslog was processed and stored by the Monitoring node

<a id="models.TacacsAuthenticationLastTwoDays.ise_node"></a>

#### ise\_node

Shows the name of the ISE node through which the access request is processed.

<a id="models.TacacsAuthenticationLastTwoDays.message_code"></a>

#### message\_code

Syslog message code

<a id="models.TacacsAuthenticationLastTwoDays.username"></a>

#### username

Shows the user name of the device administrator.

<a id="models.TacacsAuthenticationLastTwoDays.failure_reason"></a>

#### failure\_reason

Specifies the reason for failure

<a id="models.TacacsAuthenticationLastTwoDays.authentication_policy"></a>

#### authentication\_policy

Specifies the authentication policy

<a id="models.TacacsAuthenticationLastTwoDays.authentication_privilege_level"></a>

#### authentication\_privilege\_level

Specifies the authentication privilege level

<a id="models.TacacsAuthenticationLastTwoDays.authentication_action"></a>

#### authentication\_action

Specifies the authentication action

<a id="models.TacacsAuthenticationLastTwoDays.authentication_type"></a>

#### authentication\_type

Specifies the authentication type

<a id="models.TacacsAuthenticationLastTwoDays.authentication_service"></a>

#### authentication\_service

Specifies the authentication service

<a id="models.TacacsAuthenticationLastTwoDays.session_key"></a>

#### session\_key

Shows the session keys (found in the EAP success or EAP failure messages) returned by ISE to the network device.

<a id="models.TacacsAuthenticationLastTwoDays.event"></a>

#### event

Specifies the event like Accounting

<a id="models.TacacsAuthenticationLastTwoDays.device_name"></a>

#### device\_name

Name of the network device (The AAA client)

<a id="models.TacacsAuthenticationLastTwoDays.device_ip"></a>

#### device\_ip

IP of the network device (The AAA client)

<a id="models.TacacsAuthenticationLastTwoDays.device_groups"></a>

#### device\_groups

To which network device group the AAA client belongs to

<a id="models.TacacsAuthenticationLastTwoDays.device_port"></a>

#### device\_port

Shows the network device port number through which the access request is made.

<a id="models.TacacsAuthenticationLastTwoDays.remote_address"></a>

#### remote\_address

Shows the IP address, MAC address, or any other string that uniquely identifies the end station

<a id="models.TacacsAuthenticationLastTwoDays.selected_authorization_profile"></a>

#### selected\_authorization\_profile

Authorization profile used after authentication

<a id="models.TacacsAuthenticationLastTwoDays.destination_ip_address"></a>

#### destination\_ip\_address

Specifies the destination IP address

<a id="models.TacacsAuthenticationLastTwoDays.status"></a>

#### status

Shows if the authentication succeeded or failed

<a id="models.TacacsAuthenticationLastTwoDays.device_type"></a>

#### device\_type

Shows the device group device type of the AAA client

<a id="models.TacacsAuthenticationLastTwoDays.location"></a>

#### location

Shows the device group device location of the AAA client

<a id="models.TacacsAuthenticationLastTwoDays.identity_store"></a>

#### identity\_store

Identity store to which users belongs to

<a id="models.TacacsAuthenticationLastTwoDays.device_ipv6"></a>

#### device\_ipv6

IPV6 address of the network device (The AAA Client)

<a id="models.TacacsAuthenticationLastTwoDays.epoch_time"></a>

#### epoch\_time

Specifies the unix epoch time

<a id="models.TacacsAuthenticationSummary"></a>

## TacacsAuthenticationSummary Objects

```python
@dataclass
class TacacsAuthenticationSummary()
```

Display aggregate view of TACACS authentications

<a id="models.TacacsAuthenticationSummary.timestamp"></a>

#### timestamp

Time when record added

<a id="models.TacacsAuthenticationSummary.ise_node"></a>

#### ise\_node

Shows the name of the ISE node through which the access request is processed.

<a id="models.TacacsAuthenticationSummary.username"></a>

#### username

Shows the user name of the device administrator.

<a id="models.TacacsAuthenticationSummary.identity_store"></a>

#### identity\_store

Identity store to which users belongs to

<a id="models.TacacsAuthenticationSummary.device_name"></a>

#### device\_name

Name of the network device (The AAA client)

<a id="models.TacacsAuthenticationSummary.device_group"></a>

#### device\_group

To which network device group the AAA client belongs to

<a id="models.TacacsAuthenticationSummary.device_type"></a>

#### device\_type

Shows the device group device type of the AAA client

<a id="models.TacacsAuthenticationSummary.location"></a>

#### location

Shows the device group device location of the AAA client

<a id="models.TacacsAuthenticationSummary.authorization_profiles"></a>

#### authorization\_profiles

Specifies the authorization profiles

<a id="models.TacacsAuthenticationSummary.failure_reason"></a>

#### failure\_reason

Specifies the reason for failure

<a id="models.TacacsAuthenticationSummary.passed_count"></a>

#### passed\_count

Number of successful authentication

<a id="models.TacacsAuthenticationSummary.failed_count"></a>

#### failed\_count

Number of failed authentication

<a id="models.TacacsAuthorization"></a>

## TacacsAuthorization Objects

```python
@dataclass
class TacacsAuthorization()
```

This provides details of all the TACACS authorization records

<a id="models.TacacsAuthorization.id"></a>

#### id

Database unique ID

<a id="models.TacacsAuthorization.generated_time"></a>

#### generated\_time

Shows the syslog generation time based on when a particular event was triggered

<a id="models.TacacsAuthorization.logged_time"></a>

#### logged\_time

Shows the time when the syslog was processed and stored by the Monitoring node

<a id="models.TacacsAuthorization.ise_node"></a>

#### ise\_node

Shows the name of the ISE node through which the access request is processed.

<a id="models.TacacsAuthorization.attributes"></a>

#### attributes

Specifies the attributes

<a id="models.TacacsAuthorization.execution_steps"></a>

#### execution\_steps

Specifies the execution steps

<a id="models.TacacsAuthorization.status"></a>

#### status

Shows if the status is pass or failed

<a id="models.TacacsAuthorization.event"></a>

#### event

Specifies the event like Accounting

<a id="models.TacacsAuthorization.message_text"></a>

#### message\_text

Specifies the operational message text

<a id="models.TacacsAuthorization.device_ipv6"></a>

#### device\_ipv6

IPV6 address of the network device (The AAA Client)

<a id="models.TacacsAuthorization.device_name"></a>

#### device\_name

Name of the network device (The AAA client)

<a id="models.TacacsAuthorization.device_ip"></a>

#### device\_ip

IP of the network device (The AAA client)

<a id="models.TacacsAuthorization.device_group"></a>

#### device\_group

To which network device group the AAA client belongs to

<a id="models.TacacsAuthorization.device_port"></a>

#### device\_port

Shows the network device port number through which the access request is made.

<a id="models.TacacsAuthorization.epoch_time"></a>

#### epoch\_time

Specifies the unix epoch time

<a id="models.TacacsAuthorization.failure_reason"></a>

#### failure\_reason

Specifies the reason for failure

<a id="models.TacacsAuthorization.username"></a>

#### username

Shows the user name of the device administrator.

<a id="models.TacacsAuthorization.authorization_policy"></a>

#### authorization\_policy

Specifies the authorization policy

<a id="models.TacacsAuthorization.authentication_privilege_level"></a>

#### authentication\_privilege\_level

Specifies the Authentication Privilege Level

<a id="models.TacacsAuthorization.authorization_request_attr"></a>

#### authorization\_request\_attr

Specifies the request attribute

<a id="models.TacacsAuthorization.authorization_response_attr"></a>

#### authorization\_response\_attr

Specifies the response attribute

<a id="models.TacacsAuthorization.session_key"></a>

#### session\_key

Shows the session keys (found in the EAP success or EAP failure messages) returned by ISE to the network device.

<a id="models.TacacsAuthorization.remote_address"></a>

#### remote\_address

Shows the IP address, MAC address, or any other string that uniquely identifies the end station

<a id="models.TacacsAuthorization.shell_profile"></a>

#### shell\_profile

Specifies the TACACS Profiles

<a id="models.TacacsAuthorization.authentication_method"></a>

#### authentication\_method

Specifies the authentication method

<a id="models.TacacsAuthorization.authentication_type"></a>

#### authentication\_type

Specifies the authentication type

<a id="models.TacacsAuthorization.authentication_service"></a>

#### authentication\_service

Specifies the authentication type

<a id="models.TacacsAuthorization.device_type"></a>

#### device\_type

Shows the device group device type of the AAA client

<a id="models.TacacsAuthorization.location"></a>

#### location

Shows the device group device location of the AAA client

<a id="models.TacacsAuthorization.matched_command_set"></a>

#### matched\_command\_set

Matched TACACS command sets

<a id="models.TacacsAuthorization.command_from_device"></a>

#### command\_from\_device

Specifies the command in the matched command set

<a id="models.TacacsCommandAccounting"></a>

## TacacsCommandAccounting Objects

```python
@dataclass
class TacacsCommandAccounting()
```

Displays details of TACACS command accounting

<a id="models.TacacsCommandAccounting.id"></a>

#### id

Unique database ID

<a id="models.TacacsCommandAccounting.username"></a>

#### username

Shows the user name of the device administrator.

<a id="models.TacacsCommandAccounting.generated_time"></a>

#### generated\_time

Shows the syslog generation time based on when a particular event was triggered

<a id="models.TacacsCommandAccounting.logged_time"></a>

#### logged\_time

Shows the time when the syslog was processed and stored by the Monitoring node

<a id="models.TacacsCommandAccounting.ise_node"></a>

#### ise\_node

Shows the name of the ISE node through which the access request is processed.

<a id="models.TacacsCommandAccounting.authentication_privilege_level"></a>

#### authentication\_privilege\_level

Specifies the Authentication Privilege Level

<a id="models.TacacsCommandAccounting.attributes"></a>

#### attributes

Specifies the attributes

<a id="models.TacacsCommandAccounting.execution_steps"></a>

#### execution\_steps

Specifies the execution steps

<a id="models.TacacsCommandAccounting.status"></a>

#### status

Shows if the status pass or failed

<a id="models.TacacsCommandAccounting.event"></a>

#### event

Specifies the event like Accounting

<a id="models.TacacsCommandAccounting.message_text"></a>

#### message\_text

Specifies the message text

<a id="models.TacacsCommandAccounting.failure_reason"></a>

#### failure\_reason

Specifies the failure reason

<a id="models.TacacsCommandAccounting.identity_group"></a>

#### identity\_group

Identity group to which users belongs to

<a id="models.TacacsCommandAccounting.session_key"></a>

#### session\_key

Shows the session keys (found in the EAP success or EAP failure messages) returned by ISE to the network device.

<a id="models.TacacsCommandAccounting.device_name"></a>

#### device\_name

IPV6 address of the network device (The AAA Client)

<a id="models.TacacsCommandAccounting.device_ip"></a>

#### device\_ip

IP of the network device (The AAA client)

<a id="models.TacacsCommandAccounting.device_groups"></a>

#### device\_groups

To which network device group the AAA client belongs to

<a id="models.TacacsCommandAccounting.device_port"></a>

#### device\_port

Shows the network device port number through which the access request is made.

<a id="models.TacacsCommandAccounting.device_ipv6"></a>

#### device\_ipv6

IPV6 address of the network device (The AAA Client)

<a id="models.TacacsCommandAccounting.remote_address"></a>

#### remote\_address

Shows the IP address, MAC address, or any other string that uniquely identifies the end station

<a id="models.TacacsCommandAccounting.authentication_method"></a>

#### authentication\_method

Specifies the authentication method

<a id="models.TacacsCommandAccounting.authentication_type"></a>

#### authentication\_type

Specifies the authentication type

<a id="models.TacacsCommandAccounting.authentication_service"></a>

#### authentication\_service

Specifies the authentication service

<a id="models.TacacsCommandAccounting.command"></a>

#### command

Specifies the command

<a id="models.TacacsCommandAccounting.command_args"></a>

#### command\_args

Specifies the command arguments

<a id="models.TacacsCommandAccounting.device_type"></a>

#### device\_type

Shows the device group device type of the AAA client

<a id="models.TacacsCommandAccounting.location"></a>

#### location

Shows the device group device location of the AAA client

<a id="models.TacacsCommandAccounting.epoch_time"></a>

#### epoch\_time

Specifies the unix epoch time

<a id="models.ThreatEvents"></a>

## ThreatEvents Objects

```python
@dataclass
class ThreatEvents()
```

Log of threat events received from various sources

<a id="models.ThreatEvents.logged_at"></a>

#### logged\_at

Shows the time when the syslog was processed and stored by the Monitoring node

<a id="models.ThreatEvents.mac_address"></a>

#### mac\_address

Specifies the MAC address

<a id="models.ThreatEvents.ip_address"></a>

#### ip\_address

Specifies the IP address

<a id="models.ThreatEvents.id"></a>

#### id

Unique database identifier

<a id="models.ThreatEvents.severity"></a>

#### severity

Specifies the severity

<a id="models.ThreatEvents.title"></a>

#### title

Specifies the title

<a id="models.ThreatEvents.event_time"></a>

#### event\_time

Specifies the event time

<a id="models.ThreatEvents.vendor_name"></a>

#### vendor\_name

Specifies the vendor name

<a id="models.ThreatEvents.source"></a>

#### source

Specifies the source

<a id="models.ThreatEvents.incident_type"></a>

#### incident\_type

Specifies the incident type

<a id="models.ThreatEvents.details"></a>

#### details

Gives further details

<a id="models.Upspolicy"></a>

## Upspolicy Objects

```python
@dataclass
class Upspolicy()
```

None

<a id="models.Upspolicyset"></a>

## Upspolicyset Objects

```python
@dataclass
class Upspolicyset()
```

None

<a id="models.UpspolicysetPolicies"></a>

## UpspolicysetPolicies Objects

```python
@dataclass
class UpspolicysetPolicies()
```

None

<a id="models.UserIdentityGroups"></a>

## UserIdentityGroups Objects

```python
@dataclass
class UserIdentityGroups()
```

This will provide details of all the user identity groups

<a id="models.UserIdentityGroups.id"></a>

#### id

Primary key for user identity groups

<a id="models.UserIdentityGroups.name"></a>

#### name

Name of the group

<a id="models.UserIdentityGroups.description"></a>

#### description

Description of the group

<a id="models.UserIdentityGroups.created_by"></a>

#### created\_by

The group was created by whom

<a id="models.UserIdentityGroups.create_time"></a>

#### create\_time

When the record was created

<a id="models.UserIdentityGroups.update_time"></a>

#### update\_time

When the record was updated

<a id="models.UserIdentityGroups.status"></a>

#### status

Shows if the group is active

<a id="models.UserPasswordChanges"></a>

## UserPasswordChanges Objects

```python
@dataclass
class UserPasswordChanges()
```

Displays verification about employees password changes

<a id="models.UserPasswordChanges.timestamp_timezone"></a>

#### timestamp\_timezone

Time with timezone when record added

<a id="models.UserPasswordChanges.timestamp"></a>

#### timestamp

Time when record added

<a id="models.UserPasswordChanges.ise_node"></a>

#### ise\_node

Displays the hostname of the ISE server

<a id="models.UserPasswordChanges.message_code"></a>

#### message\_code

Displays the message code

<a id="models.UserPasswordChanges.admin_name"></a>

#### admin\_name

Admin name

<a id="models.UserPasswordChanges.admin_ip_address"></a>

#### admin\_ip\_address

Admin IP address

<a id="models.UserPasswordChanges.admin_ipv6_address"></a>

#### admin\_ipv6\_address

Admin IPV6 address

<a id="models.UserPasswordChanges.admin_interface"></a>

#### admin\_interface

Admin interface used

<a id="models.UserPasswordChanges.message_class"></a>

#### message\_class

Message class

<a id="models.UserPasswordChanges.message_text"></a>

#### message\_text

Displays the message text

<a id="models.UserPasswordChanges.operator_name"></a>

#### operator\_name

Operator name

<a id="models.UserPasswordChanges.user_admin_flag"></a>

#### user\_admin\_flag

User admin flag

<a id="models.UserPasswordChanges.account_name"></a>

#### account\_name

Account name

<a id="models.UserPasswordChanges.device_ip"></a>

#### device\_ip

Device IP

<a id="models.UserPasswordChanges.identity_store_name"></a>

#### identity\_store\_name

Identity store name

<a id="models.UserPasswordChanges.change_password_method"></a>

#### change\_password\_method

Method of password change

<a id="models.UserPasswordChanges.audit_password_type"></a>

#### audit\_password\_type

Password type

<a id="models.VulnerabilityAssessmentFailures"></a>

## VulnerabilityAssessmentFailures Objects

```python
@dataclass
class VulnerabilityAssessmentFailures()
```

This report contains details of endpoints for which Vulnerability Assessment failed

<a id="models.VulnerabilityAssessmentFailures.logged_at"></a>

#### logged\_at

Shows the time when the syslog was processed and stored by the Monitoring node

<a id="models.VulnerabilityAssessmentFailures.id"></a>

#### id

Unique database ID

<a id="models.VulnerabilityAssessmentFailures.adapter_instance_name"></a>

#### adapter\_instance\_name

Specifies the adapter instance name

<a id="models.VulnerabilityAssessmentFailures.adapter_instance_id"></a>

#### adapter\_instance\_id

Specifies the adapter instance ID

<a id="models.VulnerabilityAssessmentFailures.vendor_name"></a>

#### vendor\_name

Specifies the vendor name

<a id="models.VulnerabilityAssessmentFailures.ise_node"></a>

#### ise\_node

Specifies the ACS instance

<a id="models.VulnerabilityAssessmentFailures.mac_address"></a>

#### mac\_address

Specifies the MAC address

<a id="models.VulnerabilityAssessmentFailures.ip_address"></a>

#### ip\_address

Specifies the IP address

<a id="models.VulnerabilityAssessmentFailures.operation_messsage_text"></a>

#### operation\_messsage\_text

Specifies the operation message text

<a id="models.VulnerabilityAssessmentFailures.message_type"></a>

#### message\_type

Specifies the message type
