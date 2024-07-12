# Oracle database connectors for Cisco ISE

<a id="factory"></a>

# factory

Database Connector Factory

<a id="factory.DatabaseConnectorFactory"></a>

## DatabaseConnectorFactory Objects

```python
class DatabaseConnectorFactory(ABC)
```

Database Connector Factory

<a id="factory.DatabaseConnectorFactory.create_connector"></a>

#### create\_connector

```python
@staticmethod
def create_connector(hostname: str, port: str, user: str, password: str,
                     **kwargs) -> DatabaseConnector
```

Create Database Connector

**Arguments**:

- `hostname` _str_ - OJDBC hostname
- `port` _str_ - OJDBC port
- `user` _str_ - OJDBC username
- `password` _str_ - OJDBC password
- `kwargs` _dict_ - Additional parameters for specific connector implementation
  

**Raises**:

- `ValueError` - For unexpected input parameters
  

**Returns**:

- `DatabaseConnector` - Database Connector

<a id="factory.OjdbcConnectorFactory"></a>

## OjdbcConnectorFactory Objects

```python
class OjdbcConnectorFactory(DatabaseConnectorFactory)
```

Database Connector Factory that return either of these connector instances:

- ThinOjdbcConnector
- ThickOjdbcConnector

<a id="factory.OjdbcConnectorFactory.create_connector"></a>

#### create\_connector

```python
@staticmethod
def create_connector(hostname: str, port: str, user: str, password: str,
                     **kwargs) -> DatabaseConnector
```

Create Database Connector

**Arguments**:

- `hostname` _str_ - OJDBC hostname
- `port` _str_ - OJDBC port
- `user` _str_ - OJDBC username
- `password` _str_ - OJDBC password
  
  For `ThinOjdbcConnector`:
- `verify` _bool, optional_ - Verify OJDBC certificate, Defaults to True.
  
  For `ThickOjdbcConnector`:
- `jar` _str_ - Thick client JAR filename
- `trust_store` _str_ - Java key store filename
- `trust_store_password` _str_ - Java key store password
  

**Raises**:

- `ValueError` - For unexpected input parameters
  

**Returns**:

- `DatabaseConnector` - Database Connector

<a id="connector"></a>

# connector

Database Connector

<a id="connector.DatabaseConnectorException"></a>

## DatabaseConnectorException Objects

```python
class DatabaseConnectorException(Exception)
```

Database Connector Exception

<a id="connector.DatabaseConnector"></a>

## DatabaseConnector Objects

```python
class DatabaseConnector(ABC)
```

Abstract database connector

<a id="connector.DatabaseConnector.connect"></a>

#### connect

```python
@abstractmethod
def connect()
```

Establish OJDBC connection to the database

<a id="connector.DatabaseConnector.close"></a>

#### close

```python
@abstractmethod
def close()
```

Close the database connection.

<a id="connector.DatabaseConnector.execute_query"></a>

#### execute\_query

```python
@abstractmethod
def execute_query(query: str, params: list | tuple | dict = None) -> list
```

Execute SQL query against the database.

**Arguments**:

- `query` _str_ - SQL query string
- `params` _list | tuple | dict_ - Named query parameters
  

**Returns**:

- `list` - All records from the query result.

<a id="connector.DatabaseConnector.tables"></a>

#### tables

```python
@property
def tables() -> list
```

List of all table names in the database

**Returns**:

- `list` - List of table names available in the database

<a id="connector.DatabaseConnector.table_schema"></a>

#### table\_schema

```python
def table_schema(table_name: str) -> list
```

Return schema for the specified table.

These values are returned for each database table:
- Column Name
- Data Type
- Column Description

**Arguments**:

- `table_name` _str_ - Database table name
  

**Returns**:

- `list` - List of Column names, their data type and description of each column

<a id="thin"></a>

# thin

ISE Data Connect using Thin Oracle DB connector

<a id="thin.ThinOjdbcConnector"></a>

## ThinOjdbcConnector Objects

```python
class ThinOjdbcConnector(
    hostname: str,
    port: str,
    user: str,
    password: str,
    verify: bool = True
)
```

OJDBC Database Connector using Thin client

**Arguments**:

- `hostname` _str_ - OJDBC hostname
- `port` _str_ - OJDBC port
- `user` _str_ - OJDBC username
- `password` _str_ - OJDBC password
- `verify` _bool, optional_ - Verify OJDBC certificate, Defaults to True.

<a id="thin.ThinOjdbcConnector.connect"></a>

#### connect

```python
def connect()
```

Establish OJDBC connection to the database

**Raises**:

- `DatabaseConnectorException` - For any errors encountered when connecting to the database

<a id="thin.ThinOjdbcConnector.close"></a>

#### close

```python
def close()
```

Close the database connection

**Raises**:

- `DatabaseConnectorException` - For any errors encountered when closing the connection

<a id="thin.ThinOjdbcConnector.execute_query"></a>

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
  

**Raises**:

- `DatabaseConnectorException` - For any errors encountered when executing the query

<a id="thick"></a>

# thick

Database connector using Oracle JAR file as a thick client

<a id="thick.stringified"></a>

#### stringified

```python
def stringified(rows: list) -> list
```

Convert all the items in all the rows to string

**Arguments**:

- `rows` _list_ - Rows returned by database query result
  

**Returns**:

- `list` - Return stringified rows returned by OJDBC connection

<a id="thick.ThickOjdbcConnector"></a>

## ThickOjdbcConnector Objects

```python
class ThickOjdbcConnector(
    hostname: str,
    port: str,
    user: str,
    password: str,
    jar: str,
    trust_store: str,
    trust_store_password: str
)
```

OJDBC Database Connector using Thick client

**Arguments**:

- `hostname` _str_ - OJDBC hostname
- `port` _str_ - OJDBC port
- `user` _str_ - OJDBC username
- `password` _str_ - OJDBC password
- `jar` _str_ - Thick client JAR filename
- `trust_store` _str_ - Java key store filename
- `trust_store_password` _str_ - Java key store password

<a id="thick.ThickOjdbcConnector.connect"></a>

#### connect

```python
def connect()
```

Establish OJDBC connection to the database

**Raises**:

- `DatabaseConnectorException` - For any errors encountered when connecting to the database

<a id="thick.ThickOjdbcConnector.execute_query"></a>

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
  

**Raises**:

- `DatabaseConnectorException` - For any errors encountered when executing the query

<a id="thick.ThickOjdbcConnector.close"></a>

#### close

```python
def close()
```

Close the database connection

**Raises**:

- `DatabaseConnectorException` - For any errors encountered when closing the connection

<a id="thick.ThickOjdbcConnector.tables"></a>

#### tables

```python
@property
def tables() -> list
```

List of all table names in the database

<a id="thick.ThickOjdbcConnector.table_schema"></a>

#### table\_schema

```python
def table_schema(table_name: str) -> list
```

Return schema for all the tables.

These values are returned for each database table:
- Column Name
- Data Type
- Column Description

**Arguments**:

- `table_name` _str_ - Database table name
  

**Returns**:

- `list` - List of Column names, their data type and description of each column
