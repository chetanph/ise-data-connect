[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/chetanph/ise-data-connect)

# ISE Data Connect

This repository provides a Python library to interact with Cisco Identity Services Engine (ISE) Data Connect. The goal is to provide a way to interact with ISE data connect with minimal Python code and focus more on use cases.

```python
from ise import IseDataConnect

with IseDataConnect("ise-snmt.example.org", "2484", "dataconnect", "Cisco.123456#", verify=False) as ise_dc:
    for node in ise_dc.get_node_list():
      print(f"{node.hostname} {node.node_type} {node.replication_status}")

    for admin_user in ise_dc.execute_query("SELECT * FROM 'ADMIN_USERS'"):
      print(admin_user)
```

The `main.py` example shows how to obtain node list as well as execute SQL queries for RADIUS
authentication summary reports.

![Main Output](./images/output.png)

More detailed documentation is available [here](./docs/README.md)

## Installation

Clone the repo:

```bash
git clone https://github.com/chetanph/ise-data-connect.git

cd ise-data-connect
```

Create the virtual environment and activate it:

```bash
python3 -m venv .venv

source .venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

## Configuration

These environment variables or CLI arguments can be used to provide inputs to `main.py`. CLI arguments take precedence over environment variables.

| Environment Variable | CLI Argument | Purpose |
| --- | --- | --- |
| `ISE_HOSTNAME` | `--ise-hostname` | ISE hostname for Data Connect |
| `ISE_DATACONNECT_PORT` | `--ise-dataconnect-port` | ISE Data Connect port, defaults to `2484` |
| `DATACONNECT_USER` | `--dataconnect-user` | ISE Data Connect username, defaults to `dataconnect` |
| `DATACONNECT_PASSWORD` | `--dataconnect-password` | ISE Data Connect password |
| `DATACONNECT_LOG_LEVEL` | `--log-level` | Logging level, defaults to `INFO` |
| `DATACONNECT_INSECURE` | `--insecure` | Ignore ISE Data Connect certificate, defaults to `False`. Used for thin client |
| `OJDBC_JAR` | `--ojdbc-jar` | Path of the JAR file used for thick client, defaults to `ojdbc11-23.4.0.24.05.jar` |
| `TRUST_STORE` | `--trust-store` | Path to Java key store file (used for thick client), defaults to `keystore.jks` |
| `TRUST_STORE_PASSWORD` | `--trust-store-password` | Password for Java key store file (used for thick client) |

Provide input configuration, either as environment variables or CLI arguments.

```bash
# (Option 1) Environment Variables
export ISE_HOSTNAME="ise-snmt.example.org"
export DATACONNECT_PASSWORD="Cisco123456#"

# (Option 2)
python main.py \
  --ise-hostname "ise-snmt.example.org" \
  --dataconnect-password "Cisco123456#"
```

## How to test the software

Make sure to follow the ISE Data Connect [Getting Started](https://developer.cisco.com/docs/dataconnect/getting-started/#getting-started) guide to enable Data Connect feature.

Follow the steps described above to setup the automation environment.

The automation environment must have access to ISE node, typically secondary Monitoring node, over TCP/2484 port.

Then run main app

```bash
python main.py
```

This has been tested with Python 3.11 and ISE version 3.2.

### References

- [ISE Data Connect](https://developer.cisco.com/docs/dataconnect/introduction/)
- [ISE Data Connect Python example by 1homas@github](https://github.com/1homas/ISE_Python_Scripts/tree/main?tab=readme-ov-file#iseqlpy)

### DevNet Sandbox

https://devnetsandbox.cisco.com/DevNet/catalog/ise-sandbox

## Getting help

If you have questions, concerns, bug reports, etc., please create an issue against this repository.

## Author(s)

This project was written and is maintained by the following individuals:

* Chetankumar Phulpagare
