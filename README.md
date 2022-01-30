# Ruuvi Gateway fetch data script

Python script for fetching and parsing sensor data from Ruuvi Gateway.

## Setup and execute


Create virtual env and install requirements

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Set IP, username and password to `fetch_data.py` script, If authentication is not enabled, username and password can be empty.

```py
STATION_IP = "10.0.0.21"
USERNAME = "username"
PASSWORD = "password"
```

Execute script

```sh
python fetch_data.py
```