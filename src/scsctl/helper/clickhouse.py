import os
from clickhouse_driver import connect
from db_credentials import get_credentials_from_hashicorp_vault


def connect_to_db(database_name: str , vault_enabled=False, creds = {}):

    if vault_enabled:
        creds = get_credentials_from_hashicorp_vault(path=creds["path"], url=creds["url"], token=creds["token"])

    username = os.getenv(key="CLICKHOUSE_USER", default=creds.get("username", "default"))
    password = os.getenv(key="CLICKHOUSE_PASSWORD", default=creds.get("password", ""))
    port = os.getenv(key="CLICKHOUSE_PORT", default=creds.get("port", "8123"))
    host = os.getenv(key="CLICKHOUSE_HOST", default=creds.get("host", "localhost"))
    try:
        conn = connect(f"clickhouse://{host}", user=username, password=password, port=port)
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database_name};")
        return cursor
    except Exception as e:
        print(f"Error connecting to database")
        return None
    # create database if does not exist