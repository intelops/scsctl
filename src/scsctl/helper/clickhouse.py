import os
from clickhouse_driver import connect


def connect_to_db(database_name: str):
    username = os.getenv(key="CLICKHOUSE_USER", default="default")
    password = os.getenv(key="CLICKHOUSE_PASSWORD", default="")
    port = os.getenv(key="CLICKHOUSE_PORT", default="8123")
    host = os.getenv(key="CLICKHOUSE_HOST", default="localhost")
    try:
        conn = connect(f"clickhouse://{host}", user=username, password=password, port=port)
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database_name};")
        return cursor
    except Exception as e:
        print(f"Error connecting to database")
        return None
    # create database if does not exist