import os

def get_postgres_db_url():

    # Try to read the environment variable
    host = os.getenv('SCSCTL_PG_HOST', 'localhost')
    port = os.getenv('SCSCTL_PG_PORT', '5432')
    user = os.getenv('SCSCTL_PG_USER', 'postgres')
    password = os.getenv('SCSCTL_PG_PASSWORD', 'password')
    database = os.getenv('SCSCTL_PG_DATABASE', 'scsctl')

    url = f"postgresql://{user}:{password}@{host}:{port}/{database}"

    return url