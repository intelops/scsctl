import os

def get_postgres_db_url():

    # Try to read the environment variable
    host = os.getenv('PG_HOST', 'localhost')
    port = os.getenv('PG_PORT', '5432')
    user = os.getenv('PG_USER', 'postgres')
    password = os.getenv('PG_PASSWORD', 'password')
    database = os.getenv('PG_DATABASE', 'postgres')

    url = f"postgresql://{user}:{password}@{host}:{port}/{database}"

    return url