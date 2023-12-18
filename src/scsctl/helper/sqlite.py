import sqlite3

# Get cursor

def get_cursor():
    conn = sqlite3.connect("scsctl_status.db")

    cursor = conn.cursor()

    #check if table exists, if not create both
    cursor.execute('''CREATE TABLE IF NOT EXISTS scsctl (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_id TEXT NOT NULL,
        run_type TEXT NOT NULL,
        docker_image_name TEXT NOT NULL,
        pyroscope_app_name TEXT NOT NULL,
        pyroscope_url TEXT NOT NULL,
        db_enabled BOOLEAN NOT NULL,
        hashicorp_vault_enabled BOOLEAN NOT NULL,
        renovate_enabled BOOLEAN NOT NULL,
        falco_enabled BOOLEAN NOT NULL,
        renovate_status TEXT NOT NULL,
        falco_status BOOLEAN NOT NULL,
        trivy_status BOOLEAN NOT NULL,
        pyroscope_status BOOLEAN NOT NULL,
        status BOOLEAN NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')

    return cursor, conn