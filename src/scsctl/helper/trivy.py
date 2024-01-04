import subprocess
import click
import json
from tabulate import tabulate
from scsctl.helper.clickhouse import connect_to_db
from scsctl.helper.common import AppDetails
import questionary
from datetime import datetime
from scsctl.helper.dgraph import connect_local

def install_trivy():
    try:
        subprocess.run(
            "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b $HOME/.local/bin",
            shell=True,
            check=True,
        )
        print("Trivy installation successful.")
    except subprocess.CalledProcessError as e:
        print(f"Trivy installation failed: {e}")


def get_sbom_report(app_details: AppDetails):
    # Check if Trivy is installed
    docker_trivy_installed = False
    try:
        result = subprocess.run("/usr/local/bin/trivy --version", capture_output=True, shell=True)
        if result.returncode == 0:
            docker_trivy_installed = True
        else:
            result = subprocess.run("$HOME/.local/bin/trivy --version", capture_output=True, shell=True)
        if result.returncode != 0:
            click.echo("\nTrivy is not installed. Installing Trivy...")
            install_trivy()
    except subprocess.CalledProcessError as e:
        click.echo(f"\nError checking Trivy installation: {e}")
        return

    # Trivy is installed, proceed with the scan
    if docker_trivy_installed:
        cmd = f"/usr/local/bin/trivy image {app_details.docker_image_name} --cache-dir /tmp/.cache --format json"
    else:
        cmd = f"$HOME/.local/bin/trivy image {app_details.docker_image_name} --cache-dir /tmp/.cache --format json"
    try:
        click.echo(f"Running Trivy scan")
        result = subprocess.run(cmd, capture_output=True, shell=True, check=True)
        json_output = result.stdout.decode("utf-8")
        return json_output, True
        # Process the JSON output or save it to a file
        # save_sbom_to_db(json_output, app_details)
    except subprocess.CalledProcessError as e:
        click.echo(f"\nTrivy scan failed: {e}")
        return "", False


def print_sbom_report(sbom_report,is_non_interactive=False):
    sbom_report = json.loads(sbom_report)
    sbom_report = sbom_report["Results"]
    sbom_report = [item["Vulnerabilities"] for item in sbom_report if item["Class"] != "lang-pkgs"][0]

    chunk_size = 200
    index = 0

    headers = [
        "VulnerabilityID",
        "PkgName",
        "Severity",
        "InstalledVersion",
        "FixedVersion",
        "Description",
    ]

    data = []
    for item in sbom_report:
        temp = []
        for key in headers:
            temp.append(item.get(key, ""))
        data.append(temp)

    # Change width of the columns (First width is for the index column)
    width = [10, 20, 20, 20, 10, 10, 80]
    
    if is_non_interactive:
        print(tabulate(data, headers=headers, tablefmt="grid",maxcolwidths=width, showindex=list(range(1, len(data) + 1))))
        return

    while index < len(data):
        table = tabulate(
            data[index : index + chunk_size],
            headers=headers,
            tablefmt="grid",
            maxcolwidths=width,
            showindex=list(range(index + 1, index + len(data[index : index + chunk_size]) + 1)),
        )
        click.echo(table)

        if index + chunk_size < len(data):
            show_more = questionary.confirm("Show more?").ask()
            if not show_more:
                break

        index += chunk_size


def save_sbom_data(sbom_data, batch_id,vault_enabled=False, creds = {}):
    database_name = "scsctl"
    cursor = connect_to_db(database_name=database_name, vault_enabled=vault_enabled, creds=creds)
    if cursor:
        table_name = "sbom_report"

        create_table_query = f"""
        CREATE TABLE IF NOT EXISTS {database_name}.{table_name} (
            batch_id String,
            created_at timestamp,
            sbom_report text
        )
        ENGINE = MergeTree()
        PRIMARY KEY (batch_id, created_at)
        """

        cursor.execute(create_table_query)

        click.echo(f"Inserting data into sbom_report table - bacth_id - {batch_id}")

        cursor.execute(
            f"INSERT INTO {database_name}.{table_name} (batch_id, created_at, sbom_report) VALUES",
            [{"batch_id": batch_id, "created_at": datetime.now(), "sbom_report": str(sbom_data)}],
        )

        cursor.close()

def save_sbom_data_to_dgraph(sbom_data, batch_id,dgraph_creds = {}):
    client, client_stub = connect_local(host=dgraph_creds["host"], port=dgraph_creds["port"])

    #Sbom data is a list of vulnerabilities in json format, I have to add batch id to the json. Also the schema is not fixed, so I have to add the schema to the json

    #Add batch id to the json
    sbom_data = json.loads(sbom_data)
    sbom_data["batch_id"] = batch_id
    sbom_data["report_type"] = "sbom_report"
    sbom_data["created_at"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    try:
        # Start a new transaction for data mutation
        txn = client.txn()

        try:
            #Save sbom data to dgraph
            # Create a new node
            response = txn.mutate(set_obj=sbom_data)
            txn.commit()
            print(f"Saved sbom data to dgraph.")

        finally:
            # Clean up resources
            txn.discard()

    finally:
        # Clean up resources
        client_stub.close()