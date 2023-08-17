import click
import requests
import json
from tabulate import tabulate
import questionary
from datetime import datetime
from scsctl.helper.common import AppDetails
from scsctl.helper.clickhouse import connect_to_db


def get_pyroscope_data(app_details: AppDetails):
    # url = f"http://localhost:4040/render?query={pyroscope_app_name}.cpu&from=now-1h&until=now&format=json"
    click.echo(f"Fetching data from pyroscope for {app_details.pyroscope_app_name}...")
    url = f"{app_details.pyroscope_url}/render?query={app_details.pyroscope_app_name}.cpu&from=now-1h&until=now&format=json"
    try:
        response = requests.get(url)
    except Exception as e:
        click.echo(f"\n{e}")
        return "", False
    if response.status_code == 200:
        data = response.json()
        package_names = data["flamebearer"]["names"]
        return package_names, True
    return [], False


def print_pyroscope_packages(pyroscope_package_names,is_non_interactive = False):
    if "total" in pyroscope_package_names:
        pyroscope_package_names.remove("total")
    if "other" in pyroscope_package_names:
        pyroscope_package_names.remove("other")
    headers = ["Packages"]
    data = []
    for item in pyroscope_package_names:
        data.append([item])
    
    width = [100]
    if is_non_interactive:
        print(tabulate(data, headers=headers, tablefmt="grid",maxcolwidths=width, showindex=list(range(1, len(data) + 1))))
        return

    chunk_size = 200
    index = 0


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


def compare_and_find_pyroscope_extra_packages(pyroscope_package_names, sbom_package_names):
    click.echo("Comparing packages from Pyroscope and SBOM...")
    sbom_package_names = json.loads(sbom_package_names)
    sbom_package_names = sbom_package_names["Results"]

    sbom_packages = [item["Vulnerabilities"] for item in sbom_package_names if item["Class"] != "lang-pkgs"][0]
    sbom_package_names = list(set([x["PkgName"] for x in sbom_packages]))

    if "total" in pyroscope_package_names:
        pyroscope_package_names.remove("total")
    if "other" in pyroscope_package_names:
        pyroscope_package_names.remove("other")

    final_res = []
    for item in sbom_package_names:
        for pyroscope_item in pyroscope_package_names:
            if item in pyroscope_item:
                final_res.append(item)
    extra_packages = list(set(sbom_package_names) - set(final_res))

    return extra_packages


def save_pyroscope_data(pyroscope_data, batch_id):
    database_name = "scsctl"
    cursor = connect_to_db(database_name=database_name)
    if cursor:
        table_name = "pyroscope_report"

        create_table_query = f"""
        CREATE TABLE IF NOT EXISTS {database_name}.{table_name} (
            batch_id String,
            created_at timestamp,
            pyroscope_report text
        )
        ENGINE = MergeTree()
        PRIMARY KEY (batch_id, created_at)
        """

        cursor.execute(create_table_query)

        click.echo(f"Inserting data into pyroscope_report table - bacth_id - {batch_id}")

        cursor.execute(
            f"INSERT INTO {database_name}.{table_name} (batch_id, created_at, pyroscope_report) VALUES",
            [{"batch_id": batch_id, "created_at": datetime.now(), "pyroscope_report": str(pyroscope_data)}],
        )

        cursor.close()