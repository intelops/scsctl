import os
import subprocess
from dataclasses import dataclass
import requests
import json
from tabulate import tabulate
import questionary
import click
from questionary import Style
import shutil
from clickhouse_driver import connect
from datetime import datetime

custom_style_fancy = Style(
    [
        ("qmark", "fg:#673ab7 bold"),  # token in front of the question
        ("question", "bold"),  # question text
        ("answer", "fg:#f44336 bold"),  # submitted answer text behind the question
        ("pointer", "fg:#673ab7 bold"),  # pointer used in select and checkbox prompts
        (
            "highlighted",
            "fg:#673ab7 bold",
        ),  # pointed-at choice in select and checkbox prompts
        ("selected", "fg:#cc5454"),  # style for a selected item of a checkbox
        ("separator", "fg:#cc5454"),  # separator in lists
        ("instruction", ""),  # user instructions for select, rawselect, checkbox
        ("text", ""),  # plain text
        (
            "disabled",
            "fg:#858585 italic",
        ),  # disabled choices for select and checkbox prompts
    ]
)


@dataclass
class AppDetails:
    docker_image_name: str
    pyroscope_app_name: str
    pyroscope_url: str


def connect_to_db(database_name: str):
    username = os.getenv(key="CLICKHOUSE_USER", default="default")
    password = os.getenv(key="CLICKHOUSE_PASSWORD", default="")
    port = os.getenv(key="CLICKHOUSE_PORT", default="8123")
    host = os.getenv(key="CLICKHOUSE_HOST", default="localhost")
    try:
        conn = connect(f"clickhouse://{host}",user=username, password=password,port=port)
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database_name};")
        return cursor
    except Exception as e:
        print(f"Error connecting to database")
        return None
    # create database if does not exist


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
    try:
        result = subprocess.run(
            "$HOME/.local/bin/trivy --version", capture_output=True, shell=True
        )
        if result.returncode != 0:
            click.echo("\nTrivy is not installed. Installing Trivy...")
            install_trivy()
    except subprocess.CalledProcessError as e:
        click.echo(f"\nError checking Trivy installation: {e}")
        return

    # Trivy is installed, proceed with the scan
    cmd = f"$HOME/.local/bin/trivy image {app_details.docker_image_name} --format json"
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


def print_pyroscope_packages(pyroscope_package_names):
    if "total" in pyroscope_package_names:
        pyroscope_package_names.remove("total")
    if "other" in pyroscope_package_names:
        pyroscope_package_names.remove("other")
    headers = ["Packages"]
    data = []
    for item in pyroscope_package_names:
        data.append([item])

    chunk_size = 200
    index = 0

    width = [100]

    while index < len(data):
        table = tabulate(
            data[index : index + chunk_size],
            headers=headers,
            tablefmt="grid",
            maxcolwidths=width,
            showindex=list(
                range(index + 1, index + len(data[index : index + chunk_size]) + 1)
            ),
        )
        click.echo(table)

        if index + chunk_size < len(data):
            show_more = questionary.confirm("Show more?").ask()
            if not show_more:
                break

        index += chunk_size


def compare_and_find_extra_packages(pyroscope_package_names, sbom_package_names):
    click.echo("Comparing packages from Pyroscope and SBOM...")
    sbom_package_names = json.loads(sbom_package_names)
    sbom_package_names = sbom_package_names["Results"]

    sbom_packages = [
        item["Vulnerabilities"]
        for item in sbom_package_names
        if item["Class"] != "lang-pkgs"
    ][0]
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

    grouped_packages = {}
    for package in extra_packages:
        filtered_elements = {"VulnerabilityID": [], "Severity": {}}
        for item in sbom_packages:
            if item["PkgName"] == package:
                if item["Severity"] in filtered_elements["Severity"]:
                    filtered_elements["Severity"][item["Severity"]] += 1
                else:
                    filtered_elements["Severity"][item["Severity"]] = 1
                filtered_elements["VulnerabilityID"].append(item["VulnerabilityID"])
        grouped_packages[package] = filtered_elements

    headers = ["Package Names", "Vulnerability IDs", "Severities"]
    data = []
    for item in grouped_packages:
        severity_joined = "\n".join(
            f"{k} - {v}" for k, v in grouped_packages[item]["Severity"].items()
        )
        data.append(
            [
                item,
                "\n".join(grouped_packages[item]["VulnerabilityID"]),
                severity_joined,
            ]
        )

    table = tabulate(data, headers=headers, tablefmt="grid")

    return table, extra_packages


def print_sbom_report(sbom_report):
    sbom_report = json.loads(sbom_report)
    sbom_report = sbom_report["Results"]
    sbom_report = [
        item["Vulnerabilities"] for item in sbom_report if item["Class"] != "lang-pkgs"
    ][0]

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
    # print(data)

    while index < len(data):
        table = tabulate(
            data[index : index + chunk_size],
            headers=headers,
            tablefmt="grid",
            maxcolwidths=width,
            showindex=list(
                range(index + 1, index + len(data[index : index + chunk_size]) + 1)
            ),
        )
        click.echo(table)

        if index + chunk_size < len(data):
            show_more = questionary.confirm("Show more?").ask()
            if not show_more:
                break

        index += chunk_size


def modify_and_build_docker_image(
    folder_path: str, package_nammes: list, bacth_id: str
):
    # Make a copy of folder in a ./temp folder, create folder if it doesn't exist
    if os.path.exists("./temp"):
        shutil.rmtree("./temp/")
    shutil.copytree(folder_path, "./temp/")

    # Create a new file which contains all the packages names to uninstall
    with open("./temp/packages.txt", "w") as f:
        f.write("\n".join(package_nammes))
    # Add the uninstall commands at the end of the file
    with open("./temp/Dockerfile", "a") as f:
        f.write("\nCOPY packages.txt /tmp/packages.txt")
        f.write(
            '\nRUN while read -r package; do \\\n   if dpkg-query -W --showformat=\'${Essential}\' "$package" | grep -q \'^no$\'; then \\\n   apt-get remove -y "$package"; \\\n    else \\\n   echo "Skipping essential package: $package"; \\\n   fi; \\\ndone < /tmp/packages.txt'
        )

    # Build the docker image with the modified Dockerfile and tag it with the batch id
    click.echo("Building the docker image...")
    try:
        subprocess.check_output(["docker", "build", "-t", f"{bacth_id}", "./temp/"])
    except subprocess.CalledProcessError as e:
        click.echo(f"Error building the docker image: {e}")
        return False

    # Remove the temp folder
    if os.path.exists("./temp"):
        shutil.rmtree("./temp/")
    return True


def save_sbom_data(sbom_data, batch_id):
    database_name = "scsctl"
    cursor = connect_to_db(database_name=database_name)
    if(cursor):
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

def save_pyroscope_data(pyroscope_data, batch_id):
    database_name = "scsctl"
    cursor = connect_to_db(database_name=database_name)
    if(cursor):
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
