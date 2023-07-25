from kubernetes import config, client
import json
import click
import questionary
from tabulate import tabulate
from datetime import datetime


def read_logs_from_log(pod_name, namespace):
    # Load the kube config from the default location
    config.load_kube_config()

    # Create a Kubernetes API client
    v1 = client.CoreV1Api()

    # Get the logs from the pod
    pod_logs = v1.read_namespaced_pod_log(namespace=namespace, name=pod_name)

    # Split the logs by line
    lines = pod_logs.split("\n")
    json_logs = []

    # Iterate over the lines
    for line in lines:
        # Try to parse the line as JSON
        try:
            parsed_json = json.loads(line)
            json_logs.append(parsed_json)
        except json.JSONDecodeError:
            # If the line cannot be parsed as JSON, ignore it
            continue
    return json_logs


def parse_logs_and_get_package_paths(falco_pod_name, target_deployment_name, namespace="default"):
    try:
        logs = read_logs_from_log(pod_name=falco_pod_name, namespace=namespace)
        package_paths = []
        # The json always should have output_fields and k8s.pod.name as keys if falco is configured like our instructions
        for log in logs:
            # check if log have output_fields and output_fields have k8s.pod.name and fd.name, also k8s.pod.name == app_pod_name
            if (
                "output_fields" in log
                and "k8s.deployment.name" in log["output_fields"]
                and "fd.name" in log["output_fields"]
                and log["output_fields"]["k8s.deployment.name"] == target_deployment_name
            ):
                package_paths.append(log["output_fields"]["fd.name"])
        return list(set(package_paths)), True
    except Exception as e:
        return [], False


def compare_and_find_extra_packages_using_falco(falco_package_names, sbom_package_names):
    click.echo("Comparing packages from falco and SBOM...")
    sbom_package_names = json.loads(sbom_package_names)
    sbom_package_names = sbom_package_names["Results"]

    sbom_packages = [item["Vulnerabilities"] for item in sbom_package_names if item["Class"] != "lang-pkgs"][0]
    sbom_package_names = list(set([x["PkgName"] for x in sbom_packages]))
    final_res = []
    for item in sbom_package_names:
        for falco_package in falco_package_names:
            if item in falco_package:
                final_res.append(item)
    extra_packages = list(set(sbom_package_names) - set(final_res))

    return extra_packages


def print_falco_packages(falco_package_names):
    headers = ["Packages"]
    data = []
    for item in falco_package_names:
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
            showindex=list(range(index + 1, index + len(data[index : index + chunk_size]) + 1)),
        )
        click.echo(table)

        if index + chunk_size < len(data):
            show_more = questionary.confirm("Show more?").ask()
            if not show_more:
                break

        index += chunk_size


def save_falco_data(cursor, falco_data, batch_id):
    database_name = "scsctl"
    if cursor:
        table_name = "falco_report"

        create_table_query = f"""
        CREATE TABLE IF NOT EXISTS {database_name}.{table_name} (
            batch_id String,
            created_at timestamp,
            falco_report text
        )
        ENGINE = MergeTree()
        PRIMARY KEY (batch_id, created_at)
        """

        cursor.execute(create_table_query)

        click.echo(f"Inserting data into pyroscope_report table - bacth_id - {batch_id}")

        cursor.execute(
            f"INSERT INTO {database_name}.{table_name} (batch_id, created_at, falco_report) VALUES",
            [{"batch_id": batch_id, "created_at": datetime.now(), "falco_report": str(falco_data)}],
        )

        cursor.close()