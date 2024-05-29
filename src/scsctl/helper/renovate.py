import subprocess
import datetime
import json
from tabulate import tabulate
import click
import questionary

def check_if_node_and_npm_is_installed():
    # Check if node and npm are installed
    # If not, install them locally
    # This is required for renovate bot to work
    node_version = subprocess.run(["node", "--version"], capture_output=True)
    npm_version = subprocess.run(["npm", "--version"], capture_output=True)
    if node_version.returncode != 0 or npm_version.returncode != 0:
        print("Node or npm not installed, please install them to use scsctl with renovate")
        return False
    print("Node and npm already installed")
    return True

def check_if_renovate_is_installed_globally():
    # Install renovate bot
    # This is required for renovate bot to work
    renovate_version = subprocess.run(["renovate", "--version"], capture_output=True)
    if renovate_version.returncode != 0:
        print("Renovate bot not installed, please install using `npm install -g renovate`")
        return False
    else:
        print("Renovate bot already installed")
        return True
    
def run_renovate_on_a_repository(token, repo_name):
    command = f"renovate --token {token} {repo_name}"
    print(f"Runing renovate on repo {repo_name}")
    #run renovate command from python
    renovate_process = subprocess.run(["renovate", "--token", token,repo_name], capture_output=True)
    return renovate_process

def run_renovate_dry_run_on_a_repository(token, repo_name):
    command = f"renovate --token {token} --dry-run {repo_name}"
    print(f"Runing renovate dry-run on repo {repo_name}")
    #run renovate command from python
    renovate_log_file = f"./proact-renovate-dry-run-{int(round(datetime.datetime.now().timestamp()))}.log.json"
    subprocess.run(["renovate", "--token", token, "--dry-run=lookup ", repo_name, f"--log-file={renovate_log_file}"], capture_output=True)
    log = parse_renovate_log_file(renovate_log_file)
    # Remove the log file
    subprocess.run(["rm", renovate_log_file])
    return True, log

def parse_renovate_log_file(log_file):
    # log file is a new line separated json file
    data = []
    with open(log_file, "r") as f:
        # Parse each line as json and take the line which contains the key alertPackageRules
        for line in f:
            json_line = json.loads(line)
            if "alertPackageRules" in json_line:
                data = json_line["alertPackageRules"]
                break
    return data


def print_renovate_report(renovate_report = [],is_non_interactive=False):
    chunk_size = 200
    index = 0

    headers = [
        "Data Sources",
        "Package Names",
        "File names",
        "Installed Version",
        "Fixed Version",
        "Description",
    ]

    # Create enum for the headers
    headers_enum = {
        "Data Sources": "matchDatasources",
        "Package Names": "matchPackageNames",
        "File names": "matchFileNames",
        "Installed Version": "matchCurrentVersion",
        "Fixed Version": "allowedVersions",
        "Description": "prBodyNotes",
    }

    data = []
    for item in renovate_report:
        temp = []
        for key in headers:
            temp.append(item.get(headers_enum[key], ""))
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