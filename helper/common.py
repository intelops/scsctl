from dataclasses import dataclass
from questionary import Style
import click
import os
import subprocess
import shutil
from tabulate import tabulate
import json

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


def modify_and_build_docker_image(folder_path: str, package_nammes: list, bacth_id: str):
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


def generate_final_report(sbom_package_names, pyroscope_package_names=[], falco_found_extra_packages=[]):
    sbom_package_names = json.loads(sbom_package_names)
    sbom_package_names = sbom_package_names["Results"]
    sbom_packages = [item["Vulnerabilities"] for item in sbom_package_names if item["Class"] != "lang-pkgs"][0]
    sbom_package_names = list(set([x["PkgName"] for x in sbom_packages]))

    if "total" in pyroscope_package_names:
        pyroscope_package_names.remove("total")
    if "other" in pyroscope_package_names:
        pyroscope_package_names.remove("other")

    extra_packages = list(set(pyroscope_package_names + falco_found_extra_packages))
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
        severity_joined = "\n".join(f"{k} - {v}" for k, v in grouped_packages[item]["Severity"].items())
        data.append(
            [
                item,
                "\n".join(grouped_packages[item]["VulnerabilityID"]),
                severity_joined,
            ]
        )

    table = tabulate(data, headers=headers, tablefmt="grid")
    return table