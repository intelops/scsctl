from dataclasses import dataclass
from questionary import Style
import click
import os
import subprocess
import shutil
from tabulate import tabulate
import json
from scsctl.helper.model import Stats
from scsctl.helper.rebuilder import build_image_with_kaniko_and_download

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
    pyroscope_app_name: str = None
    pyroscope_url: str = None

def modify_and_build_docker_images(file_paths: list, package_names: list, batch_id: str):
    counter = 0
    for file_path in file_paths:
        if os.path.exists("./temp"):
            shutil.rmtree("./temp/")
        #create folder
        os.makedirs("./temp")
        shutil.copyfile(file_path, "./temp/Dockerfile")

        # Create a new file which contains all the packages names to uninstall
        with open("./temp/packages.txt", "w") as f:
            f.write("\n".join(package_names))
        # Add the uninstall commands at the end of the file
        with open("./temp/Dockerfile", "a") as f:
            f.write("\nCOPY packages.txt /tmp/packages.txt")
            f.write(
                '\nRUN while read -r package; do \\\n   if dpkg-query -W --showformat=\'${Essential}\' "$package" | grep -q \'^no$\'; then \\\n   apt-get remove -y "$package"; \\\n    else \\\n   echo "Skipping essential package: $package"; \\\n   fi; \\\ndone < /tmp/packages.txt'
            )

        # Build the docker image with the modified Dockerfile and tag it with the batch id
        click.echo("Building the docker image...")
        try:
            subprocess.check_output(["docker", "build", "-t", f"{batch_id}_{counter}", "./temp/"])
        except subprocess.CalledProcessError as e:
            click.echo(f"Error building the docker image: {e}")
            return False

        # Remove the temp folder
        if os.path.exists("./temp"):
            shutil.rmtree("./temp/")
        counter += 1

def modify_and_build_docker_image(folder_path: str, package_nammes: list, bacth_id: str):
    # Make a copy of folder in a ./temp folder, create folder if it doesn't exist
    # Check if folder_path is a folder or file, if its file take the folder path
    if not os.path.isdir(folder_path):
        file_name = os.path.basename(folder_path)
        folder_path = os.path.dirname(folder_path)
    if os.path.exists("./temp"):
        shutil.rmtree("./temp/")
    shutil.copytree(folder_path, "./temp/")

    # # Create a new file which contains all the packages names to uninstall
    with open("./temp/packages.txt", "w") as f:
        f.write("\n".join(package_nammes))
    # Add the uninstall commands at the end of the file
    with open(f"./temp/{file_name}", "a") as f:
        f.write("\nCOPY packages.txt /tmp/packages.txt")
        f.write(
            '\nRUN while read -r package; do \\\n   if dpkg-query -W --showformat=\'${Essential}\' "$package" | grep -q \'^no$\'; then \\\n   apt-get remove -y "$package"; \\\n    else \\\n   echo "Skipping essential package: $package"; \\\n   fi; \\\ndone < /tmp/packages.txt'
        )

    # Build the docker image with the modified Dockerfile and tag it with the batch id
    click.echo("Building the docker image...")
    try:
        # Abosule path of the temp folder
        absoulute_path = os.path.abspath("./temp/")
        build_image_with_kaniko_and_download(f"{absoulute_path}/{file_name}", "rebuilded-image", "latest")
        # subprocess.check_output(["docker", "build", "-t", f"{bacth_id}", "./temp/"])
    except subprocess.CalledProcessError as e:
        click.echo(f"Error building the docker image: {e}")
        return False

    # Remove the temp folder
    if os.path.exists("./temp"):
        shutil.rmtree("./temp/")
    return True


def generate_final_report(sbom_package_names, pyroscope_package_names=[], falco_found_extra_packages=[], is_api=False):
    sbom_package_names = json.loads(sbom_package_names)
    sbom_package_names = sbom_package_names["Results"]
    sbom_packages = [item["Vulnerabilities"] for item in sbom_package_names][0]
    # sbom_packages = [item["Vulnerabilities"] for item in sbom_package_names if item["Class"] != "lang-pkgs"][0]
    sbom_package_names = list(set([x["PkgName"] for x in sbom_packages]))

    if "total" in pyroscope_package_names:
        pyroscope_package_names.remove("total")
    if "other" in pyroscope_package_names:
        pyroscope_package_names.remove("other")

    #if pyroscope_package_names is empty then everything is extra packages

    extra_packages = list(set(pyroscope_package_names + falco_found_extra_packages))

    # if len(extra_packages) == 0:
    #Generating summary for all vulnerable packages
    extra_packages = sbom_package_names

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
    stats = Stats(vulnerable_packages_count=len(grouped_packages))
    for item in grouped_packages:
        severity = grouped_packages[item]["Severity"]
        for key in severity:
            if key == "CRITICAL":
                stats.severity_critical_count += severity[key]
            elif key == "HIGH":
                stats.severity_high_count += severity[key]
            elif key == "MEDIUM":
                stats.severity_medium_count += severity[key]
            elif key == "LOW":
                stats.severity_low_count += severity[key]
            else:
                stats.severity_unknown_count += severity[key]
        stats.vulnerablitites_count += len(grouped_packages[item]["VulnerabilityID"])
        
        if(is_api):
            data.append({"package_names": item, "vulnerability_ids": grouped_packages[item]["VulnerabilityID"], "severities": [f"{k} - {v}" for k, v in grouped_packages[item]["Severity"].items()]})
            continue
        
        severity_joined = "\n".join(f"{k} - {v}" for k, v in grouped_packages[item]["Severity"].items())
        data.append(
            [
                item,
                "\n".join(grouped_packages[item]["VulnerabilityID"]),
                severity_joined,
            ]
        )

    
    if(is_api):
        return data, stats

    table = tabulate(data, headers=headers, tablefmt="grid")
    return table , stats