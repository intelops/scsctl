from datetime import datetime
import click
import questionary
from scsctl.helper.falco import (
    parse_logs_and_get_package_paths,
    compare_and_find_extra_packages_using_falco,
    print_falco_packages,
    save_falco_data,
    save_falco_data_to_dgraph
)
from scsctl.helper.pyroscope import (
    get_pyroscope_data,
    print_pyroscope_packages,
    save_pyroscope_data,
    compare_and_find_pyroscope_extra_packages,
    save_pyroscope_data_to_dgraph
)
from scsctl.helper.common import AppDetails, generate_final_report, modify_and_build_docker_image,modify_and_build_docker_images, custom_style_fancy
from scsctl.helper.trivy import get_sbom_report, print_sbom_report, save_sbom_data, save_sbom_data_to_dgraph
from scsctl.helper.renovate import (check_if_node_and_npm_is_installed,check_if_renovate_is_installed_globally,run_renovate_on_a_repository)

import yaml


@click.group()
def cli():
    pass


current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
batch_id = f"scsctl_{current_datetime}"


@click.command()
@click.option("--pyroscope_app_name", default=None, help="Name of the pyroscope app")
@click.option("--docker_image_name", default=None, help="Name of the docker image")
@click.option("--pyroscope_url", default=None, help="Url of the pyroscope app")
@click.option(
    "--falco_pod_name",
    default=None,
    help="Falco pod name",
    is_flag=False,
    flag_value=None,
)
@click.option(
    "--falco_target_deployment_name",
    default=None,
    help="Deployment name of the falco target",
    is_flag=False,
    flag_value=None,
)
@click.option("--db_enabled", help="Enable db", default=False, is_flag=True, flag_value=True)
@click.option("--dgraph_enabled", help="Enable dgraph", default=False, is_flag=True, flag_value=True)
@click.option("--dgraph_db_host", help="Host of the db", default="localhost", is_flag=False, flag_value=None)
@click.option("--dgraph_db_port", help="Port of the db", default=9080, is_flag=False, flag_value=None)
@click.option("--db_hashicorp_vault_enabled", help="Read db creds from hashicorp vault", default=False, is_flag=True, flag_value=True)
@click.option("--db_hashicorp_vault_url", help="Url of the hashicorp vault", default=None, is_flag=False, flag_value=None)
@click.option("--db_hashicorp_vault_token", help="Token of the hashicorp vault", default=None, is_flag=False, flag_value=None)
@click.option("--db_hashicorp_vault_path", help="Path of the hashicorp vault", default=None, is_flag=False, flag_value=None)
@click.option("--falco_enabled", help="Enable falco", default=False, is_flag=True, flag_value=True)
@click.option("--renovate_enabled", help="Enable renovate", default=False, is_flag=True, flag_value=True)
@click.option("--renovate_repo_token", help="Repo token for renovate", default=None, is_flag=False, flag_value=None)
@click.option("--renovate_repo_name", help="Repo name for renovate", default=None, is_flag=False, flag_value=None)
@click.option("--non_interactive", help="Run scsctl in non interactive mode", default= False, is_flag=True, flag_value=True)
@click.option(
    "--docker_file_folder_path", help="Path of the docker file to rebuild", default=None, is_flag=False, flag_value=None, multiple=True
)
@click.option("--config_file", help="Path of the configuration file", default=None, is_flag=False, flag_value=None)

def scan(
    pyroscope_app_name=None,
    docker_image_name=None,
    pyroscope_url=None,
    falco_pod_name=None,
    falco_target_deployment_name=None,
    docker_file_folder_path=None,
    db_enabled=False,
    falco_enabled=False,
    config_file=None,
    non_interactive = False,
    renovate_enabled = False,
    renovate_repo_token = None,
    renovate_repo_name = None,
    db_hashicorp_vault_enabled=False,
    db_hashicorp_vault_url=None,
    db_hashicorp_vault_token=None,
    db_hashicorp_vault_path=None,
    dgraph_enabled=False,
    dgraph_db_host="localhost",
    dgraph_db_port=9080
):
    config_data = {}
    if config_file is not None:
        with open(config_file, "r") as f:
            config_data = yaml.safe_load(f)

        # If command line options are not provided, take the options from the configuration file
        if pyroscope_app_name is None:
            pyroscope_app_name = config_data.get("pyroscope_app_name")
        if docker_image_name is None:
            docker_image_name = config_data.get("docker_image_name")
        if pyroscope_url is None:
            pyroscope_url = config_data.get("pyroscope_url")
        if falco_pod_name is None:
            falco_pod_name = config_data.get("falco_pod_name")
        if falco_target_deployment_name is None:
            falco_target_deployment_name = config_data.get("falco_target_deployment_name")
        if docker_file_folder_path is None:
            docker_file_folder_path = config_data.get("docker_file_folder_path")
        if db_hashicorp_vault_url is None:
            db_hashicorp_vault_url = config_data.get("db_hashicorp_vault_url")
        if db_hashicorp_vault_token is None:
            db_hashicorp_vault_token = config_data.get("db_hashicorp_vault_token")
        if db_hashicorp_vault_path is None:
            db_hashicorp_vault_path = config_data.get("db_hashicorp_vault_path")

        # For flags, only set from config if not set from command line
        if not db_enabled:
            db_enabled = config_data.get("db_enabled", False)
        if not falco_enabled:
            falco_enabled = config_data.get("falco_enabled", False)
        if not renovate_enabled:
            renovate_enabled = config_data.get("renovate_enabled", False)
        if not db_hashicorp_vault_enabled:
            db_hashicorp_vault_enabled = config_data.get("db_hashicorp_vault_enabled", False)
        if not dgraph_enabled:
            dgraph_enabled = config_data.get("dgraph_enabled", False)
        if not dgraph_db_host:
            dgraph_db_host = config_data.get("dgraph_db_host", "localhost")
        if not dgraph_db_port:
            dgraph_db_port = config_data.get("dgraph_db_port", 9080)

        # Check mandatory fields
        if pyroscope_app_name is None:
            raise ValueError("pyroscope_app_name is required, either via command line or config file")

        if docker_image_name is None:
            raise ValueError("docker_image_name is required, either via command line or config file")

        if pyroscope_url is None:
            raise ValueError("pyroscope_url is required, either via command line or config file")
        if falco_enabled and (falco_pod_name is None or falco_target_deployment_name is None):
            raise ValueError(
                "falco_pod_name and falco_target_deployment_name are required, either via command line or config file if falco is enabled"
            )
        if(renovate_enabled and (renovate_repo_token is None or renovate_repo_name is None)):
            raise ValueError("renovate_repo_token and renovate_repo_name are required, either via command line or config file if renovate is enabled")

    """This script will scan the docker image and find the unused packages"""
    appDetails = AppDetails(
        pyroscope_app_name=pyroscope_app_name, docker_image_name=docker_image_name, pyroscope_url=pyroscope_url
    )

    scan_status = True
    sbom_report, sbom_status = get_sbom_report(appDetails)
    if sbom_status:
        pyroscope_data, pyroscope_status = get_pyroscope_data(appDetails)
        if pyroscope_status:
            pyroscope_found_extra_packages = compare_and_find_pyroscope_extra_packages(
                pyroscope_package_names=pyroscope_data,
                sbom_package_names=sbom_report,
            )
            if falco_enabled:
                falco_package_paths, falco_status = parse_logs_and_get_package_paths(
                    falco_pod_name=falco_pod_name, target_deployment_name=falco_target_deployment_name
                )
                if falco_status:
                    falco_found_extra_packages = compare_and_find_extra_packages_using_falco(
                        falco_package_paths, sbom_report
                    )
                final_report = generate_final_report(
                    sbom_package_names=sbom_report,
                    pyroscope_package_names=pyroscope_found_extra_packages,
                    falco_found_extra_packages=falco_found_extra_packages,
                )
            else:
                final_report = generate_final_report(
                    sbom_package_names=sbom_report, pyroscope_package_names=pyroscope_found_extra_packages
                )
            if db_enabled:
                if(dgraph_enabled):
                    save_sbom_data_to_dgraph(sbom_data=sbom_report, batch_id=batch_id,dgraph_creds={"host": dgraph_db_host, "port": dgraph_db_port})
                    save_pyroscope_data_to_dgraph(pyroscope_data=pyroscope_data, batch_id=batch_id,dgraph_creds={"host": dgraph_db_host, "port": dgraph_db_port})
                    if falco_enabled:
                        save_falco_data_to_dgraph(falco_data=falco_found_extra_packages, batch_id=batch_id,dgraph_creds={"host": dgraph_db_host, "port": dgraph_db_port})
                    return
                if(db_hashicorp_vault_enabled and (db_hashicorp_vault_url == "" or db_hashicorp_vault_token == "" or db_hashicorp_vault_path == "")):
                    click.echo("Please provide db_hashicorp_vault_url, db_hashicorp_vault_token and db_hashicorp_vault_path to save data to db")
                    return
                save_sbom_data(sbom_data=sbom_report, batch_id=batch_id, vault_enabled=db_hashicorp_vault_enabled, creds={"url":db_hashicorp_vault_url,"token":db_hashicorp_vault_token,"path":db_hashicorp_vault_path})
                save_pyroscope_data(pyroscope_data=pyroscope_data, batch_id=batch_id, vault_enabled=db_hashicorp_vault_enabled, creds={"url":db_hashicorp_vault_url,"token":db_hashicorp_vault_token,"path":db_hashicorp_vault_path})
                if falco_enabled:
                    save_falco_data(falco_data=falco_found_extra_packages, batch_id=batch_id, vault_enabled=db_hashicorp_vault_enabled, creds={"url":db_hashicorp_vault_url,"token":db_hashicorp_vault_token,"path":db_hashicorp_vault_path})

        else:
            scan_status = False
            click.echo("\nError fetching data from pyroscope... Exiting")
    else:
        scan_status = False
        click.echo("\nError fetching data from sbom_report... Exiting")

    if(renovate_enabled):
        if(check_if_node_and_npm_is_installed()):
            if(check_if_renovate_is_installed_globally()):
                renovate_process = run_renovate_on_a_repository(token=renovate_repo_token,repo_name=renovate_repo_name)
                if renovate_process.returncode == 0:
                    click.echo("Renovate bot ran successfully")
                    return True
                else:
                    click.echo("Error running renovate bot")
                    return False
            else:
                return False
        else:
            return False
        

    choices = [
        "Sbom report",
        "Pyroscope detected packages",
        "Falco detected packages",
        "Final report",
        "Rebuild the image",
        "Exit",
    ]

    if falco_enabled == False:
        choices.remove("Falco detected packages")

    if scan_status:
        if(non_interactive):
            click.echo("Sbom report")
            click.echo("===========")
            print_sbom_report(sbom_report = sbom_report,is_non_interactive = True)
            click.echo("Pyroscope detected packages")
            click.echo("===========================")
            print_pyroscope_packages(pyroscope_package_names = pyroscope_data,is_non_interactive = True)
            if falco_enabled:
                click.echo("Falco detected packages")
                click.echo("=======================")
                print_falco_packages(falco_package_names = falco_found_extra_packages,is_non_interactive = True)
            click.echo("Final Report")
            click.echo("=============")
            click.echo(final_report)
        else:
            while True:
                choice = questionary.select("Select an option", choices=choices, style=custom_style_fancy).ask()
                if choice == "Exit":
                    break
                if choice == "Sbom report":
                    print_sbom_report(sbom_report)
                if choice == "Pyroscope detected packages":
                    print_pyroscope_packages(pyroscope_data)
                if choice == "Falco detected packages":
                    print_falco_packages(falco_found_extra_packages)
                if choice == "Final report":
                    click.echo("Vulnerable packages that can be uninstalled from the docker image are:")
                    click.echo(final_report)
                if choice == "Rebuild the image":
                    if docker_file_folder_path == None:
                        docker_file_folder_path = click.prompt("Enter docker file folder path", type=str)
                    # modify_and_build_docker_image(docker_file_folder_path, pyroscope_found_extra_packages, batch_id)
                    modify_and_build_docker_images(file_paths=docker_file_folder_path,package_names=pyroscope_found_extra_packages,batch_id=batch_id)


cli.add_command(scan)


if __name__ == "__main__":
    cli()