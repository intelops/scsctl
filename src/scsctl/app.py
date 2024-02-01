from datetime import datetime
import click
import questionary
from scsctl.helper.falco import (
    print_falco_packages,
)
from scsctl.helper.pyroscope import (
    print_pyroscope_packages,
)
from scsctl.helper.common import AppDetails, modify_and_build_docker_images, custom_style_fancy
from scsctl.helper.trivy import print_sbom_report

import yaml

from scsctl.helper.sqlite import get_cursor

from scsctl.helper.scan import run_scan


@click.group()

def cli():
    pass

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
@click.option("--pyroscope_enabled", help="Enable pyroscope", default=False, is_flag=True, flag_value=True)
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
@click.option("--rebuild_image", help="Rebuild the image", default=False, is_flag=True, flag_value=True)
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
    rebuild_image=False,
    docker_file_folder_path=None,
    db_enabled=False,
    falco_enabled=False,
    config_file=None,
    non_interactive = False,
    renovate_enabled = False,
    renovate_repo_token = None,
    renovate_repo_name = None,
    pyroscope_enabled = False,
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
        if not rebuild_image:
            rebuild_image = config_data.get("rebuild_image", False)
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
        if not pyroscope_enabled:
            pyroscope_enabled = config_data.get("pyroscope_enabled", False)

        # Check mandatory fields
        if pyroscope_enabled and pyroscope_app_name is None:
            raise ValueError("pyroscope_app_name is required, either via command line or config file")

        if docker_image_name is None:
            raise ValueError("docker_image_name is required, either via command line or config file")

        if pyroscope_enabled and pyroscope_url is None:
            raise ValueError("pyroscope_url is required, either via command line or config file")
        if falco_enabled and (falco_pod_name is None or falco_target_deployment_name is None):
            raise ValueError(
                "falco_pod_name and falco_target_deployment_name are required, either via command line or config file if falco is enabled"
            )
        if(renovate_enabled and (renovate_repo_token is None or renovate_repo_name is None)):
            raise ValueError("renovate_repo_token and renovate_repo_name are required, either via command line or config file if renovate is enabled")

    """This script will scan the docker image and find the unused packages"""

    current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    batch_id = f"scsctl_{current_datetime}"


    result = run_scan(batch_id=batch_id, pyroscope_enabled = pyroscope_enabled, docker_image_name=docker_image_name,pyroscope_app_name=pyroscope_app_name,pyroscope_url=pyroscope_url,dgraph_enabled=dgraph_enabled,dgraph_db_host=dgraph_db_host,dgraph_db_port=dgraph_db_port,renovate_enabled=renovate_enabled,falco_enabled=falco_enabled,falco_pod_name=falco_pod_name,falco_target_deployment_name=falco_target_deployment_name,db_enabled=db_enabled,renovate_repo_token=renovate_repo_token,renovate_repo_name=renovate_repo_name,docker_file_folder_path=docker_file_folder_path,db_hashicorp_vault_enabled=db_hashicorp_vault_enabled,db_hashicorp_vault_url=db_hashicorp_vault_url,db_hashicorp_vault_token=db_hashicorp_vault_token,db_hashicorp_vault_path=db_hashicorp_vault_path,non_interactive=non_interactive,rebuild_image=rebuild_image, is_api=True)

    scan_status = result.get("scan_status")
    sbom_report = result.get("sbom_report")
    pyroscope_data = result.get("pyroscope_data")
    pyroscope_found_extra_packages = result.get("pyroscope_found_extra_packages")
    falco_found_extra_packages = result.get("falco_found_extra_packages")
    final_report = result.get("final_report")


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
            click.echo({
                "sbom_report": result.get("sbom_report"),
                "pyroscope_data" :result.get("pyroscope_data"),
                "final_report" : result.get("final_report")
            })
            # click.echo("Sbom report")
            # click.echo("===========")
            # print_sbom_report(sbom_report = sbom_report,is_non_interactive = True)
            # click.echo("Pyroscope detected packages")
            # click.echo("===========================")
            # print_pyroscope_packages(pyroscope_package_names = pyroscope_data,is_non_interactive = True)
            # if falco_enabled:
            #     click.echo("Falco detected packages")
            #     click.echo("=======================")
            #     print_falco_packages(falco_package_names = falco_found_extra_packages,is_non_interactive = True)
            # click.echo("Final Report")
            # click.echo("=============")
            # click.echo(final_report)
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