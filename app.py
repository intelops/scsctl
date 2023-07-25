from datetime import datetime
from helper import (
    get_sbom_report,
    get_pyroscope_data,
    AppDetails,
    compare_and_find_extra_packages,
    print_sbom_report,
    print_pyroscope_packages,
    custom_style_fancy,
    modify_and_build_docker_image,
    save_sbom_data,
    save_pyroscope_data,
    connect_to_db,
)
import click
import questionary
from helper_g.falco import (
    parse_logs_and_get_package_paths,
    compare_and_find_extra_packages_using_falco,
    print_falco_packages,
    save_falco_data,
)

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
@click.option("--falco_enabled", help="Enable falco", default=False, is_flag=True, flag_value=True)
@click.option(
    "--docker_file_folder_path", help="Path of the docker file to rebuild", default=None, is_flag=False, flag_value=None
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

        # For flags, only set from config if not set from command line
        if not db_enabled:
            db_enabled = config_data.get("db_enabled", False)
        if not falco_enabled:
            falco_enabled = config_data.get("falco_enabled", False)

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

    """This script will scan the docker image and find the unused packages"""
    appDetails = AppDetails(
        pyroscope_app_name=pyroscope_app_name, docker_image_name=docker_image_name, pyroscope_url=pyroscope_url
    )

    scan_status = True
    sbom_report, sbom_status = get_sbom_report(appDetails)
    if sbom_status:
        pyroscope_data, pyroscope_status = get_pyroscope_data(appDetails)
        if pyroscope_status:
            if falco_enabled:
                falco_package_paths, falco_status = parse_logs_and_get_package_paths(
                    falco_pod_name=falco_pod_name, target_deployment_name=falco_target_deployment_name
                )
                if falco_status:
                    falco_found_extra_packages = compare_and_find_extra_packages_using_falco(
                        falco_package_paths, sbom_report
                    )
                    final_report, extra_packages = compare_and_find_extra_packages(
                        pyroscope_package_names=pyroscope_data,
                        sbom_package_names=sbom_report,
                        falco_found_extra_packages=falco_found_extra_packages,
                    )
            else:
                final_report, extra_packages = compare_and_find_extra_packages(
                    pyroscope_package_names=pyroscope_data, sbom_package_names=sbom_report
                )

            if db_enabled:
                save_sbom_data(sbom_data=sbom_report, batch_id=batch_id)
                save_pyroscope_data(pyroscope_data=pyroscope_data, batch_id=batch_id)
                cursor = connect_to_db("scsctl")
                if falco_enabled:
                    save_falco_data(cursor, falco_data=falco_found_extra_packages, batch_id=batch_id)

        else:
            scan_status = False
            click.echo("\nError fetching data from pyroscope... Exiting")
    else:
        scan_status = False
        click.echo("\nError fetching data from sbom_report... Exiting")

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
                modify_and_build_docker_image(docker_file_folder_path, extra_packages, batch_id)


cli.add_command(scan)


if __name__ == "__main__":
    cli()