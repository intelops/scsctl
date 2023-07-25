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
)
import click
import questionary
from helper_g.falco import (
    parse_logs_and_get_package_paths,
    compare_and_find_extra_packages_using_falco,
    print_falco_packages,
)


@click.group()
def cli():
    pass


current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
batch_id = f"scsctl_{current_datetime}"


@click.command()
@click.option("--pyroscope_app_name", prompt="Enter pyroscope app name", help="Name of the pyroscope app")
@click.option("--docker_image_name", prompt="Enter docker image name", help="Name of the docker image")
@click.option("--pyroscope_url", prompt="Enter pyroscope url", help="Url of the pyroscope app")
@click.option(
    "--falco_pod_name",
    prompt="Enter falco pod name",
    help="Falco pod name",
    default=None,
    is_flag=False,
    flag_value=None,
)
@click.option(
    "--falco_target_deployment_name",
    prompt="Enter deployment name of the falco target",
    help="Deployment name of the falco target",
    default=None,
    is_flag=False,
    flag_value=None,
)
@click.option("--db_enabled", help="Enable db", default=False, is_flag=True, flag_value=True)
@click.option("--falco_enabled", help="Enable falco", default=False, is_flag=True, flag_value=True)
@click.option(
    "--docker_file_folder_path", help="Path of the docker file to rebuild", default=None, is_flag=False, flag_value=None
)
def scan(
    pyroscope_app_name,
    docker_image_name,
    pyroscope_url,
    falco_pod_name=None,
    falco_target_deployment_name=None,
    docker_file_folder_path=None,
    db_enabled=False,
    falco_enabled=False,
):
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
