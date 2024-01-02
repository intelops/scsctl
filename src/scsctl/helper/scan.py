
from scsctl.helper.renovate import (check_if_node_and_npm_is_installed,check_if_renovate_is_installed_globally,run_renovate_on_a_repository)

from scsctl.helper.pyroscope import (
    get_pyroscope_data,
    save_pyroscope_data,
    compare_and_find_pyroscope_extra_packages,
    save_pyroscope_data_to_dgraph
)

from scsctl.helper.trivy import (get_sbom_report)

from scsctl.helper.common import AppDetails,generate_final_report

from scsctl.helper.trivy import get_sbom_report, save_sbom_data, save_sbom_data_to_dgraph

from scsctl.helper.falco import (
    parse_logs_and_get_package_paths,
    save_falco_data,
    save_falco_data_to_dgraph,
    compare_and_find_extra_packages_using_falco
)

from scsctl.helper.sqlite import get_cursor


def save_status_to_db(batch_id, docker_image_name,pyroscope_app_name = None, pyroscope_url = None, renovate_enabled = False, falco_enabled = False, db_enabled = False, renovate_status = "", sbom_status = False, pyroscope_status = False, falco_status = False, scan_status = False):
    cursor, conn = get_cursor()

    cursor.execute(f"INSERT INTO scsctl (batch_id,run_type,docker_image_name,pyroscope_app_name,pyroscope_url,db_enabled,hashicorp_vault_enabled,renovate_enabled,falco_enabled,renovate_status,falco_status,trivy_status,pyroscope_status,status) VALUES ('{batch_id}','api','{docker_image_name}','{pyroscope_app_name}','{pyroscope_url}',{db_enabled},{False},{renovate_enabled},{falco_enabled},'{renovate_status}',{falco_status},{sbom_status},{pyroscope_status},{scan_status})")

    conn.commit()
    conn.close()

def run_scan(batch_id, docker_image_name,pyroscope_enabled = False,pyroscope_app_name = None, pyroscope_url = None, dgraph_enabled = False, dgraph_db_host = "", dgraph_db_port = "",renovate_enabled = False, falco_enabled = False,falco_pod_name = "",falco_target_deployment_name = "", db_enabled = False, renovate_repo_token = "", renovate_repo_name = "", docker_file_folder_path = "", **kwargs):
    #check if kwargs have job_id and store it in a variable
    job_id = kwargs.get("job_id", None)
    is_scheduled = kwargs.get("is_scheduled", False)
    print(job_id)
    pyroscope_data = []
    pyroscope_found_extra_packages = []
    falco_found_extra_packages = []
    final_report = []
    sbom_report = []
    falco_found_extra_packages = []
    appDetails = AppDetails(
        pyroscope_app_name=pyroscope_app_name, docker_image_name=docker_image_name, pyroscope_url=pyroscope_url
    )
    scan_status = True
    renovate_status = ""
    sbom_status = False
    pyroscope_status = False
    falco_status = False
    sbom_report, sbom_status = get_sbom_report(appDetails)
    if sbom_status:
        if(pyroscope_enabled):
            #Pyroscope enabled
            pyroscope_data, pyroscope_status = get_pyroscope_data(appDetails)
            if pyroscope_status:
                pyroscope_found_extra_packages = compare_and_find_pyroscope_extra_packages(
                    pyroscope_package_names=pyroscope_data,
                    sbom_package_names=sbom_report,
                )
            else:
                scan_status = False
                print("\nError fetching data from pyroscope... Exiting")
                save_status_to_db(batch_id=batch_id, docker_image_name=docker_image_name,pyroscope_app_name = pyroscope_app_name, pyroscope_url = pyroscope_url, renovate_enabled = renovate_enabled, falco_enabled = falco_enabled, db_enabled = db_enabled, renovate_status = renovate_status, sbom_status = sbom_status, pyroscope_status = pyroscope_status, falco_status = falco_status, scan_status = scan_status)

                return {
                    "batch_id": batch_id,
                    "scan_status": scan_status,
                    "sbom_report": sbom_report,
                    "pyroscope_data": pyroscope_data,
                    "pyroscope_found_extra_packages": pyroscope_found_extra_packages,
                    "falco_found_extra_packages": falco_found_extra_packages,
                    "final_report": final_report,
                    "renovate_status" : renovate_status
                }
        else:
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
                    falco_found_extra_packages=falco_found_extra_packages
                )
            else:
                final_report = generate_final_report(
                    sbom_package_names=sbom_report, pyroscope_package_names=pyroscope_found_extra_packages, is_api = True
                )
            if db_enabled:
                if(dgraph_enabled):
                    save_sbom_data_to_dgraph(sbom_data=sbom_report, batch_id=batch_id,dgraph_creds={"host": dgraph_db_host, "port": dgraph_db_port})
                    save_pyroscope_data_to_dgraph(pyroscope_data=pyroscope_data, batch_id=batch_id,dgraph_creds={"host": dgraph_db_host, "port": dgraph_db_port})
                    if falco_enabled:
                        save_falco_data_to_dgraph(falco_data=falco_found_extra_packages, batch_id=batch_id,dgraph_creds={"host": dgraph_db_host, "port": dgraph_db_port})
                else:
                    save_sbom_data(sbom_data=sbom_report, batch_id=batch_id)
                    save_pyroscope_data(pyroscope_data=pyroscope_data, batch_id=batch_id)
                    if falco_enabled:
                        save_falco_data(falco_data=falco_found_extra_packages, batch_id=batch_id)

    else:
        scan_status = False
        print("\nError fetching data from sbom_report... Exiting")

    renovate_status = "Error"
    if(renovate_enabled):
        if(check_if_node_and_npm_is_installed()):
            if(check_if_renovate_is_installed_globally()):
                renovate_process = run_renovate_on_a_repository(token=renovate_repo_token,repo_name=renovate_repo_name)
                if renovate_process.returncode == 0:
                    renovate_status = "Renovate bot ran successfully"
                else:
                    renovate_status = "Error running renovate bot"
            else:
                renovate_status = "Renovate bot not installed, please install using `npm install -g renovate`"
        else:
            renovate_status = "Node or npm not installed, please install them to use scsctl with renovate"
    else:
        renovate_status = "Renovate not enabled"

    save_status_to_db(batch_id=batch_id, docker_image_name=docker_image_name,pyroscope_app_name = pyroscope_app_name, pyroscope_url = pyroscope_url, renovate_enabled = renovate_enabled, falco_enabled = falco_enabled, db_enabled = db_enabled, renovate_status = renovate_status, sbom_status = sbom_status, pyroscope_status = pyroscope_status, falco_status = falco_status, scan_status = scan_status)

    # print({
    #     "batch_id": batch_id,
    #     "scan_status": scan_status,
    #     "sbom_report": sbom_report,
    #     "pyroscope_data": pyroscope_data,
    #     "pyroscope_found_extra_packages": pyroscope_found_extra_packages,
    #     "falco_found_extra_packages": falco_found_extra_packages,
    #     "final_report": final_report,
    #     "renovate_status" : renovate_status
    # })

    return {
        "batch_id": batch_id,
        "scan_status": scan_status,
        "sbom_report": sbom_report,
        "pyroscope_data": pyroscope_data,
        "pyroscope_found_extra_packages": pyroscope_found_extra_packages,
        "falco_found_extra_packages": falco_found_extra_packages,
        "final_report": final_report,
        "renovate_status" : renovate_status
    }