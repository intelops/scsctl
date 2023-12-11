import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
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
    save_falco_data_to_dgraph
)

from datetime import datetime

from scsctl.helper.renovate import (check_if_node_and_npm_is_installed,check_if_renovate_is_installed_globally,run_renovate_on_a_repository)

from helper.db_credentials import get_credentials_from_hashicorp_vault

class Config(BaseModel):
    pyroscope_app_name: str
    docker_image_name: str
    pyroscope_url: str
    falco_pod_name: str = None
    falco_target_deployment_name: str = None
    docker_file_folder_path: str = None
    db_enabled: bool = False
    falco_enabled: bool = False
    renovate_enabled: bool = False
    dgraph_enabled: bool = False
    dgraph_db_host: str = None
    dgraph_db_port: str = None
    

class RenovateConfig(BaseModel):
    token: str
    repo_name: str

class TestConfig(BaseModel):
    url: str
    token: str
    path: str

app = FastAPI()

@app.post("/test")
async def test( config: TestConfig ):
    return get_credentials_from_hashicorp_vault( url=config.url, token=config.token, path=config.path)

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.post("/renovate")
async def renovate(renovateConfig: RenovateConfig):
    if(check_if_node_and_npm_is_installed()):
        if(check_if_renovate_is_installed_globally()):
            renovate_process = run_renovate_on_a_repository(token=renovateConfig.token,repo_name=renovateConfig.repo_name)
            if renovate_process.returncode == 0:
                print("Renovate bot ran successfully")
                return True
            else:
                print("Error running renovate bot")
                return False
        else:
            return False
    else:
        return False
    

    

@app.post("/scan")
async def scan_api(config: Config):
    pyroscope_data = []
    pyroscope_found_extra_packages = []
    falco_found_extra_packages = []
    final_report = []
    sbom_report = []
    current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    batch_id = f"scsctl_{current_datetime}"
    falco_found_extra_packages = []
    appDetails = AppDetails(
        pyroscope_app_name=config.pyroscope_app_name, docker_image_name=config.docker_image_name, pyroscope_url=config.pyroscope_url
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
            if config.falco_enabled:
                falco_package_paths, falco_status = parse_logs_and_get_package_paths(
                    falco_pod_name=config.falco_pod_name, target_deployment_name=config.falco_target_deployment_name
                )
                if falco_status:
                    falco_found_extra_packages = config.compare_and_find_extra_packages_using_falco(
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
            if config.db_enabled:
                if(config.dgraph_enabled):
                    save_sbom_data_to_dgraph(sbom_data=sbom_report, batch_id=batch_id,dgraph_creds={"host": config.dgraph_db_host, "port": config.dgraph_db_port})
                    save_pyroscope_data_to_dgraph(pyroscope_data=pyroscope_data, batch_id=batch_id,dgraph_creds={"host": config.dgraph_db_host, "port": config.dgraph_db_port})
                    if config.falco_enabled:
                        save_falco_data_to_dgraph(falco_data=falco_found_extra_packages, batch_id=batch_id,dgraph_creds={"host": config.dgraph_db_host, "port": config.dgraph_db_port})
                    return
                save_sbom_data(sbom_data=sbom_report, batch_id=batch_id)
                save_pyroscope_data(pyroscope_data=pyroscope_data, batch_id=batch_id)
                if config.falco_enabled:
                    save_falco_data(falco_data=falco_found_extra_packages, batch_id=batch_id)

        else:
            scan_status = False
            print("\nError fetching data from pyroscope... Exiting")
    else:
        scan_status = False
        print("\nError fetching data from sbom_report... Exiting")

    renovate_status = "Error"
    if(config.renovate_enabled):
        if(check_if_node_and_npm_is_installed()):
            if(check_if_renovate_is_installed_globally()):
                renovate_process = run_renovate_on_a_repository(token=config.renovate_repo_token,repo_name=config.renovate_repo_name)
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
    return {
        "scan_status": scan_status,
        "sbom_report": sbom_report,
        "pyroscope_data": pyroscope_data,
        "pyroscope_found_extra_packages": pyroscope_found_extra_packages,
        "falco_found_extra_packages": falco_found_extra_packages,
        "final_report": final_report,
        "renovate_status" : renovate_status
    }

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0",port=5000, log_level="info", reload=True)