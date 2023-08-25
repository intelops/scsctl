import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from scsctl.helper.pyroscope import (
    get_pyroscope_data,
    save_pyroscope_data,
    compare_and_find_pyroscope_extra_packages,
)

from scsctl.helper.trivy import (get_sbom_report)

from scsctl.helper.common import AppDetails,generate_final_report

from scsctl.helper.trivy import get_sbom_report, save_sbom_data

from scsctl.helper.falco import (
    parse_logs_and_get_package_paths,
    save_falco_data,
)

from datetime import datetime

class Config(BaseModel):
    pyroscope_app_name: str
    docker_image_name: str
    pyroscope_url: str
    falco_pod_name: str = None
    falco_target_deployment_name: str = None
    docker_file_folder_path: str = None
    db_enabled: bool = False
    falco_enabled: bool = False

app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.post("/scan")
async def scan_api(config: Config):
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
    return {
        "scan_status": scan_status,
        "sbom_report": sbom_report,
        "pyroscope_data": pyroscope_data,
        "pyroscope_found_extra_packages": pyroscope_found_extra_packages,
        "falco_found_extra_packages": falco_found_extra_packages,
        "final_report": final_report,
    }

if __name__ == "__main__":
    uvicorn.run("server:app", port=5000, log_level="info", reload=True)