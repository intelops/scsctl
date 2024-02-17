import uvicorn
from fastapi import FastAPI
from datetime import datetime
from scsctl.helper.model import ScanConfig
from scsctl.routers import schedule
from scsctl.helper.scan import run_scan
# from scsctl.routers.schedule import create_scheduler
from scsctl.helper.database import Base,engine
import os
import docker
import time


#TEMP
from fastapi import Depends, Request
from sqlalchemy.orm import Session
from scsctl.helper.database import get_db
from scsctl.helper.model import CreateScheduleConfig, Schedules, ScanConfigs

#TEMP

app = FastAPI(
    title="SCSCTL",
    description="SCSCTL is a tool to automate security scans for container images",
    version="0.0.1"
)

# app.include_router(schedule.router)

# scheduler = create_scheduler()
# scheduler.start()
# app.scheduler = scheduler

# Base.metadata.create_all(bind=engine)

#TODO: Fix multiple scan if scan is missed

# @app.post("/scan", include_in_schema=False)
# async def scan_api(config: ScanConfig):
#     current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
#     batch_id = f"scsctl_{current_datetime}"

#     return run_scan(batch_id=batch_id, **config.model_dump(), is_api=True)
# TODO: Need to update this probes later
@app.get("/ready", include_in_schema=False)
async def readinessProbe():
    return {"status": "ok"}


@app.get("/healthz", include_in_schema=False)
async def livenessProbe():
    # check if postgres
    return {"status": "ok"}

def run_container(image_url):
    config.load_incluster_config()
    api = client.CoreV1Api()

    container_name = "proact-rebuilded-qttest"
    namespace = "proact"

    container_manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": container_name},
        "spec": {
            "containers": [
                {"name": container_name, "image": image_url, "command": ["/bin/sleep", "infinity"]}
            ]
        }
    }

    api.create_namespaced_pod(namespace, body=container_manifest)

    # Wait for the container to be running (you might need to customize based on your container startup time)
    while True:
        pod = api.read_namespaced_pod(name=container_name, namespace=namespace)
        if pod.status.phase == "Running":
            break
        time.sleep(1)

    
if __name__ == "__main__":
    # #check environment and run uvicorn accordingly
    if os.getenv("SCSCTL_ENVIRONMENT","dev") == "prod":
        uvicorn.run("server:app", host="0.0.0.0",port=5000, log_level="info", workers=2)
    else:
        uvicorn.run("server:app", host="0.0.0.0",port=5000, log_level="debug", reload=True)

