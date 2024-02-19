import uvicorn
from fastapi import FastAPI
from datetime import datetime
# from helper.model import ScanConfig
from routers import schedule
from helper.scan import run_scan
import os


app = FastAPI(
    title="SCSCTL",
    description="SCSCTL is a tool to automate security scans for container images",
    version="0.0.1"
)

#TODO: Fix multiple scan if scan is missed

@app.post("/scan", include_in_schema=True)
async def scan_api(config: dict):
    current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    batch_id = f"scsctl_{current_datetime}"

    return run_scan(**config, is_api=True)
# TODO: Need to update this probes later
@app.get("/ready", include_in_schema=False)
async def readinessProbe():
    return {"status": "ok"}


@app.get("/healthz", include_in_schema=False)
async def livenessProbe():
    # check if postgres
    return {"status": "ok"}


    
if __name__ == "__main__":
    # #check environment and run uvicorn accordingly
    if os.getenv("SCSCTL_ENVIRONMENT","dev") == "prod":
        uvicorn.run("server:app", host="0.0.0.0",port=5000, log_level="info", workers=2)
    else:
        uvicorn.run("server:app", host="0.0.0.0",port=5000, log_level="debug", reload=True)

