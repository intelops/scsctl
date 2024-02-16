import uvicorn
from fastapi import FastAPI
from datetime import datetime
from scsctl.helper.model import ScanConfig
from scsctl.routers import schedule
from scsctl.helper.scan import run_scan
# from scsctl.routers.schedule import create_scheduler
from scsctl.helper.database import Base,engine
import os


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

Base.metadata.create_all(bind=engine)

#TODO: Fix multiple scan if scan is missed

@app.post("/scan", include_in_schema=False)
async def scan_api(config: ScanConfig):
    current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    batch_id = f"scsctl_{current_datetime}"

    return run_scan(batch_id=batch_id, **config.model_dump(), is_api=True)

    
if __name__ == "__main__":
    # #check environment and run uvicorn accordingly
    if os.getenv("SCSCTL_ENVIRONMENT","dev") == "prod":
        uvicorn.run("server:app", host="0.0.0.0",port=5000, log_level="info", workers=2)
    else:
        uvicorn.run("server:app", host="0.0.0.0",port=5000, log_level="debug", reload=True)

