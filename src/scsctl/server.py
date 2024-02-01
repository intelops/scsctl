import os
from datetime import datetime

import uvicorn
from fastapi import Depends
from fastapi import FastAPI
from fastapi import Request
from scsctl.helper.database import Base
from scsctl.helper.database import engine
from scsctl.helper.database import get_db
from scsctl.helper.model import CreateScheduleConfig
from scsctl.helper.model import ScanConfig
from scsctl.helper.model import ScanConfigs
from scsctl.helper.model import Schedules
from scsctl.helper.scan import run_scan
from scsctl.routers import schedule
from scsctl.routers.schedule import create_scheduler
from sqlalchemy.orm import Session
import json


import logging

logger = logging.getLogger(__name__)
# TEMP

# TEMP

app = FastAPI(
    title="SCSCTL",
    description="SCSCTL is a tool to automate security scans for container images",
    version="0.0.1",
)

# app.include_router(schedule.router)

# scheduler = create_scheduler()
# scheduler.start()
# app.scheduler = scheduler

# Base.metadata.create_all(bind=engine)

# TODO: Fix multiple scan if scan is missed


@app.post("/scan", include_in_schema=False)
async def scan_api(config: ScanConfig):
    current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    batch_id = f"scsctl_{current_datetime}"
    result = run_scan(batch_id=batch_id, **config.model_dump(), is_api=True)

    logger.info({
                "sbom_report": result.get("sbom_report"),
                "pyroscope_data" :result.get("pyroscope_data"),
                "final_report" : result.get("final_report"),
                "pyroscope_found_extra_packages": result.get("pyroscope_found_extra_packages"),
                "stats" : result.get("stats")
            }, extra={"type": "report"})

    return result


# TODO: Need to update this probes later
@app.get("/ready", include_in_schema=False)
async def readinessProbe():
    return {"status": "ok"}


@app.get("/healthz", include_in_schema=False)
async def livenessProbe():
    # check if postgres
    return {"status": "ok"}


if __name__ == "__main__":
    log_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            },
            "access": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            }
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr"
            },
            "access": {
                "formatter": "access",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout"
            }
        },
        "loggers": {
            "uvicorn.error": {
                "level": "INFO",
                "handlers": ["default"],
                "propagate": False
            },
            "uvicorn.access": {
                "level": "INFO",
                "handlers": ["access"],
                "propagate": False
            }
        },
        "root": {
            "level": "DEBUG",
            "handlers": ["default"],
            "propagate": False
        }
    }    
    #check environment and run uvicorn accordingly
    if os.getenv("SCSCTL_ENVIRONMENT", "dev") == "prod":
        uvicorn.run(
            "server:app",
            host="0.0.0.0",
            port=5000,
            log_config=log_config,
            # log_level="info",
            workers=2,
        )
    else:
        uvicorn.run(
            "server:app",
            host="0.0.0.0",
            port=5000,
            log_config=log_config,
            # log_level="debug",
            reload=True,
        )
