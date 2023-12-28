from fastapi import APIRouter
from scsctl.helper.model import ScheduleScanConfig
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from scsctl.helper.scan import run_scan
from apscheduler.triggers.cron import CronTrigger

router = APIRouter(prefix="/api/schedule", tags=["scsctl"])


@router.post("/create")
async def createTask(config: ScheduleScanConfig):    
    current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    batch_id = f"scsctl_{current_datetime}"

    print(f"\nRunning Scan - {batch_id}\n")

    scheduler = BackgroundScheduler()

    kwargs = {
        "batch_id": batch_id,
        **config.model_dump()
    }
    #remove cron_schedule from kwargs
    cron_schedule = kwargs["cron_schedule"]
    del kwargs["cron_schedule"]

    job = scheduler.add_job(run_scan, CronTrigger.from_crontab(cron_schedule), kwargs=kwargs)
    scheduler.start()
    return {"message": "Task Created", "job_id": job.id}