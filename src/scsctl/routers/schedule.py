from fastapi import APIRouter
from scsctl.helper.model import CreateScanConfig, DeleteScanConfig, PauseScanConfig, ResumeScanConfig
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from scsctl.helper.scan import run_scan
from apscheduler.triggers.cron import CronTrigger
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from fastapi import Request
from scsctl.helper.capten import get_postgres_db_url


router = APIRouter(prefix="/api/schedule", tags=["scsctl"])

def create_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_jobstore(SQLAlchemyJobStore(url=get_postgres_db_url()))
    return scheduler

def test(**kwargs):
    print(f'Running job on - {datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}')

@router.post("/create")
async def createTask(request: Request, config: CreateScanConfig):    
    current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    batch_id = f"scsctl_{current_datetime}"

    scheduler: BackgroundScheduler = request.app.scheduler

    kwargs = {
        "batch_id": batch_id,
        **config.model_dump()
    }
    #remove cron_schedule from kwargs
    cron_schedule = kwargs["cron_schedule"]
    del kwargs["cron_schedule"]

    job = scheduler.add_job(run_scan, CronTrigger.from_crontab(cron_schedule), kwargs=kwargs)
    return {"message": "Task Created", "job_id": job.id}

@router.post("/delete")
async def deleteTask(request: Request, config: DeleteScanConfig):
    scheduler: BackgroundScheduler = request.app.scheduler
    job = scheduler.get_job(config.job_id)
    job.remove()
    return {"message": "Task Deleted", "job_id": config.job_id}

@router.post("/pause")
async def pauseTask(request: Request, config: PauseScanConfig):
    scheduler: BackgroundScheduler = request.app.scheduler
    job = scheduler.get_job(config.job_id)
    job.pause()
    return {"message": "Task Paused", "job_id": config.job_id}

@router.post("/resume")
async def resumeTask(request: Request, config: ResumeScanConfig):
    scheduler: BackgroundScheduler = request.app.scheduler
    job = scheduler.get_job(config.job_id)
    job.resume()
    return {"message": "Task Resumed", "job_id": config.job_id}

@router.get("/list")
async def list_jobs(request: Request):
    scheduler: BackgroundScheduler = request.app.scheduler
    jobs = scheduler.get_jobs()
    #Return list of jobs with id, name, next_run_time
    return list(map(lambda job: {"id": job.id, "name": job.name, "next_run_time": job.next_run_time}, jobs))