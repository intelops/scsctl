from fastapi import APIRouter, Depends
from scsctl.helper.model import CreateScanConfig, DeleteScanConfig, PauseScanConfig, ResumeScanConfig, Schedules, ScanConfigs, Executions, ExecutionJobs
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from scsctl.helper.scan import run_scan
from apscheduler.triggers.cron import CronTrigger
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from fastapi import Request
from scsctl.helper.capten import get_postgres_db_url
from uuid import uuid4
from sqlalchemy.orm import Session
from scsctl.helper.database import get_db


router = APIRouter(prefix="/api/v1/schedule", tags=["scsctl"])

#Rest api to create, delete, pause, resume, list jobs

def create_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_jobstore(SQLAlchemyJobStore(url=get_postgres_db_url()))
    return scheduler

@router.post("/")
async def createTask(request: Request, config: CreateScanConfig, db: Session = Depends(get_db)):    
    scheduler: BackgroundScheduler = request.app.scheduler

    schedules = config.model_dump()
    scan_configs = schedules.pop("scan_configs")

    #Create a schedule
    new_schedule = Schedules(**schedules)
    db.add(new_schedule)
    db.commit()
    db.refresh(new_schedule)
    #Get the schedule id
    schedule_id = new_schedule.schedule_id

    #Create executions
    new_execution = Executions(schedule_id=schedule_id)
    db.add(new_execution)
    db.commit()
    db.refresh(new_execution)
    execution_id = new_execution.execution_id


    #Add scan configs
    for scan_config in scan_configs:
        scan_config["schedule_id"] = schedule_id
        db.add(ScanConfigs(**scan_config))
        db.commit()

        # Add job to scheduler
        current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        batch_id = f"scsctl_{current_datetime}"
        job_id = str(uuid4())
        kwargs = {
            "batch_id": batch_id,
            "job_id": job_id,
            "is_scheduled": True,
            **scan_config
        }
        job = scheduler.add_job(run_scan, CronTrigger.from_crontab(config.cron_schedule), id=job_id,kwargs=kwargs, coalesce=True)

        #Add job to execution_jobs
        db.add(ExecutionJobs(execution_id=execution_id, job_id=job_id))
        db.commit()


    return {"message": "Schedule Created", "schedule_id": schedule_id}

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