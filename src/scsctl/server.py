import uvicorn
from fastapi import FastAPI
from datetime import datetime
from scsctl.helper.model import  ScanConfig
from scsctl.routers import schedule
from scsctl.helper.scan import run_scan
from scsctl.routers.schedule import create_scheduler
from scsctl.helper.database import Base,engine



#Temp
from fastapi import Depends
from scsctl.helper.capten import get_postgres_db_url
from uuid import uuid4
from sqlalchemy.orm import Session
from scsctl.helper.database import get_db
from fastapi import Request
from scsctl.helper.model import CreateScanConfig, Schedules, ScanConfigs, Executions, ExecutionJobs
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
#Temp


app = FastAPI()

app.include_router(schedule.router)

scheduler = create_scheduler()
scheduler.start()
app.scheduler = scheduler

Base.metadata.create_all(bind=engine)

# @app.on_event('startup')
# def init_data():
#     scheduler = create_scheduler()
#     scheduler.start()
#     app.scheduler = scheduler

@app.post("/create")
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
            **scan_config
        }
        job = scheduler.add_job(run_scan, CronTrigger.from_crontab(config.cron_schedule), id=job_id,kwargs=kwargs)

        #Add job to execution_jobs
        db.add(ExecutionJobs(execution_id=execution_id, job_id=job_id))
        db.commit()


    return {"message": "Schedule Created", "schedule_id": schedule_id}

@app.post("/scan")
async def scan_api(config: ScanConfig):
    current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    batch_id = f"scsctl_{current_datetime}"

    return run_scan(batch_id=batch_id, **config.model_dump())

def test(**kwargs):
    print(f'Running job on - {datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}')
    
if __name__ == "__main__":
    # uvicorn.run("server:app", host="0.0.0.0",port=5000, log_level="info", workers=2)
    uvicorn.run("server:app", host="0.0.0.0",port=5000, log_level="info", reload=True)




