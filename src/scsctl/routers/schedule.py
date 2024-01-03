from fastapi import APIRouter, Depends
from scsctl.helper.model import CreateScheduleConfig, Schedules, ScanConfigs, Executions, ExecutionJobs
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from fastapi import Request
from scsctl.helper.capten import get_postgres_db_url
from sqlalchemy.orm import Session
from scsctl.helper.database import get_db
from scsctl.routers.service import create_new_schedule, delete_schedule
from scsctl.helper.model import ScheduleEnum


router = APIRouter(prefix="/api/v1/schedule", tags=["scsctl"])

#Rest api to create, delete, pause, resume, list jobs

def create_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_jobstore(SQLAlchemyJobStore(url=get_postgres_db_url()))
    return scheduler

@router.post("/")
async def createSchedule(request: Request, config: CreateScheduleConfig, db: Session = Depends(get_db)):    
    scheduler: BackgroundScheduler = request.app.scheduler
    status, schedule_id = create_new_schedule(config, db, scheduler)
    return {"message": status.value, "schedule_id": schedule_id}

@router.delete("/{schedule_id}")
async def deleteSchedule(request: Request,schedule_id: str, db: Session = Depends(get_db)):
    scheduler: BackgroundScheduler = request.app.scheduler
    status,schedule_id = delete_schedule(schedule_id, db, scheduler)
    return {"message": status.value, "schedule_id": schedule_id}


@router.put("/{schedule_id}")
async def updateSchedule(request: Request,schedule_id: str, config: CreateScheduleConfig, db: Session = Depends(get_db)):
    scheduler: BackgroundScheduler = request.app.scheduler

    #Delete schedule
    status, _ = delete_schedule(schedule_id = schedule_id, db = db, scheduler=scheduler)
    if(status != ScheduleEnum.SCHEDULE_DELETED):
        return {"message": status.value, "schedule_id": schedule_id}
    
    #Create schedule
    status, _ = create_new_schedule(config = config, db = db, scheduler = scheduler, schedule_id = schedule_id)
    if(status != ScheduleEnum.SCHEDULE_CREATED):
        return {"message": status.value, "schedule_id": schedule_id}

    return {"message": "Schedule Updated", "schedule_id": schedule_id}