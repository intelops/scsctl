from fastapi import APIRouter, Depends
from scsctl.helper.model import CreateScheduleConfig, Schedules, ScanConfigs, ScanConfig
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from fastapi import Request
from scsctl.helper.capten import get_postgres_db_url
from sqlalchemy.orm import Session
from scsctl.helper.database import get_db
from scsctl.routers.service import create_new_schedule, delete_schedule
from scsctl.helper.model import ScheduleEnum, CreateDeleteUpdateScheduleResponse, ScheduleResponse, ScheduleDetailsResponse, ExecutionResponse
from datetime import datetime


router = APIRouter(prefix="/api/v1/schedule", tags=["scsctl"])

#Rest api to create, delete, pause, resume, list jobs

def create_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_jobstore(SQLAlchemyJobStore(url=get_postgres_db_url()))
    return scheduler

@router.post("/")
async def createSchedule(request: Request, config: CreateScheduleConfig, db: Session = Depends(get_db)) -> CreateDeleteUpdateScheduleResponse:
    """
    Create a new schedule
    """
    scheduler: BackgroundScheduler = request.app.scheduler
    status, schedule_id = create_new_schedule(config, db, scheduler)
    return CreateDeleteUpdateScheduleResponse(message=status.value, schedule_id=schedule_id)

@router.delete("/{scheduleId}")
async def deleteSchedule(request: Request,scheduleId: str, db: Session = Depends(get_db)) -> CreateDeleteUpdateScheduleResponse:
    """
    Delete a schedule with the given schedule_id
    """
    scheduler: BackgroundScheduler = request.app.scheduler
    status,scheduleId = delete_schedule(scheduleId, db, scheduler)
    return CreateDeleteUpdateScheduleResponse(message=status.value, schedule_id=scheduleId)


@router.put("/{scheduleId}")
async def updateSchedule(request: Request,scheduleId: str, config: CreateScheduleConfig, db: Session = Depends(get_db)) -> CreateDeleteUpdateScheduleResponse:
    """
    Update a schedule with the given schedule_id
    """
    scheduler: BackgroundScheduler = request.app.scheduler
    #Delete schedule
    status, _ = delete_schedule(schedule_id = scheduleId, db = db, scheduler=scheduler)
    if(status != ScheduleEnum.SCHEDULE_DELETED):
        return CreateDeleteUpdateScheduleResponse(message=ScheduleEnum.SCHEDULE_UPDATE_FAILED.value, schedule_id=scheduleId)
    
    #Create schedule
    status, _ = create_new_schedule(config = config, db = db, scheduler = scheduler, schedule_id = scheduleId)
    if(status != ScheduleEnum.SCHEDULE_CREATED):
        return CreateDeleteUpdateScheduleResponse(message=ScheduleEnum.SCHEDULE_UPDATE_FAILED.value, schedule_id=scheduleId)

    return CreateDeleteUpdateScheduleResponse(message=ScheduleEnum.SCHEDULE_UPDATED.value, schedule_id=scheduleId)

@router.get("/")
async def listSchedules(request: Request, db: Session = Depends(get_db)) -> list[ScheduleResponse]:
    """
    List all schedules
    """
    #Get schedule name and schedule id from Schedules
    schedules = db.query(Schedules.schedule_name, Schedules.schedule_id).all()
    if(schedules == None):
        return []
    else:
        #Convert to list of ScheduleResponse using ** expression
        schedules = [ScheduleResponse(**schedule._asdict()) for schedule in schedules]
        return schedules
    
@router.get("/{scheduleId}", response_model_exclude_none=True)
async def getScheduleConfigs(request: Request, scheduleId: str, db: Session = Depends(get_db)) -> CreateScheduleConfig:
    """
    Get schedule details with the given schedule_id
    """
    #Get schedule details from Schedules
    try:
        schedule = db.query(Schedules.schedule_id,Schedules.schedule_name,Schedules.start_date,Schedules.end_date, Schedules.container_registry_id,Schedules.cron_schedule,Schedules.update_time).filter(Schedules.schedule_id == scheduleId).first()._asdict()

        #Get scan configs
        scan_configs = db.query(ScanConfigs.docker_image_name,ScanConfigs.pyroscope_url,ScanConfigs.pyroscope_app_name,ScanConfigs.falco_pod_name,ScanConfigs.falco_target_deployment_name, ScanConfigs.docker_file_folder_path, ScanConfigs.db_enabled, ScanConfigs.falco_enabled, ScanConfigs.renovate_enabled, ScanConfigs.renovate_repo_name, ScanConfigs.renovate_repo_token,ScanConfigs.dgraph_enabled, ScanConfigs.dgraph_db_host, ScanConfigs.dgraph_db_port).filter(ScanConfigs.schedule_id == scheduleId).all()
        scan_configs = [ScanConfig(**scan_config._asdict()) for scan_config in scan_configs]
        schedule["scan_configs"] = scan_configs

        schedule_details = CreateScheduleConfig(**schedule)
        return schedule_details.model_dump()
    except Exception as e:
        print(e)
        return CreateScheduleConfig(schedule_name="", container_registry_id="", cron_schedule="", scan_configs=[])
    
@router.get("/{scheduleId}/details")
async def getScheduleDetails(request: Request, scheduleId: str, db: Session = Depends(get_db)) -> ScheduleDetailsResponse:

    execution_response_1 = ExecutionResponse(execution_id="123", start_time=datetime.now(), end_time=datetime.now(), scan_images_count=2, vulnerable_images_count=1, vulnerablities_count=20, status="Ongoing", scan_report={})
    execution_response_2 = ExecutionResponse(execution_id="2345", start_time=datetime.now(), end_time=datetime.now(), scan_images_count=4, vulnerable_images_count=2, vulnerablities_count=0, status="Failed", scan_report={})

    schedule_details_response = ScheduleDetailsResponse(schedule_id=scheduleId, schedule_name="test", executions=[execution_response_1, execution_response_2])

    return schedule_details_response

