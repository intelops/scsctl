
from uuid import uuid4
from sqlalchemy.orm import Session
from scsctl.helper.model import CreateScheduleConfig, Schedules, ScanConfigs, Executions, ExecutionJobs, ScanStatus
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from scsctl.helper.model import ScheduleEnum
from datetime import datetime
from scsctl.helper.scan import run_scan

def create_new_schedule(config: CreateScheduleConfig, db: Session, scheduler: BackgroundScheduler, schedule_id: str = None) -> tuple[ScheduleEnum, str]:
    #TODO: Make the db commits atomic, if any of the db commit fails then rollback all the db commits
    try:
        schedules = config.model_dump()
        scan_configs = schedules.pop("scan_configs")

        #During update schedule_id will be passed to keep the schedule id same even if we are creating a new schedule
        if(schedule_id):
            schedules["schedule_id"] = schedule_id

        #Create a schedule
        new_schedule = Schedules(**schedules)
        db.add(new_schedule)
        db.commit()
        db.refresh(new_schedule)
        #Get the schedule id
        schedule_id = new_schedule.schedule_id

        #Create executions
        new_execution = Executions(schedule_id=schedule_id, scan_images_count=len(scan_configs))
        db.add(new_execution)
        db.commit()
        db.refresh(new_execution)
        execution_id = new_execution.execution_id


        #Add scan configs
        for scan_config in scan_configs:
            job_id = str(uuid4())
            scan_config["schedule_id"] = schedule_id
            scan_config["job_id"] = job_id
            db.add(ScanConfigs(**scan_config))
            # db.commit()

            # Add job to scheduler
            kwargs = {
                "job_id": job_id,
                "is_api": True,
                "execution_id": execution_id,
                **scan_config
            }
            job = scheduler.add_job(run_scan, CronTrigger.from_crontab(config.cron_schedule), id=job_id,kwargs=kwargs, coalesce=True, max_instances=1)

            #Add job to execution_jobs
            db.add(ExecutionJobs(execution_id=execution_id, job_id=job_id))
        db.commit()
        return ScheduleEnum.SCHEDULE_CREATED, schedule_id
    except Exception as e:
        print(e)
        return ScheduleEnum.SCHEDULE_CREATION_FAILED, schedule_id


def delete_schedule(schedule_id: str, db: Session, scheduler: BackgroundScheduler) -> tuple[ScheduleEnum, str]:
    try:
        #Get execution_id
        #Check if schedule exists if not return error
        if(not db.query(Schedules).filter(Schedules.schedule_id == schedule_id).first()):
            return ScheduleEnum.SCHEDULE_NOT_FOUND, schedule_id
        execution_id = db.query(Executions).filter(Executions.schedule_id == schedule_id).first().execution_id
        #Delete execution_jobs
        execution_jobs = db.query(ExecutionJobs).filter(ExecutionJobs.execution_id == execution_id).all()
        for execution_job in execution_jobs:
            scheduler.remove_job(str(execution_job.job_id))
        db.query(ExecutionJobs).filter(ExecutionJobs.execution_id == execution_id).delete()
        # db.commit()

        #Delete scan configs
        db.query(ScanConfigs).filter(ScanConfigs.schedule_id == schedule_id).delete()
        # db.commit()


        #Delete scan status
        db.query(ScanStatus).filter(ScanStatus.execution_id == execution_id).delete()
        # db.commit()

        #Delete execution
        db.query(Executions).filter(Executions.schedule_id == schedule_id).delete()
        # db.commit()

        #Delete schedule
        db.query(Schedules).filter(Schedules.schedule_id == schedule_id).delete()
        db.commit()

        return ScheduleEnum.SCHEDULE_DELETED, schedule_id
    except Exception as e:
        print(e)
        return ScheduleEnum.SCHEDULE_DELETE_FAILED, schedule_id