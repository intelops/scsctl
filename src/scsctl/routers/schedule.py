from fastapi import APIRouter
from scsctl.helper.model import Config
from crontab import CronTab

router = APIRouter(prefix="/api/schedule", tags=["scsctl"])

class ScheduleConfig(Config):
    schedule_time: str


@router.post("/create")
async def create_schedule(config: ScheduleConfig):
    #Create a cron job according to the schedule_time
    pass