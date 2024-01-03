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
from sqlalchemy.orm import Session
from scsctl.helper.database import get_db
from fastapi import Request
from scsctl.helper.model import CreateScheduleConfig
from apscheduler.schedulers.background import BackgroundScheduler
from scsctl.helper.model import ScheduleEnum
from scsctl.routers.service import create_new_schedule, delete_schedule
from scsctl.helper.model import CreateScheduleConfig, Schedules, ScanConfigs, Executions, ExecutionJobs
#Temp


app = FastAPI()

app.include_router(schedule.router)

scheduler = create_scheduler()
scheduler.start()
app.scheduler = scheduler

Base.metadata.create_all(bind=engine)

@app.post("/scan")
async def scan_api(config: ScanConfig):
    current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    batch_id = f"scsctl_{current_datetime}"

    return run_scan(batch_id=batch_id, **config.model_dump(), is_api=True)

def test(**kwargs):
    print(f'Running job on - {datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}')
    
if __name__ == "__main__":
    # uvicorn.run("server:app", host="0.0.0.0",port=5000, log_level="info", workers=2)
    uvicorn.run("server:app", host="0.0.0.0",port=5000, log_level="info", reload=True)




