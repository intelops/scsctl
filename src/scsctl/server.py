import uvicorn
from fastapi import FastAPI
from datetime import datetime
from scsctl.helper.model import  ScanConfig
from scsctl.routers import schedule
from scsctl.helper.scan import run_scan
from scsctl.routers.schedule import create_scheduler

app = FastAPI()

app.include_router(schedule.router)

@app.on_event('startup')
def init_data():
    scheduler = create_scheduler()
    scheduler.start()
    app.scheduler = scheduler

@app.post("/scan")
async def scan_api(config: ScanConfig):
    current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    batch_id = f"scsctl_{current_datetime}"

    return run_scan(batch_id=batch_id, **config.model_dump())

def test(**kwargs):
    print(f'Running job on - {datetime.now().strftime("%Y_%m_%d_%H_%M_%S")}')
    
if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0",port=5000, log_level="info", workers=2)




