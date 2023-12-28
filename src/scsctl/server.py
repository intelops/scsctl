import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
# from scsctl.helper.sqlite import get_cursor
from scsctl.helper.model import ScanConfig
from scsctl.routers import schedule
from scsctl.helper.scan import run_scan
    
class TestConfig(BaseModel):
    query: str

app = FastAPI()

app.include_router(schedule.router)


@app.post("/scan")
async def scan_api(config: ScanConfig):
    current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    batch_id = f"scsctl_{current_datetime}"

    return run_scan(batch_id=batch_id, **config.model_dump())
    
if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0",port=5000, log_level="info", reload=True)