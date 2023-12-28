import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
# from scsctl.helper.sqlite import get_cursor
from scsctl.helper.model import Config
from scsctl.routers import schedule
from scsctl.helper.scan import run_scan
    
class TestConfig(BaseModel):
    query: str

app = FastAPI()

app.include_router(schedule.router)


@app.get("/")
async def root():
    return {"message": "Hello World"}

# @app.get("/test")
# async def test_api(config: TestConfig):
#     # Run query on sqlite db and return the result
#     cursor, conn = get_cursor()
#     cursor.execute(config.query)

#     #Get all rows as a json
#     obj = cursor.fetchall()
#     obj = [dict(zip([key[0] for key in cursor.description], row)) for row in obj]
#     conn.close()
#     return obj



@app.post("/scan")
async def scan_api(config: Config):
    current_datetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    batch_id = f"scsctl_{current_datetime}"

    return run_scan(batch_id=batch_id, pyroscope_app_name=config.pyroscope_app_name, docker_image_name=config.docker_image_name, pyroscope_url=config.pyroscope_url, dgraph_enabled=config.dgraph_enabled, dgraph_db_host=config.dgraph_db_host, dgraph_db_port=config.dgraph_db_port,renovate_enabled=config.renovate_enabled, falco_enabled=config.falco_enabled,falco_pod_name=config.falco_pod_name,falco_target_deployment_name=config.falco_target_deployment_name, db_enabled=config.db_enabled, renovate_repo_token=config.renovate_repo_token, renovate_repo_name=config.renovate_repo_name)

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0",port=5000, log_level="info", reload=True)