from pydantic import BaseModel, Field

class ScanConfig(BaseModel):
    pyroscope_app_name: str
    docker_image_name: str
    pyroscope_url: str
    falco_pod_name: str = Field(default=None)
    falco_target_deployment_name: str = Field(default=None)
    docker_file_folder_path: str = Field(default=None)
    db_enabled: bool = Field(default=False)
    falco_enabled: bool = Field(default=False)
    renovate_enabled: bool = Field(default=False)
    renovate_repo_name: str = Field(default=None)
    renovate_repo_token: str = Field(default=None)
    dgraph_enabled: bool = Field(default=False)
    dgraph_db_host: str = Field(default=None)
    dgraph_db_port: str = Field(default=None)

class ScheduleScanConfig(ScanConfig):
    cron_schedule: str