from pydantic import BaseModel, Field, validator
from scsctl.helper.database import Base
from sqlalchemy import Column, Integer, String, DateTime, PrimaryKeyConstraint, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

class ScanConfig(BaseModel):
    docker_image_name: str
    pyroscope_url: Optional[str] = Field(default=None)
    pyroscope_app_name: Optional[str] = Field(default=None)
    falco_pod_name: Optional[str] = Field(default=None)
    falco_target_deployment_name: Optional[str] = Field(default=None)
    docker_file_folder_path: Optional[str] = Field(default=None)
    db_enabled: Optional[bool] = Field(default=False)
    falco_enabled: Optional[bool] = Field(default=False)
    renovate_enabled: Optional[bool] = Field(default=False)
    renovate_repo_name: Optional[str] = Field(default=None)
    renovate_repo_token: Optional[str] = Field(default=None)
    dgraph_enabled: Optional[bool] = Field(default=False)
    dgraph_db_host: Optional[str] = Field(default=None)
    dgraph_db_port: Optional[str] = Field(default=None)
    pyroscope_enabled: Optional[bool] = Field(default=False)

class CreateScheduleConfig(BaseModel):
    schedule_name: str
    container_registry_id: str
    cron_schedule: str
    start_date: Optional[datetime] = Field(default=None)
    end_date: Optional[datetime] = Field(default=None)
    scan_configs: list[ScanConfig]

class DeleteScheduleConfig(BaseModel):
    schedule_id: str

class PauseScanConfig(BaseModel):
    job_id: str

class ResumeScanConfig(BaseModel):
    job_id: str

class Schedules(Base):
    __tablename__ = 'schedules'
    schedule_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    schedule_name = Column(String)
    start_date = Column(DateTime, nullable=True)
    end_date = Column(DateTime, nullable=True)
    container_registry_id = Column(String)
    cron_schedule = Column(String)
    update_time = Column(DateTime, default=datetime.utcnow)

class ScanConfigs(Base):
    __tablename__ = 'scan_configs'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    schedule_id = Column(UUID(as_uuid=True), ForeignKey('schedules.schedule_id'), nullable=False)
    job_id = Column(UUID(as_uuid=True))
    docker_image_name = Column(String, nullable=False)
    pyroscope_url = Column(String, nullable=True)
    pyroscope_app_name = Column(String, nullable=True)
    falco_pod_name = Column(String, nullable=True)
    falco_target_deployment_name = Column(String, nullable=True)
    docker_file_folder_path = Column(String, nullable=True)
    db_enabled = Column(Boolean, default=False)
    falco_enabled = Column(Boolean, default=False)
    renovate_enabled = Column(Boolean, default=False)
    renovate_repo_name = Column(String, nullable=True)
    renovate_repo_token = Column(String, nullable=True)
    dgraph_enabled = Column(Boolean, default=False)
    dgraph_db_host = Column(String, nullable=True)
    dgraph_db_port = Column(String, nullable=True)
    is_api = Column(Boolean, default=False)

class Executions(Base):
    __tablename__ = 'executions'
    execution_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    schedule_id = Column(UUID(as_uuid=True), ForeignKey('schedules.schedule_id'), nullable=False)
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    scan_images_count = Column(Integer, nullable=True)
    vulnerable_images_count = Column(Integer, nullable=True)
    vulnerablities_count = Column(Integer, nullable=True)
    status = Column(String, nullable=True)
    scan_report = Column(String, nullable=True)

class ExecutionJobs(Base):
    __tablename__ = 'execution_jobs'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    execution_id = Column(UUID(as_uuid=True), ForeignKey('executions.execution_id'), nullable=False)
    job_id = Column(UUID(as_uuid=True), nullable=False)
    
class ScanStatus(Base):
    __tablename__ = 'scan_status'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True))
    execution_id = Column(UUID(as_uuid=True), ForeignKey('executions.execution_id'), nullable=False)
    batch_id = Column(String, unique=True)
    run_type = Column(String)
    vulnerable_packages_count = Column(Integer, default=0)
    vulnerablitites_count = Column(Integer, default=0)
    severity_high_count = Column(Integer, default=0)
    severity_medium_count = Column(Integer, default=0)
    severity_low_count = Column(Integer, default=0)
    severity_critical_count = Column(Integer, default=0)
    severity_unknown_count = Column(Integer, default=0)
    status = Column(Boolean, default=False)
    datetime = Column(DateTime, default=datetime.utcnow)


class ScheduleEnum(Enum):
    SCHEDULE_CREATED = "Schedule Created"
    SCHEDULE_UPDATED = "Schedule Updated"
    SCHEDULE_PAUSED = "Schedule Paused"
    SCHEDULE_RESUMED = "Schedule Resumed"
    SCHEDULE_DELETED = "Schedule Deleted"
    SCHEDULE_CREATION_FAILED = "Error creating schedule"
    SCHEDULE_UPDATE_FAILED = "Error updating schedule"
    SCHEDULE_PAUSE_FAILED = "Error pausing schedule"
    SCHEDULE_RESUME_FAILED = "Error resuming schedule"
    SCHEDULE_DELETE_FAILED = "Error deleting schedule"
    SCHEDULE_NOT_FOUND = "Schedule not found"

class CreateDeleteUpdateScheduleResponse(BaseModel):
    message: str
    schedule_id: str

    @validator('*', pre=True, always=True)
    def convert_to_string(cls, v):
        return str(v)
    
class ScheduleResponse(BaseModel):
    
    @validator('*', pre=True, always=True)
    def convert_to_string(cls, v):
        return str(v)
    
    schedule_id: str
    schedule_name: str


class ExecutionResponse(BaseModel):
    execution_id: str
    start_time: datetime
    end_time: datetime
    scan_images_count: int
    vulnerable_images_count: int
    vulnerablities_count: int
    status: str
    scan_report: dict

class ScheduleDetailsResponse(BaseModel):
    schedule_id: str
    schedule_name: str
    executions: list[ExecutionResponse]

class Stats(BaseModel):
    vulnerable_packages_count: int = Field(default=0)
    vulnerablitites_count: int = Field(default=0)
    severity_critical_count: int = Field(default=0)
    severity_high_count: int = Field(default=0)
    severity_medium_count: int = Field(default=0)
    severity_low_count: int = Field(default=0)
    severity_unknown_count: int = Field(default=0)