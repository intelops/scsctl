from pydantic import BaseModel, Field
from scsctl.helper.database import Base
from sqlalchemy import Column, Integer, String, DateTime, PrimaryKeyConstraint, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime

class ScanConfig(BaseModel):
    docker_image_name: str
    pyroscope_url: str = Field(default=None)
    pyroscope_app_name: str = Field(default=None)
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

class CreateScanConfig(BaseModel):
    schedule_name: str
    container_registry_id: str
    cron_schedule: str
    start_date: datetime = Field(default=None)
    end_date: datetime = Field(default=None)
    scan_configs: list[ScanConfig]

class DeleteScanConfig(BaseModel):
    job_id: str

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
    status = Column(Boolean, default=False)
    datetime = Column(DateTime, default=datetime.utcnow)