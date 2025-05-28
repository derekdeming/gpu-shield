from pydantic import BaseModel, Field, validator, ConfigDict
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from enum import Enum

"""
Enums should be matching SQLAlchemy models
"""


class GPUVendor(str, Enum):
    NVIDIA = "nvidia"
    AMD = "amd"
    INTEL = "intel"


class TelemetryType(str, Enum):
    METRICS = "metrics"
    SECURITY_EVENT = "security_event"
    PERFORMANCE = "performance"
    ERROR = "error"


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    DRIVER_IOCTL = "driver_ioctl"
    DMA_BUF_MAPPING = "dma_buf_mapping"
    FIRMWARE_HASH = "firmware_hash"
    MODULE_LOAD = "module_load"
    SYSCALL = "syscall"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class NodeBase(BaseSchema):
    name: str = Field(..., description="Node name")
    cluster_id: str = Field(..., description="Kubernetes cluster ID")
    ip_address: str = Field(..., description="Node IP address")
    kubernetes_version: Optional[str] = None
    kernel_version: Optional[str] = None
    container_runtime: Optional[str] = None

class NodeCreate(NodeBase):
    spiffe_id: Optional[str] = None

class NodeUpdate(BaseSchema):
    name: Optional[str] = None
    ip_address: Optional[str] = None
    kubernetes_version: Optional[str] = None
    kernel_version: Optional[str] = None
    container_runtime: Optional[str] = None
    spiffe_id: Optional[str] = None
    attestation_status: Optional[str] = None

class NodeResponse(NodeBase):
    id: str
    spiffe_id: Optional[str] = None
    last_attestation: Optional[datetime] = None
    attestation_status: str = "pending"
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_seen: datetime

class GPUBase(BaseSchema):
    vendor: GPUVendor
    model: str
    device_id: str
    uuid: Optional[str] = None
    memory_total: Optional[int] = Field(None, description="Total GPU memory in MB")
    compute_capability: Optional[str] = None
    driver_version: Optional[str] = None
    firmware_version: Optional[str] = None

class GPUCreate(GPUBase):
    node_id: str

class GPUUpdate(BaseSchema):
    model: Optional[str] = None
    driver_version: Optional[str] = None
    firmware_version: Optional[str] = None
    is_active: Optional[bool] = None
    temperature: Optional[float] = None
    power_usage: Optional[float] = None

class GPUResponse(GPUBase):
    id: str
    node_id: str
    is_active: bool = True
    temperature: Optional[float] = None
    power_usage: Optional[float] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

class SensorBase(BaseSchema):
    sensor_type: str = Field(..., description="Sensor type (dcgm, rocm, ebpf, etc.)")
    version: str = Field(..., description="Sensor version")
    config: Optional[Dict[str, Any]] = None

class SensorCreate(SensorBase):
    node_id: str

class SensorUpdate(BaseSchema):
    version: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None

class SensorResponse(SensorBase):
    id: str
    node_id: str
    is_active: bool = True
    last_heartbeat: datetime
    samples_collected: int = 0
    errors_count: int = 0
    created_at: datetime
    updated_at: Optional[datetime] = None

class TelemetryRecordBase(BaseSchema):
    telemetry_type: TelemetryType
    timestamp: datetime
    metrics: Dict[str, Any] = Field(..., description="GPU metrics data")
    metadata: Optional[Dict[str, Any]] = None

class TelemetryRecordCreate(TelemetryRecordBase):
    gpu_id: str
    sensor_id: str

class TelemetryRecordUpdate(BaseSchema):
    processed: Optional[bool] = None
    anomaly_score: Optional[float] = Field(None, ge=0.0, le=1.0)

class TelemetryRecordResponse(TelemetryRecordBase):
    id: str
    gpu_id: str
    sensor_id: str
    processed: bool = False
    anomaly_score: Optional[float] = None
    created_at: datetime

class OTLPTelemetryBatch(BaseSchema):
    """Schema for OTLP telemetry batch from OpenTelemetry collector"""

    resource_metrics: List[Dict[str, Any]]
    @validator("resource_metrics")
    def validate_metrics(cls, v):
        if not v:
            raise ValueError("At least one metric required")
        return v

class SecurityEventBase(BaseSchema):
    event_type: EventType
    timestamp: datetime
    pid: Optional[int] = None
    comm: Optional[str] = Field(None, max_length=16)
    uid: Optional[int] = None
    gid: Optional[int] = None
    syscall_nr: Optional[int] = None
    ioctl_cmd: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = Field(None, regex=r"^[a-fA-F0-9]{64}$")
    details: Optional[Dict[str, Any]] = None

class SecurityEventCreate(SecurityEventBase):
    node_id: str
    risk_score: Optional[float] = Field(None, ge=0.0, le=1.0)

class SecurityEventResponse(SecurityEventBase):
    id: str
    node_id: str
    risk_score: Optional[float] = None
    created_at: datetime

class AlertBase(BaseSchema):
    title: str = Field(..., max_length=255)
    description: Optional[str] = None
    severity: AlertSeverity
    rule_id: Optional[str] = None
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)

class AlertCreate(AlertBase):
    node_id: str
    security_event_ids: Optional[List[str]] = None
    telemetry_record_ids: Optional[List[str]] = None
    first_seen: datetime
    last_seen: datetime

class AlertUpdate(BaseSchema):
    title: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    severity: Optional[AlertSeverity] = None
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    last_seen: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    response_actions: Optional[List[Dict[str, Any]]] = None
    notes: Optional[str] = None

class AlertResponse(AlertBase):
    id: str
    node_id: str
    security_event_ids: Optional[List[str]] = None
    telemetry_record_ids: Optional[List[str]] = None
    status: str = "open"
    assigned_to: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    resolved_at: Optional[datetime] = None
    response_actions: Optional[List[Dict[str, Any]]] = None
    notes: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

class AuditLogCreate(BaseSchema):
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    operation: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    request_data: Optional[Dict[str, Any]] = None
    response_status: Optional[int] = None
    duration_ms: Optional[int] = None

class AuditLogResponse(AuditLogCreate):
    id: str
    timestamp: datetime

class SensorHeartbeat(BaseSchema):
    sensor_id: str
    timestamp: datetime
    status: str = "healthy"
    metrics: Optional[Dict[str, Any]] = None
    errors: Optional[List[str]] = None

class TelemetryBulkCreate(BaseSchema):
    records: List[TelemetryRecordCreate] = Field(..., min_items=1, max_items=1000)

class SecurityEventBulkCreate(BaseSchema):
    events: List[SecurityEventCreate] = Field(..., min_items=1, max_items=1000)

class TimeRange(BaseSchema):
    start: datetime
    end: datetime

class TelemetryQuery(BaseSchema):
    gpu_ids: Optional[List[str]] = None
    sensor_ids: Optional[List[str]] = None
    telemetry_types: Optional[List[TelemetryType]] = None
    time_range: Optional[TimeRange] = None
    processed: Optional[bool] = None
    min_anomaly_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    limit: int = Field(100, ge=1, le=10000)
    offset: int = Field(0, ge=0)

class AlertQuery(BaseSchema):
    node_ids: Optional[List[str]] = None
    severities: Optional[List[AlertSeverity]] = None
    statuses: Optional[List[str]] = None
    time_range: Optional[TimeRange] = None
    assigned_to: Optional[str] = None
    limit: int = Field(100, ge=1, le=1000)
    offset: int = Field(0, ge=0)

class SecurityEventQuery(BaseSchema):
    node_ids: Optional[List[str]] = None
    event_types: Optional[List[EventType]] = None
    time_range: Optional[TimeRange] = None
    min_risk_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    pids: Optional[List[int]] = None
    limit: int = Field(100, ge=1, le=10000)
    offset: int = Field(0, ge=0)

class PaginatedResponse(BaseSchema):
    items: List[Any]
    total: int
    offset: int
    limit: int
    has_more: bool

class HealthCheckResponse(BaseSchema):
    status: str
    database: str
    spire: str
    timestamp: datetime

class MetricsResponse(BaseSchema):
    """Response for metrics/statistics endpoints"""

    nodes_count: int
    gpus_count: int
    active_sensors: int
    alerts_open: int
    alerts_critical: int
    telemetry_records_24h: int
    security_events_24h: int