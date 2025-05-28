from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    Boolean,
    Text,
    JSON,
    ForeignKey,
    Enum,
    Index,
    UniqueConstraint,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
import enum
from uuid import uuid4

Base = declarative_base()


class GPUVendor(enum.Enum):
    NVIDIA = "nvidia"
    AMD = "amd"
    INTEL = "intel"


class TelemetryType(enum.Enum):
    METRICS = "metrics"
    SECURITY_EVENT = "security_event"
    PERFORMANCE = "performance"
    ERROR = "error"


class AlertSeverity(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(enum.Enum):
    DRIVER_IOCTL = "driver_ioctl"
    DMA_BUF_MAPPING = "dma_buf_mapping"
    FIRMWARE_HASH = "firmware_hash"
    MODULE_LOAD = "module_load"
    SYSCALL = "syscall"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"


class Node(Base):
    """Kubernetes node with GPU resources"""

    __tablename__ = "nodes"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    name = Column(String(255), nullable=False, unique=True)
    cluster_id = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=False)  # IPv4/IPv6

    # Node metadata
    kubernetes_version = Column(String(50))
    kernel_version = Column(String(100))
    container_runtime = Column(String(50))

    # SPIRE identity
    spiffe_id = Column(String(500), unique=True)
    last_attestation = Column(DateTime(timezone=True))
    attestation_status = Column(String(20), default="pending")

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    sensors = relationship(
        "Sensor", back_populates="node", cascade="all, delete-orphan"
    )
    gpus = relationship("GPU", back_populates="node", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_node_cluster", "cluster_id"),
        Index("idx_node_spiffe", "spiffe_id"),
    )


class GPU(Base):
    """GPU device information"""

    __tablename__ = "gpus"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    node_id = Column(String, ForeignKey("nodes.id"), nullable=False)

    # GPU identification
    vendor = Column(Enum(GPUVendor), nullable=False)
    model = Column(String(100), nullable=False)
    device_id = Column(String(50), nullable=False)  # PCI device ID
    uuid = Column(String(100), unique=True)  # GPU UUID

    # Hardware specs
    memory_total = Column(Integer)  # MB
    compute_capability = Column(String(10))  # e.g., "8.0" for A100

    # Driver/firmware
    driver_version = Column(String(50))
    firmware_version = Column(String(50))

    # Status
    is_active = Column(Boolean, default=True)
    temperature = Column(Float)  # Celsius
    power_usage = Column(Float)  # Watts

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    node = relationship("Node", back_populates="gpus")
    telemetry_records = relationship("TelemetryRecord", back_populates="gpu")

    __table_args__ = (
        Index("idx_gpu_node", "node_id"),
        Index("idx_gpu_vendor", "vendor"),
        UniqueConstraint("node_id", "device_id", name="uq_gpu_node_device"),
    )


class Sensor(Base):
    """Telemetry sensor instance"""

    __tablename__ = "sensors"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    node_id = Column(String, ForeignKey("nodes.id"), nullable=False)

    # Sensor metadata
    sensor_type = Column(String(50), nullable=False)  # dcgm, rocm, ebpf, etc.
    version = Column(String(50), nullable=False)
    config = Column(JSON)  # Sensor-specific configuration

    # Status
    is_active = Column(Boolean, default=True)
    last_heartbeat = Column(DateTime(timezone=True), server_default=func.now())

    # Collection metrics
    samples_collected = Column(Integer, default=0)
    errors_count = Column(Integer, default=0)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    node = relationship("Node", back_populates="sensors")

    __table_args__ = (
        Index("idx_sensor_node", "node_id"),
        Index("idx_sensor_type", "sensor_type"),
    )


class TelemetryRecord(Base):
    """Raw telemetry data from sensors"""

    __tablename__ = "telemetry_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    gpu_id = Column(String, ForeignKey("gpus.id"), nullable=False)
    sensor_id = Column(String, ForeignKey("sensors.id"), nullable=False)

    # Record metadata
    telemetry_type = Column(Enum(TelemetryType), nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False)

    # Telemetry data
    metrics = Column(JSON)  # GPU metrics (utilization, memory, etc.)
    metadata = Column(JSON)  # Additional context

    # Processing status
    processed = Column(Boolean, default=False)
    anomaly_score = Column(Float)  # 0.0-1.0, computed by analysis

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    gpu = relationship("GPU", back_populates="telemetry_records")

    __table_args__ = (
        Index("idx_telemetry_gpu", "gpu_id"),
        Index("idx_telemetry_timestamp", "timestamp"),
        Index("idx_telemetry_type", "telemetry_type"),
        Index("idx_telemetry_processed", "processed"),
    )


class SecurityEvent(Base):
    """Security events detected by eBPF probes"""

    __tablename__ = "security_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    node_id = Column(String, ForeignKey("nodes.id"), nullable=False)

    # Event details
    event_type = Column(Enum(EventType), nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False)

    # Process context
    pid = Column(Integer)
    comm = Column(String(16))  # Process name
    uid = Column(Integer)
    gid = Column(Integer)

    # Event data
    syscall_nr = Column(Integer)  # For syscall events
    ioctl_cmd = Column(String(50))  # For ioctl events
    file_path = Column(String(4096))  # For file operations
    file_hash = Column(String(64))  # SHA256 for firmware/modules

    # Additional context
    details = Column(JSON)  # Event-specific data
    risk_score = Column(Float)  # 0.0-1.0

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("idx_security_event_node", "node_id"),
        Index("idx_security_event_type", "event_type"),
        Index("idx_security_event_timestamp", "timestamp"),
        Index("idx_security_event_pid", "pid"),
    )


class Alert(Base):
    """Security alerts generated by the alert engine"""

    __tablename__ = "alerts"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    node_id = Column(String, ForeignKey("nodes.id"), nullable=False)

    # Alert details
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(Enum(AlertSeverity), nullable=False)

    # Detection details
    rule_id = Column(String(100))  # Detection rule that triggered
    confidence = Column(Float)  # 0.0-1.0

    # Related events
    security_event_ids = Column(JSON)  # List of related security event IDs
    telemetry_record_ids = Column(JSON)  # List of related telemetry IDs

    # Status
    status = Column(
        String(20), default="open"
    )  # open, investigating, resolved, false_positive
    assigned_to = Column(String(100))  # User/team assigned

    # Timeline
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    resolved_at = Column(DateTime(timezone=True))

    # Response
    response_actions = Column(JSON)  # Actions taken
    notes = Column(Text)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    __table_args__ = (
        Index("idx_alert_node", "node_id"),
        Index("idx_alert_severity", "severity"),
        Index("idx_alert_status", "status"),
        Index("idx_alert_first_seen", "first_seen"),
    )


class AuditLog(Base):
    """Audit log for API operations"""

    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))

    # User/service context
    user_id = Column(String(255))  # SPIRE SVID subject
    source_ip = Column(String(45))
    user_agent = Column(String(500))

    # Operation details
    operation = Column(
        String(100), nullable=False
    )  # e.g., "create_alert", "update_node"
    resource_type = Column(String(50))  # e.g., "alert", "node", "sensor"
    resource_id = Column(String(255))

    # Request/response
    request_data = Column(JSON)
    response_status = Column(Integer)

    # Timing
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    duration_ms = Column(Integer)

    __table_args__ = (
        Index("idx_audit_user", "user_id"),
        Index("idx_audit_operation", "operation"),
        Index("idx_audit_timestamp", "timestamp"),
    )
