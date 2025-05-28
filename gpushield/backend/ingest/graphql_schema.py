import strawberry
from typing import List, Optional
from datetime import datetime
from sqlalchemy import select

from .models import Node, GPU, Sensor, TelemetryRecord, Alert
from .database import get_db


@strawberry.type
class NodeType:
    id: str
    name: str
    cluster_id: str
    ip_address: str
    kubernetes_version: Optional[str]
    kernel_version: Optional[str]
    container_runtime: Optional[str]
    spiffe_id: Optional[str]
    attestation_status: str
    created_at: datetime
    last_seen: datetime


@strawberry.type
class GPUType:
    id: str
    node_id: str
    vendor: str
    model: str
    device_id: str
    uuid: Optional[str]
    memory_total: Optional[int]
    compute_capability: Optional[str]
    driver_version: Optional[str]
    firmware_version: Optional[str]
    is_active: bool
    temperature: Optional[float]
    power_usage: Optional[float]
    created_at: datetime


@strawberry.type
class SensorType:
    id: str
    node_id: str
    sensor_type: str
    version: str
    is_active: bool
    last_heartbeat: datetime
    samples_collected: int
    errors_count: int
    created_at: datetime


@strawberry.type
class TelemetryRecordType:
    id: str
    gpu_id: str
    sensor_id: str
    telemetry_type: str
    timestamp: datetime
    metrics: strawberry.scalars.JSON
    metadata: Optional[strawberry.scalars.JSON]
    processed: bool
    anomaly_score: Optional[float]
    created_at: datetime


@strawberry.type
class AlertType:
    id: str
    node_id: str
    title: str
    description: Optional[str]
    severity: str
    rule_id: Optional[str]
    confidence: Optional[float]
    status: str
    assigned_to: Optional[str]
    first_seen: datetime
    last_seen: datetime
    resolved_at: Optional[datetime]
    notes: Optional[str]
    created_at: datetime


@strawberry.type
class Query:
    @strawberry.field
    async def nodes(self, limit: int = 100) -> List[NodeType]:
        """Get list of nodes"""
        async with get_db() as db:
            result = await db.execute(select(Node).limit(limit))
            nodes = result.scalars().all()
            return [
                NodeType(
                    id=node.id,
                    name=node.name,
                    cluster_id=node.cluster_id,
                    ip_address=node.ip_address,
                    kubernetes_version=node.kubernetes_version,
                    kernel_version=node.kernel_version,
                    container_runtime=node.container_runtime,
                    spiffe_id=node.spiffe_id,
                    attestation_status=node.attestation_status,
                    created_at=node.created_at,
                    last_seen=node.last_seen,
                )
                for node in nodes
            ]

    @strawberry.field
    async def node(self, id: str) -> Optional[NodeType]:
        """Get a specific node by ID"""
        async with get_db() as db:
            result = await db.execute(select(Node).where(Node.id == id))
            node = result.scalar_one_or_none()
            if not node:
                return None
            return NodeType(
                id=node.id,
                name=node.name,
                cluster_id=node.cluster_id,
                ip_address=node.ip_address,
                kubernetes_version=node.kubernetes_version,
                kernel_version=node.kernel_version,
                container_runtime=node.container_runtime,
                spiffe_id=node.spiffe_id,
                attestation_status=node.attestation_status,
                created_at=node.created_at,
                last_seen=node.last_seen,
            )

    @strawberry.field
    async def gpus(
        self, node_id: Optional[str] = None, limit: int = 100
    ) -> List[GPUType]:
        """Get list of GPUs, optionally filtered by node"""
        async with get_db() as db:
            stmt = select(GPU)
            if node_id:
                stmt = stmt.where(GPU.node_id == node_id)
            stmt = stmt.limit(limit)

            result = await db.execute(stmt)
            gpus = result.scalars().all()
            return [
                GPUType(
                    id=gpu.id,
                    node_id=gpu.node_id,
                    vendor=gpu.vendor.value,
                    model=gpu.model,
                    device_id=gpu.device_id,
                    uuid=gpu.uuid,
                    memory_total=gpu.memory_total,
                    compute_capability=gpu.compute_capability,
                    driver_version=gpu.driver_version,
                    firmware_version=gpu.firmware_version,
                    is_active=gpu.is_active,
                    temperature=gpu.temperature,
                    power_usage=gpu.power_usage,
                    created_at=gpu.created_at,
                )
                for gpu in gpus
            ]

    @strawberry.field
    async def alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[AlertType]:
        """Get list of alerts with optional filtering"""
        async with get_db() as db:
            stmt = select(Alert)
            if severity:
                stmt = stmt.where(Alert.severity == severity)
            if status:
                stmt = stmt.where(Alert.status == status)

            stmt = stmt.order_by(Alert.first_seen.desc()).limit(limit)

            result = await db.execute(stmt)
            alerts = result.scalars().all()
            return [
                AlertType(
                    id=alert.id,
                    node_id=alert.node_id,
                    title=alert.title,
                    description=alert.description,
                    severity=alert.severity.value,
                    rule_id=alert.rule_id,
                    confidence=alert.confidence,
                    status=alert.status,
                    assigned_to=alert.assigned_to,
                    first_seen=alert.first_seen,
                    last_seen=alert.last_seen,
                    resolved_at=alert.resolved_at,
                    notes=alert.notes,
                    created_at=alert.created_at,
                )
                for alert in alerts
            ]

    @strawberry.field
    async def telemetry_records(
        self,
        gpu_id: Optional[str] = None,
        sensor_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[TelemetryRecordType]:
        """Get telemetry records with optional filtering"""
        async with get_db() as db:
            stmt = select(TelemetryRecord)
            if gpu_id:
                stmt = stmt.where(TelemetryRecord.gpu_id == gpu_id)
            if sensor_id:
                stmt = stmt.where(TelemetryRecord.sensor_id == sensor_id)

            stmt = stmt.order_by(TelemetryRecord.timestamp.desc()).limit(limit)
            result = await db.execute(stmt)
            records = result.scalars().all()
            return [
                TelemetryRecordType(
                    id=record.id,
                    gpu_id=record.gpu_id,
                    sensor_id=record.sensor_id,
                    telemetry_type=record.telemetry_type.value,
                    timestamp=record.timestamp,
                    metrics=record.metrics,
                    metadata=record.metadata,
                    processed=record.processed,
                    anomaly_score=record.anomaly_score,
                    created_at=record.created_at,
                )
                for record in records
            ]


schema = strawberry.Schema(query=Query)
