from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from typing import List, Optional
from datetime import datetime, timedelta, UTC
import logging

from ..database import get_db
from ..models import TelemetryRecord, GPU, Sensor
from ..schemas import (TelemetryRecordCreate, TelemetryRecordResponse, TelemetryRecordUpdate,TelemetryBulkCreate, TelemetryQuery, PaginatedResponse, OTLPTelemetryBatch)
from ..services.telemetry_processor import TelemetryProcessor

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post(
    "/records",
    response_model=TelemetryRecordResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_telemetry_record(
    record: TelemetryRecordCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Create a single telemetry record

    Args:
        record: TelemetryRecordCreate
        background_tasks: BackgroundTasks (for async processing)
        db: AsyncSession (database session)

    Returns:
    """
    try:
        gpu_exists = await db.execute(select(GPU.id).where(GPU.id == record.gpu_id))
        if not gpu_exists.scalar():
            raise HTTPException(status_code=404, detail="GPU not found")
        sensor_exists = await db.execute(select(Sensor.id).where(Sensor.id == record.sensor_id))
        if not sensor_exists.scalar():
            raise HTTPException(status_code=404, detail="Sensor not found")
        db_record = TelemetryRecord(**record.model_dump())
        db.add(db_record)
        await db.commit()
        await db.refresh(db_record)
        background_tasks.add_task(TelemetryProcessor.process_record, db_record.id)
        return db_record
    except Exception as e:
        logger.error(f"Error creating telemetry record: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create telemetry record")


@router.post("/records/bulk", status_code=status.HTTP_201_CREATED)
async def create_telemetry_records_bulk(
    batch: TelemetryBulkCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Create multiple telemetry records in batch

    need to validate all GPU and sensor IDs exist
    """
    try:
        gpu_ids = list(set(record.gpu_id for record in batch.records))
        sensor_ids = list(set(record.sensor_id for record in batch.records))
        gpu_count = await db.execute(select(func.count(GPU.id)).where(GPU.id.in_(gpu_ids)))
        if gpu_count.scalar() != len(gpu_ids):
            raise HTTPException(status_code=400, detail="One or more GPU IDs not found")

        sensor_count = await db.execute(select(func.count(Sensor.id)).where(Sensor.id.in_(sensor_ids)))
        if sensor_count.scalar() != len(sensor_ids):
            raise HTTPException(status_code=400, detail="One or more sensor IDs not found")
        db_records = [TelemetryRecord(**record.model_dump()) for record in batch.records]
        db.add_all(db_records)
        await db.commit()
        record_ids = [record.id for record in db_records]
        background_tasks.add_task(TelemetryProcessor.process_batch, record_ids)
        return {"created": len(db_records), "record_ids": record_ids}
    except Exception as e:
        logger.error(f"Error creating telemetry records bulk: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create telemetry records")


@router.post("/otlp", status_code=status.HTTP_202_ACCEPTED)
async def ingest_otlp_telemetry(
    otlp_batch: OTLPTelemetryBatch,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Ingest telemetry from OpenTelemetry collector (OTLP format)"""
    try:
        background_tasks.add_task(TelemetryProcessor.process_otlp_batch, otlp_batch.resource_metrics)
        return {
            "status": "accepted",
            "resource_metrics_count": len(otlp_batch.resource_metrics)}
    except Exception as e:
        logger.error(f"Error ingesting OTLP telemetry: {e}")
        raise HTTPException(status_code=500, detail="Failed to ingest OTLP telemetry")

@router.post("/query", response_model=PaginatedResponse)
async def query_telemetry_records(
    query: TelemetryQuery, db: AsyncSession = Depends(get_db)
):
    """Query telemetry records with filters"""
    try:
        stmt = select(TelemetryRecord)
        filters = []
        if query.gpu_ids:
            filters.append(TelemetryRecord.gpu_id.in_(query.gpu_ids))
        if query.sensor_ids:
            filters.append(TelemetryRecord.sensor_id.in_(query.sensor_ids))
        if query.telemetry_types:
            filters.append(TelemetryRecord.telemetry_type.in_(query.telemetry_types))
        if query.processed is not None:
            filters.append(TelemetryRecord.processed == query.processed)
        if query.min_anomaly_score is not None:
            filters.append(TelemetryRecord.anomaly_score >= query.min_anomaly_score)
        if query.time_range:
            filters.append(TelemetryRecord.timestamp >= query.time_range.start)
            filters.append(TelemetryRecord.timestamp <= query.time_range.end)
        if filters:
            stmt = stmt.where(and_(*filters))
        
        count_stmt = select(func.count()).select_from(stmt.alias())
        total_result = await db.execute(count_stmt)
        total = total_result.scalar()
        stmt = stmt.order_by(TelemetryRecord.timestamp.desc())
        stmt = stmt.offset(query.offset).limit(query.limit)
        result = await db.execute(stmt)
        records = result.scalars().all()

        return PaginatedResponse(
            items=[TelemetryRecordResponse.model_validate(record) for record in records],
            total=total,
            offset=query.offset,
            limit=query.limit,
            has_more=query.offset + len(records) < total,
        )
    except Exception as e:
        logger.error(f"Error querying telemetry records: {e}")
        raise HTTPException(status_code=500, detail="Failed to query telemetry records")


@router.get("/records/{record_id}", response_model=TelemetryRecordResponse)
async def get_telemetry_record(record_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific telemetry record"""
    result = await db.execute(select(TelemetryRecord).where(TelemetryRecord.id == record_id))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Telemetry record not found")
    return record


@router.patch("/records/{record_id}", response_model=TelemetryRecordResponse)
async def update_telemetry_record(
    record_id: str, update: TelemetryRecordUpdate, db: AsyncSession = Depends(get_db)
):
    """Update a telemetry record (mainly for processing status)"""
    result = await db.execute(select(TelemetryRecord).where(TelemetryRecord.id == record_id))
    record = result.scalar_one_or_none()

    if not record:
        raise HTTPException(status_code=404, detail="Telemetry record not found")
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(record, field, value)

    try:
        await db.commit()
        await db.refresh(record)
        return record
    except Exception as e:
        logger.error(f"Error updating telemetry record: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update telemetry record")


@router.get("/metrics/gpu/{gpu_id}/latest")
async def get_latest_gpu_metrics(
    gpu_id: str,
    metric_types: Optional[List[str]] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Get latest metrics for a specific GPU"""
    try:
        gpu_result = await db.execute(select(GPU).where(GPU.id == gpu_id))
        gpu = gpu_result.scalar_one_or_none()
        if not gpu:
            raise HTTPException(status_code=404, detail="GPU not found")
        stmt = select(TelemetryRecord).where(TelemetryRecord.gpu_id == gpu_id).order_by(TelemetryRecord.timestamp.desc()).limit(1)

        result = await db.execute(stmt)
        latest_record = result.scalar_one_or_none()
        if not latest_record:
            return {"gpu_id": gpu_id, "metrics": {}, "timestamp": None}
        metrics = latest_record.metrics
        if metric_types:
            metrics = {k: v for k, v in metrics.items() if k in metric_types}
        return {
            "gpu_id": gpu_id,
            "metrics": metrics,
            "timestamp": latest_record.timestamp,
            "anomaly_score": latest_record.anomaly_score,
        }
    except Exception as e:
        logger.error(f"Error getting latest GPU metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get GPU metrics")


@router.get("/metrics/summary")
async def get_telemetry_summary(
    hours: int = Query(24, ge=1, le=168),  # 1 hour to 1 week
    db: AsyncSession = Depends(get_db),
):
    """Get telemetry summary statistics"""
    try:
        cutoff_time = datetime.now(UTC) - timedelta(hours=hours)
        result = await db.execute(
            select(TelemetryRecord.telemetry_type, func.count(TelemetryRecord.id).label("count")).where(TelemetryRecord.timestamp >= cutoff_time).group_by(TelemetryRecord.telemetry_type)
        )

        type_counts = {row.telemetry_type: row.count for row in result}
        anomaly_result = await db.execute(
            select(func.count(TelemetryRecord.id)).where(
                and_(TelemetryRecord.timestamp >= cutoff_time, TelemetryRecord.anomaly_score >= 0.7)
            )
        )
        anomaly_count = anomaly_result.scalar()
        unprocessed_result = await db.execute(
            select(func.count(TelemetryRecord.id)).where(
                and_(TelemetryRecord.timestamp >= cutoff_time, TelemetryRecord.processed == False)
            )
        )
        unprocessed_count = unprocessed_result.scalar()
        return {
            "time_window_hours": hours,
            "records_by_type": type_counts,
            "total_records": sum(type_counts.values()),
            "anomalies_detected": anomaly_count,
            "unprocessed_records": unprocessed_count,
            "timestamp": datetime.now(UTC),
        }
    except Exception as e:
        logger.error(f"Error getting telemetry summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to get telemetry summary")