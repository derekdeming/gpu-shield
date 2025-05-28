from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from typing import List, Optional
from datetime import datetime, timedelta, UTC
import logging

from ..database import get_db
from ..models import Sensor, Node
from ..schemas import SensorCreate, SensorResponse, SensorUpdate, SensorHeartbeat

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/", response_model=SensorResponse, status_code=status.HTTP_201_CREATED)
async def create_sensor(sensor: SensorCreate, db: AsyncSession = Depends(get_db)):
    """Register a new sensor"""
    try:
        node_exists = await db.execute(select(Node.id).where(Node.id == sensor.node_id))
        if not node_exists.scalar():
            raise HTTPException(status_code=404, detail="Node not found")
        db_sensor = Sensor(**sensor.model_dump())
        db.add(db_sensor)
        await db.commit()
        await db.refresh(db_sensor)
        logger.info(
            f"Created sensor {db_sensor.id} of type {db_sensor.sensor_type} on node {db_sensor.node_id}"
        )
        return db_sensor
    except Exception as e:
        logger.error(f"Error creating sensor: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create sensor")


@router.get("/", response_model=List[SensorResponse])
async def list_sensors(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    node_id: Optional[str] = None,
    sensor_type: Optional[str] = None,
    is_active: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
):
    """List sensors with filtering"""
    try:
        stmt = select(Sensor)
        if node_id:
            stmt = stmt.where(Sensor.node_id == node_id)
        if sensor_type:
            stmt = stmt.where(Sensor.sensor_type == sensor_type)
        if is_active is not None:
            stmt = stmt.where(Sensor.is_active == is_active)
        stmt = stmt.order_by(Sensor.created_at.desc())
        stmt = stmt.offset(offset).limit(limit)
        result = await db.execute(stmt)
        sensors = result.scalars().all()
        return [SensorResponse.model_validate(sensor) for sensor in sensors]
    except Exception as e:
        logger.error(f"Error listing sensors: {e}")
        raise HTTPException(status_code=500, detail="Failed to list sensors")


@router.get("/{sensor_id}", response_model=SensorResponse)
async def get_sensor(sensor_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific sensor"""
    result = await db.execute(select(Sensor).where(Sensor.id == sensor_id))
    sensor = result.scalar_one_or_none()
    if not sensor:
        raise HTTPException(status_code=404, detail="Sensor not found")
    return sensor


@router.patch("/{sensor_id}", response_model=SensorResponse)
async def update_sensor(
    sensor_id: str, update: SensorUpdate, db: AsyncSession = Depends(get_db)
):
    """Update sensor configuration or status"""
    result = await db.execute(select(Sensor).where(Sensor.id == sensor_id))
    sensor = result.scalar_one_or_none()

    if not sensor:
        raise HTTPException(status_code=404, detail="Sensor not found")
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(sensor, field, value)
    try:
        await db.commit()
        await db.refresh(sensor)
        logger.info(f"Updated sensor {sensor_id}")
        return sensor
    except Exception as e:
        logger.error(f"Error updating sensor: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update sensor")


@router.delete("/{sensor_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sensor(sensor_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a sensor"""
    result = await db.execute(select(Sensor).where(Sensor.id == sensor_id))
    sensor = result.scalar_one_or_none()
    if not sensor:
        raise HTTPException(status_code=404, detail="Sensor not found")

    try:
        await db.delete(sensor)
        await db.commit()
        logger.info(f"Deleted sensor {sensor_id}")
    except Exception as e:
        logger.error(f"Error deleting sensor: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete sensor")


@router.post("/{sensor_id}/heartbeat", status_code=status.HTTP_200_OK)
async def sensor_heartbeat(
    sensor_id: str, heartbeat: SensorHeartbeat, db: AsyncSession = Depends(get_db)
):
    """Receive sensor heartbeat"""
    if heartbeat.sensor_id != sensor_id:
        raise HTTPException(status_code=400, detail="Sensor ID mismatch")

    result = await db.execute(select(Sensor).where(Sensor.id == sensor_id))
    sensor = result.scalar_one_or_none()

    if not sensor:
        raise HTTPException(status_code=404, detail="Sensor not found")

    try:
        sensor.last_heartbeat = heartbeat.timestamp
        if heartbeat.errors:
            sensor.errors_count += len(heartbeat.errors)
            logger.warning(
                f"Sensor {sensor_id} reported {len(heartbeat.errors)} errors"
            )
        if heartbeat.status == "healthy" and not sensor.is_active:
            sensor.is_active = True
            logger.info(f"Sensor {sensor_id} is now active")
        await db.commit()
        return {
            "sensor_id": sensor_id,
            "status": "received",
            "timestamp": heartbeat.timestamp,
        }
    except Exception as e:
        logger.error(f"Error processing sensor heartbeat: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to process heartbeat")


@router.get("/{sensor_id}/status")
async def get_sensor_status(sensor_id: str, db: AsyncSession = Depends(get_db)):
    """Get detailed sensor status"""
    result = await db.execute(select(Sensor).where(Sensor.id == sensor_id))
    sensor = result.scalar_one_or_none()

    if not sensor:
        raise HTTPException(status_code=404, detail="Sensor not found")
    cutoff_time = datetime.now(UTC) - timedelta(minutes=5)
    is_stale = sensor.last_heartbeat < cutoff_time
    hour_ago = datetime.now(UTC) - timedelta(hours=1)
    samples_last_hour = 0
    # TODO: Implement actual query

    return {
        "sensor_id": sensor_id,
        "sensor_type": sensor.sensor_type,
        "is_active": sensor.is_active,
        "is_stale": is_stale,
        "last_heartbeat": sensor.last_heartbeat,
        "samples_collected": sensor.samples_collected,
        "errors_count": sensor.errors_count,
        "samples_last_hour": samples_last_hour,
        "config": sensor.config,
        "created_at": sensor.created_at,
    }


@router.get("/stats/summary")
async def get_sensors_summary(db: AsyncSession = Depends(get_db)):
    """Get sensor statistics summary"""
    try:
        type_result = await db.execute(
            select(Sensor.sensor_type, func.count(Sensor.id).label("count")).group_by(
                Sensor.sensor_type
            )
        )
        type_counts = {row.sensor_type: row.count for row in type_result}
        active_result = await db.execute(
            select(func.count(Sensor.id)).where(Sensor.is_active == True)
        )
        active_count = active_result.scalar()
        cutoff_time = datetime.now(UTC) - timedelta(minutes=5)
        stale_result = await db.execute(
            select(func.count(Sensor.id)).where(
                and_(Sensor.is_active == True, Sensor.last_heartbeat < cutoff_time)
            )
        )
        stale_count = stale_result.scalar()
        error_result = await db.execute(select(func.sum(Sensor.errors_count)))
        total_errors = error_result.scalar() or 0
        samples_result = await db.execute(select(func.sum(Sensor.samples_collected)))
        total_samples = samples_result.scalar() or 0
        return {
            "sensors_by_type": type_counts,
            "total_sensors": sum(type_counts.values()),
            "active_sensors": active_count,
            "stale_sensors": stale_count,
            "total_errors": total_errors,
            "total_samples_collected": total_samples,
            "timestamp": datetime.now(UTC),
        }
    except Exception as e:
        logger.error(f"Error getting sensors summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to get sensors summary")
