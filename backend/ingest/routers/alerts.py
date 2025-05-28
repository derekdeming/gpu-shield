from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from typing import List, Optional
from datetime import datetime, timedelta, UTC
import logging

from ..database import get_db
from ..models import Alert, Node
from ..schemas import (
    AlertCreate,
    AlertResponse,
    AlertUpdate,
    AlertQuery,
    PaginatedResponse,
    AlertSeverity,
)

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
async def create_alert(alert: AlertCreate, db: AsyncSession = Depends(get_db)):
    """Create a new security alert"""
    try:
        node_exists = await db.execute(select(Node.id).where(Node.id == alert.node_id))
        if not node_exists.scalar():
            raise HTTPException(status_code=404, detail="Node not found")

        db_alert = Alert(**alert.model_dump())
        db.add(db_alert)
        await db.commit()
        await db.refresh(db_alert)
        logger.info(f"Created alert {db_alert.id} with severity {db_alert.severity}")
        return db_alert
    except Exception as e:
        logger.error(f"Error creating alert: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create alert")


@router.post("/query", response_model=PaginatedResponse)
async def query_alerts(query: AlertQuery, db: AsyncSession = Depends(get_db)):
    """Query alerts with filters"""
    try:
        stmt = select(Alert)
        filters = []
        if query.node_ids:
            filters.append(Alert.node_id.in_(query.node_ids))
        if query.severities:
            filters.append(Alert.severity.in_(query.severities))
        if query.statuses:
            filters.append(Alert.status.in_(query.statuses))
        if query.assigned_to:
            filters.append(Alert.assigned_to == query.assigned_to)
        if query.time_range:
            filters.append(Alert.first_seen >= query.time_range.start)
            filters.append(Alert.last_seen <= query.time_range.end)
        if filters:
            stmt = stmt.where(and_(*filters))

        count_stmt = select(func.count()).select_from(stmt.alias())
        total_result = await db.execute(count_stmt)
        total = total_result.scalar()
        stmt = stmt.order_by(Alert.first_seen.desc())
        stmt = stmt.offset(query.offset).limit(query.limit)
        result = await db.execute(stmt)
        alerts = result.scalars().all()
        return PaginatedResponse(
            items=[AlertResponse.model_validate(alert) for alert in alerts],
            total=total,
            offset=query.offset,
            limit=query.limit,
            has_more=query.offset + len(alerts) < total,
        )
    except Exception as e:
        logger.error(f"Error querying alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to query alerts")


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific alert"""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: str, update: AlertUpdate, db: AsyncSession = Depends(get_db)
):
    """Update an alert (status, assignment, notes, etc.)"""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    update_data = update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(alert, field, value)
    if update.status == "resolved" and not alert.resolved_at:
        alert.resolved_at = datetime.now(UTC)

    try:
        await db.commit()
        await db.refresh(alert)
        logger.info(f"Updated alert {alert_id}: {update_data}")
        return alert
    except Exception as e:
        logger.error(f"Error updating alert: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update alert")


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    """Delete an alert (use with caution)"""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    try:
        await db.delete(alert)
        await db.commit()
        logger.warning(f"Deleted alert {alert_id}")
    except Exception as e:
        logger.error(f"Error deleting alert: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete alert")


@router.get("/", response_model=List[AlertResponse])
async def list_alerts(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[AlertSeverity] = None,
    status: Optional[str] = None,
    node_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List alerts with basic filtering"""
    try:
        stmt = select(Alert)
        if severity:
            stmt = stmt.where(Alert.severity == severity)
        if status:
            stmt = stmt.where(Alert.status == status)
        if node_id:
            stmt = stmt.where(Alert.node_id == node_id)
        stmt = stmt.order_by(Alert.first_seen.desc())
        stmt = stmt.offset(offset).limit(limit)
        result = await db.execute(stmt)
        alerts = result.scalars().all()
        return [AlertResponse.model_validate(alert) for alert in alerts]
    except Exception as e:
        logger.error(f"Error listing alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to list alerts")


@router.post("/{alert_id}/assign")
async def assign_alert(
    alert_id: str, assignee: str, db: AsyncSession = Depends(get_db)
):
    """Assign an alert to a user/team"""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.assigned_to = assignee
    if alert.status == "open":
        alert.status = "investigating"

    try:
        await db.commit()
        logger.info(f"Assigned alert {alert_id} to {assignee}")
        return {"alert_id": alert_id, "assigned_to": assignee, "status": alert.status}
    except Exception as e:
        logger.error(f"Error assigning alert: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to assign alert")


@router.post("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    resolution_notes: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Mark an alert as resolved"""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "resolved"
    alert.resolved_at = datetime.now(UTC)
    if resolution_notes:
        alert.notes = f"{alert.notes or ''}\n\nResolution: {resolution_notes}".strip()

    try:
        await db.commit()
        logger.info(f"Resolved alert {alert_id}")
        return {
            "alert_id": alert_id,
            "status": "resolved",
            "resolved_at": alert.resolved_at,
        }
    except Exception as e:
        logger.error(f"Error resolving alert: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to resolve alert")


@router.get("/stats/summary")
async def get_alerts_summary(
    hours: int = Query(24, ge=1, le=168),  # 1 hour to 1 week
    db: AsyncSession = Depends(get_db),
):
    """Get alert statistics summary"""
    try:
        cutoff_time = datetime.now(UTC) - timedelta(hours=hours)
        severity_result = await db.execute(
            select(Alert.severity, func.count(Alert.id).label("count"))
            .where(Alert.first_seen >= cutoff_time)
            .group_by(Alert.severity)
        )
        severity_counts = {row.severity: row.count for row in severity_result}
        status_result = await db.execute(
            select(Alert.status, func.count(Alert.id).label("count"))
            .where(Alert.first_seen >= cutoff_time)
            .group_by(Alert.status)
        )
        status_counts = {row.status: row.count for row in status_result}
        critical_open_result = await db.execute(
            select(func.count(Alert.id)).where(
                and_(
                    Alert.severity.in_([AlertSeverity.CRITICAL, AlertSeverity.HIGH]),
                    Alert.status.in_(["open", "investigating"]),
                )
            )
        )
        critical_open = critical_open_result.scalar()
        resolved_alerts = await db.execute(
            select(Alert).where(
                and_(Alert.resolved_at.is_not(None), Alert.first_seen >= cutoff_time)
            )
        )

        resolution_times = []
        for alert in resolved_alerts.scalars():
            if alert.resolved_at and alert.first_seen:
                duration = (
                    alert.resolved_at - alert.first_seen
                ).total_seconds() / 3600  # turn it to hours
                resolution_times.append(duration)

        avg_resolution_hours = (
            sum(resolution_times) / len(resolution_times) if resolution_times else 0
        )
        return {
            "time_window_hours": hours,
            "alerts_by_severity": severity_counts,
            "alerts_by_status": status_counts,
            "total_alerts": sum(severity_counts.values()),
            "critical_high_open": critical_open,
            "average_resolution_hours": round(avg_resolution_hours, 2),
            "timestamp": datetime.now(UTC),
        }
    except Exception as e:
        logger.error(f"Error getting alerts summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to get alerts summary")
