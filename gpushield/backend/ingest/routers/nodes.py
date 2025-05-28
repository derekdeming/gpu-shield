from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from sqlalchemy.orm import selectinload
from typing import List, Optional
from datetime import datetime, timedelta, UTC
import logging

from ..database import get_db
from ..models import Node, GPU, Sensor
from ..schemas import NodeCreate, NodeResponse, NodeUpdate, GPUCreate, GPUResponse

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/", response_model=NodeResponse, status_code=status.HTTP_201_CREATED)
async def create_node(node: NodeCreate, db: AsyncSession = Depends(get_db)):
    """Register a new Kubernetes node"""
    try:
        existing = await db.execute(select(Node).where(Node.name == node.name))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Node with this name already exists")
        db_node = Node(**node.model_dump())
        db.add(db_node)
        await db.commit()
        await db.refresh(db_node)
        logger.info(f"Created node {db_node.id} ({db_node.name}) in cluster {db_node.cluster_id}")
        return db_node
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating node: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create node")


@router.get("/", response_model=List[NodeResponse])
async def list_nodes(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    cluster_id: Optional[str] = None,
    attestation_status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List nodes with filtering"""
    try:
        stmt = select(Node)
        if cluster_id:
            stmt = stmt.where(Node.cluster_id == cluster_id)
        if attestation_status:
            stmt = stmt.where(Node.attestation_status == attestation_status)
        stmt = stmt.order_by(Node.created_at.desc())
        stmt = stmt.offset(offset).limit(limit)
        result = await db.execute(stmt)
        nodes = result.scalars().all()
        return [NodeResponse.model_validate(node) for node in nodes]
    except Exception as e:
        logger.error(f"Error listing nodes: {e}")
        raise HTTPException(status_code=500, detail="Failed to list nodes")


@router.get("/{node_id}", response_model=NodeResponse)
async def get_node(node_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific node"""
    result = await db.execute(
        select(Node)
        .options(selectinload(Node.gpus), selectinload(Node.sensors))
        .where(Node.id == node_id)
    )
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    return node


@router.patch("/{node_id}", response_model=NodeResponse)
async def update_node(
    node_id: str, update: NodeUpdate, db: AsyncSession = Depends(get_db)
):
    """Update node information"""
    result = await db.execute(select(Node).where(Node.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(node, field, value)
    node.last_seen = datetime.now(UTC)

    try:
        await db.commit()
        await db.refresh(node)
        logger.info(f"Updated node {node_id}")
        return node
    except Exception as e:
        logger.error(f"Error updating node: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update node")


@router.delete("/{node_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_node(node_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a node and all associated resources"""
    result = await db.execute(select(Node).where(Node.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    try:
        await db.delete(node)
        await db.commit()
        logger.warning(f"Deleted node {node_id} ({node.name})")
    except Exception as e:
        logger.error(f"Error deleting node: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete node")


@router.post(
    "/{node_id}/gpus", response_model=GPUResponse, status_code=status.HTTP_201_CREATED
)
async def add_gpu_to_node(
    node_id: str, gpu: GPUCreate, db: AsyncSession = Depends(get_db)):
    """Add a GPU to a node"""
    node_exists = await db.execute(select(Node.id).where(Node.id == node_id))
    if not node_exists.scalar():
        raise HTTPException(status_code=404, detail="Node not found")
    if gpu.node_id != node_id:
        raise HTTPException(status_code=400, detail="GPU node_id must match URL node_id")

    try:
        existing = await db.execute(select(GPU).where(and_(GPU.node_id == node_id, GPU.device_id == gpu.device_id)))
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=409, detail="GPU with this device_id already exists on node"
            )

        db_gpu = GPU(**gpu.model_dump())
        db.add(db_gpu)
        await db.commit()
        await db.refresh(db_gpu)

        logger.info(f"Added GPU {db_gpu.id} ({db_gpu.model}) to node {node_id}")
        return db_gpu
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding GPU to node: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to add GPU to node")


@router.get("/{node_id}/gpus", response_model=List[GPUResponse])
async def list_node_gpus(node_id: str, db: AsyncSession = Depends(get_db)):
    """List all GPUs on a node"""
    node_exists = await db.execute(select(Node.id).where(Node.id == node_id))
    if not node_exists.scalar():
        raise HTTPException(status_code=404, detail="Node not found")

    result = await db.execute(select(GPU).where(GPU.node_id == node_id))
    gpus = result.scalars().all()
    return [GPUResponse.model_validate(gpu) for gpu in gpus]

@router.post("/{node_id}/heartbeat")
async def node_heartbeat(node_id: str, db: AsyncSession = Depends(get_db)):
    """Update node last seen timestamp"""
    result = await db.execute(select(Node).where(Node.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    try:
        node.last_seen = datetime.now(UTC)
        await db.commit()
        return {"node_id": node_id, "status": "received", "timestamp": node.last_seen}
    except Exception as e:
        logger.error(f"Error processing node heartbeat: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to process heartbeat")


@router.post("/{node_id}/attest")
async def attest_node(node_id: str, spiffe_id: str, db: AsyncSession = Depends(get_db)):
    """Update node SPIRE attestation"""
    result = await db.execute(select(Node).where(Node.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")

    try:
        node.spiffe_id = spiffe_id
        node.last_attestation = datetime.now(UTC)
        node.attestation_status = "verified"
        await db.commit()
        logger.info(f"Attested node {node_id} with SPIFFE ID {spiffe_id}")

        return {
            "node_id": node_id,
            "spiffe_id": spiffe_id,
            "status": "verified",
            "timestamp": node.last_attestation,
        }
    except Exception as e:
        logger.error(f"Error attesting node: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to attest node")


@router.get("/{node_id}/status")
async def get_node_status(node_id: str, db: AsyncSession = Depends(get_db)):
    """Get detailed node status"""
    result = await db.execute(
        select(Node)
        .options(selectinload(Node.gpus), selectinload(Node.sensors))
        .where(Node.id == node_id))
    node = result.scalar_one_or_none()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    cutoff_time = datetime.now(UTC) - timedelta(minutes=10)
    is_stale = node.last_seen < cutoff_time
    active_sensors = sum(1 for sensor in node.sensors if sensor.is_active)
    active_gpus = sum(1 for gpu in node.gpus if gpu.is_active)

    return {
        "node_id": node_id,
        "name": node.name,
        "cluster_id": node.cluster_id,
        "ip_address": node.ip_address,
        "is_stale": is_stale,
        "last_seen": node.last_seen,
        "attestation_status": node.attestation_status,
        "last_attestation": node.last_attestation,
        "spiffe_id": node.spiffe_id,
        "gpu_count": len(node.gpus),
        "active_gpu_count": active_gpus,
        "sensor_count": len(node.sensors),
        "active_sensor_count": active_sensors,
        "kubernetes_version": node.kubernetes_version,
        "kernel_version": node.kernel_version,
        "container_runtime": node.container_runtime,
        "created_at": node.created_at,
    }


@router.get("/stats/summary")
async def get_nodes_summary(db: AsyncSession = Depends(get_db)):
    """Get node statistics summary"""
    try:
        cluster_result = await db.execute(
            select(Node.cluster_id, func.count(Node.id).label("count")).group_by(Node.cluster_id))
        cluster_counts = {row.cluster_id: row.count for row in cluster_result}
        attestation_result = await db.execute(
            select(Node.attestation_status, func.count(Node.id).label("count")).group_by(Node.attestation_status))
        attestation_counts = {row.attestation_status: row.count for row in attestation_result}
        cutoff_time = datetime.now(UTC) - timedelta(minutes=10)
        stale_result = await db.execute(select(func.count(Node.id)).where(Node.last_seen < cutoff_time))
        stale_count = stale_result.scalar()
        gpu_result = await db.execute(select(func.count(GPU.id)))
        total_gpus = gpu_result.scalar()
        sensor_result = await db.execute(select(func.count(Sensor.id)))
        total_sensors = sensor_result.scalar()
        return {
            "nodes_by_cluster": cluster_counts,
            "nodes_by_attestation_status": attestation_counts,
            "total_nodes": sum(cluster_counts.values()),
            "stale_nodes": stale_count,
            "total_gpus": total_gpus,
            "total_sensors": total_sensors,
            "timestamp": datetime.now(UTC),
        }
    except Exception as e:
        logger.error(f"Error getting nodes summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to get nodes summary")
