import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..config import settings
from ..database import AsyncSessionLocal
from ..models import TelemetryRecord
from sqlalchemy import select

logger = logging.getLogger(__name__)


class TelemetryProcessor:
    """Service for processing telemetry data and detecting anomalies"""

    @staticmethod
    async def process_record(record_id: str):
        """Process a single telemetry record for anomaly detection"""
        try:
            async with AsyncSessionLocal() as db:

                result = await db.execute(
                    select(TelemetryRecord).where(TelemetryRecord.id == record_id)
                )
                record = result.scalar_one_or_none()
                if not record:
                    logger.warning(f"Telemetry record {record_id} not found")
                    return
                anomaly_score = await TelemetryProcessor._detect_anomalies(
                    record.metrics
                )
                record.anomaly_score = anomaly_score
                record.processed = True
                await db.commit()
                if anomaly_score >= settings.ANOMALY_THRESHOLD:
                    await TelemetryProcessor._generate_anomaly_alert(
                        record, anomaly_score
                    )
                logger.debug(
                    f"Processed telemetry record {record_id}, anomaly score: {anomaly_score}"
                )
        except Exception as e:
            logger.error(f"Error processing telemetry record {record_id}: {e}")

    @staticmethod
    async def process_batch(record_ids: List[str]):
        """Process multiple telemetry records in batch"""
        try:
            tasks = [
                TelemetryProcessor.process_record(record_id) for record_id in record_ids
            ]
            await asyncio.gather(*tasks, return_exceptions=True)
            logger.info(f"Processed batch of {len(record_ids)} telemetry records")
        except Exception as e:
            logger.error(f"Error processing telemetry batch: {e}")

    @staticmethod
    async def process_otlp_batch(resource_metrics: List[Dict[str, Any]]):
        """Process OTLP telemetry batch from OpenTelemetry collector"""
        try:
            processed_count = 0

            for resource_metric in resource_metrics:
                # Extract resource attributes
                resource = resource_metric.get("resource", {})
                resource_attributes = resource.get("attributes", [])

                # Find GPU and sensor information from attributes
                gpu_id = None
                sensor_id = None
                node_id = None

                for attr in resource_attributes:
                    key = attr.get("key", "")
                    value = attr.get("value", {}).get("stringValue", "")

                    if key == "gpu.id":
                        gpu_id = value
                    elif key == "sensor.id":
                        sensor_id = value
                    elif key == "node.id":
                        node_id = value

                if not all([gpu_id, sensor_id]):
                    logger.warning(
                        "Missing GPU or sensor ID in OTLP resource attributes"
                    )
                    continue

                # Process scope metrics
                scope_metrics = resource_metric.get("scopeMetrics", [])
                for scope_metric in scope_metrics:
                    metrics = scope_metric.get("metrics", [])

                    for metric in metrics:
                        await TelemetryProcessor._process_otlp_metric(
                            metric, gpu_id, sensor_id, node_id
                        )
                        processed_count += 1

            logger.info(f"Processed {processed_count} OTLP metrics")

        except Exception as e:
            logger.error(f"Error processing OTLP batch: {e}")

    @staticmethod
    async def _process_otlp_metric(
        metric: Dict[str, Any], gpu_id: str, sensor_id: str, node_id: Optional[str]
    ):
        """Process a single OTLP metric"""
        try:
            metric_name = metric.get("name", "")
            metric_description = metric.get("description", "")

            # Extract data points
            data_points = []
            if "gauge" in metric:
                data_points = metric["gauge"].get("dataPoints", [])
            elif "sum" in metric:
                data_points = metric["sum"].get("dataPoints", [])
            elif "histogram" in metric:
                data_points = metric["histogram"].get("dataPoints", [])

            for data_point in data_points:
                # Extract timestamp
                timestamp_nano = data_point.get("timeUnixNano", 0)
                timestamp = datetime.fromtimestamp(timestamp_nano / 1_000_000_000)

                # Extract value
                value = None
                if "asDouble" in data_point:
                    value = data_point["asDouble"]
                elif "asInt" in data_point:
                    value = data_point["asInt"]

                # Extract attributes
                attributes = {}
                for attr in data_point.get("attributes", []):
                    key = attr.get("key", "")
                    attr_value = attr.get("value", {})
                    if "stringValue" in attr_value:
                        attributes[key] = attr_value["stringValue"]
                    elif "intValue" in attr_value:
                        attributes[key] = attr_value["intValue"]
                    elif "doubleValue" in attr_value:
                        attributes[key] = attr_value["doubleValue"]

                # Create telemetry record
                metrics_data = {metric_name: value, **attributes}

                metadata = {
                    "description": metric_description,
                    "otlp_source": True,
                    "node_id": node_id,
                }

                # Store in database
                async with AsyncSessionLocal() as db:
                    from ..models import TelemetryType

                    record = TelemetryRecord(
                        gpu_id=gpu_id,
                        sensor_id=sensor_id,
                        telemetry_type=TelemetryType.METRICS,
                        timestamp=timestamp,
                        metrics=metrics_data,
                        metadata=metadata,
                    )
                    db.add(record)
                    await db.commit()

                    # Process asynchronously
                    asyncio.create_task(TelemetryProcessor.process_record(record.id))

        except Exception as e:
            logger.error(f"Error processing OTLP metric: {e}")

    @staticmethod
    async def _detect_anomalies(metrics: Dict[str, Any]) -> float:
        """Detect anomalies in telemetry metrics"""
        try:
            anomaly_score = 0.0

            # dummy anomaly detection rules
            # TODO: use ML models in production

            # GPU utilization anomalies
            gpu_util = metrics.get("gpu_utilization", 0)
            if gpu_util > 95:
                anomaly_score += 0.3
            elif gpu_util < 5:
                anomaly_score += 0.2
            memory_util = metrics.get("memory_utilization", 0)
            if memory_util > 90:
                anomaly_score += 0.4
            temperature = metrics.get("temperature", 0)
            if temperature > 85:
                anomaly_score += 0.5
            elif temperature > 80:
                anomaly_score += 0.3
            power = metrics.get("power_usage", 0)
            if power > 400:
                anomaly_score += 0.3
            gpu_clock = metrics.get("gpu_clock", 0)
            memory_clock = metrics.get("memory_clock", 0)
            if gpu_clock > 2000 or memory_clock > 8000:
                anomaly_score += 0.4
            return min(anomaly_score, 1.0)
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            return 0.0

    @staticmethod
    async def _generate_anomaly_alert(record: TelemetryRecord, anomaly_score: float):
        """Generate an alert for detected anomaly"""
        try:
            async with AsyncSessionLocal() as db:
                from ..models import Alert, AlertSeverity, GPU

                gpu_result = await db.execute(
                    select(GPU).where(GPU.id == record.gpu_id)
                )
                gpu = gpu_result.scalar_one_or_none()
                if not gpu:
                    logger.warning(f"GPU {record.gpu_id} not found for anomaly alert")
                    return
                if anomaly_score >= 0.9:
                    severity = AlertSeverity.CRITICAL
                elif anomaly_score >= 0.7:
                    severity = AlertSeverity.HIGH
                elif anomaly_score >= 0.5:
                    severity = AlertSeverity.MEDIUM
                else:
                    severity = AlertSeverity.LOW
                alert = Alert(
                    node_id=gpu.node_id,
                    title=f"GPU Anomaly Detected - {gpu.model}",
                    description=f"Anomalous behavior detected on GPU {gpu.device_id} with score {anomaly_score:.2f}",
                    severity=severity,
                    rule_id="anomaly_detection",
                    confidence=anomaly_score,
                    telemetry_record_ids=[record.id],
                    first_seen=record.timestamp,
                    last_seen=record.timestamp,
                )
                db.add(alert)
                await db.commit()
                logger.warning(
                    f"Generated {severity.value} anomaly alert for GPU {gpu.device_id}"
                )
        except Exception as e:
            logger.error(f"Error generating anomaly alert: {e}")
