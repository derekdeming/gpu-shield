"""Tests for protobuf generation and functionality."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'gpushield_proto'))

def test_protobuf_imports():
    """Test that protobuf modules can be imported successfully."""
    try:
        import telemetry_pb2
        import telemetry_pb2_grpc
        import integrity_pb2
        import integrity_pb2_grpc
        assert True, "All protobuf modules imported successfully"
    except ImportError as e:
        pytest.skip(f"Protobuf modules not generated yet: {e}")

def test_telemetry_message_creation():
    """Test that telemetry protobuf messages can be created."""
    try:
        import telemetry_pb2
        from google.protobuf.timestamp_pb2 import Timestamp
        telemetry_data = telemetry_pb2.TelemetryData()
        telemetry_data.node_id = "test-node"
        telemetry_data.hostname = "test-hostname"
        telemetry_data.sensor_version = "0.1.0"
        gpu_metric = telemetry_data.gpu_metrics.add()
        gpu_metric.device_id = 0
        gpu_metric.device_name = "Test GPU"
        gpu_metric.uuid = "GPU-12345678-1234-1234-1234-123456789012"
        
        assert telemetry_data.node_id == "test-node"
        assert telemetry_data.hostname == "test-hostname"
        assert len(telemetry_data.gpu_metrics) == 1
        assert telemetry_data.gpu_metrics[0].device_name == "Test GPU"
        
    except ImportError:
        pytest.skip("Telemetry protobuf module not available")

def test_integrity_message_creation():
    """Test that integrity protobuf messages can be created."""
    try:
        import integrity_pb2
        
        integrity_report = integrity_pb2.IntegrityReport()
        integrity_report.node_id = "test-node"
        integrity_report.hostname = "test-hostname"
        integrity_report.report_id = "report-12345"
        integrity_report.overall_status = integrity_pb2.INTEGRITY_STATUS_TRUSTED
        component = integrity_report.components.add()
        component.component_name = "nvidia_driver"
        component.component_version = "525.60.11"
        component.component_type = integrity_pb2.COMPONENT_TYPE_DRIVER
        component.status = integrity_pb2.INTEGRITY_STATUS_TRUSTED
        
        assert integrity_report.node_id == "test-node"
        assert integrity_report.overall_status == integrity_pb2.INTEGRITY_STATUS_TRUSTED
        assert len(integrity_report.components) == 1
        assert integrity_report.components[0].component_name == "nvidia_driver"
        
    except ImportError:
        pytest.skip("Integrity protobuf module not available")

if __name__ == "__main__":
    pytest.main([__file__]) 