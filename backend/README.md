# GPUShield Backend

FastAPI-based backend service for GPU runtime security telemetry ingestion and alerting.

## Architecture

The backend is built with:

- **FastAPI**: Modern, fast web framework for building APIs
- **PostgreSQL**: Primary database for storing telemetry and alerts
- **SQLAlchemy**: Async ORM for database operations
- **Strawberry GraphQL**: GraphQL API alongside REST
- **SPIRE**: Identity and attestation framework
- **OpenTelemetry**: OTLP telemetry ingestion
- **Prometheus**: Metrics collection and monitoring

## Features

### REST API Endpoints

- **Telemetry** (`/api/v1/telemetry/`)

  - Ingest GPU metrics from sensors
  - Bulk telemetry ingestion
  - OTLP format support
  - Query and filter telemetry records

- **Alerts** (`/api/v1/alerts/`)

  - Create and manage security alerts
  - Alert lifecycle management
  - Query alerts with filtering
  - Alert assignment and resolution

- **Sensors** (`/api/v1/sensors/`)

  - Register GPU telemetry sensors
  - Sensor heartbeat monitoring
  - Sensor configuration management

- **Nodes** (`/api/v1/nodes/`)
  - Kubernetes node registration
  - GPU device management
  - SPIRE attestation
  - Node status monitoring

### GraphQL API

Available at `/graphql` with queries for:

- Nodes and GPU devices
- Telemetry records
- Security alerts
- Real-time data exploration

### Key Components

#### Models (`ingest/models.py`)

- **Node**: Kubernetes nodes with GPU resources
- **GPU**: GPU device information and status
- **Sensor**: Telemetry collection sensors
- **TelemetryRecord**: Raw GPU metrics data
- **SecurityEvent**: eBPF security events
- **Alert**: Security alerts and incidents

#### Services

- **TelemetryProcessor**: Anomaly detection and OTLP processing
- **SpireClient**: Identity and attestation with SPIRE

## GPU Vendor Support

### NVIDIA (A100/H100)

- NVML integration via Go bindings
- DCGM metrics collection
- Temperature, power, utilization monitoring

### AMD (MI300)

- ROCProfiler integration
- HIP runtime monitoring
- Memory and compute metrics

### Intel (Max Series)

- Level Zero API integration
- GPU utilization tracking
- Performance counters

## Security Features

### eBPF Monitoring

- Driver ioctl syscall monitoring
- DMA buffer mapping detection
- Firmware/module hash verification
- Anomalous behavior detection

### SPIRE Integration

- Node attestation with SPIFFE IDs
- Short-lived SVID tokens
- Workload identity verification

### Isolation

- Kata Containers support
- VM-based GPU workload isolation
- Runtime security enforcement

## Development Setup

### Prerequisites

- Python 3.11+
- PostgreSQL 15+
- Docker & Docker Compose

### Quick Start

1. **Clone and setup**:

```bash
cd gpushield/backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. **Start services**:

```bash
docker-compose up -d postgres redis
```

3. **Set environment variables**:

```bash
export DATABASE_URL="postgresql+asyncpg://gpushield:gpushield@localhost:5432/gpushield"
export DEBUG=true
export REQUIRE_AUTH=false
```

4. **Run the application**:

```bash
uvicorn ingest.main:app --reload --host 0.0.0.0 --port 8000
```

5. **Access the API**:

- REST API: http://localhost:8000
- GraphQL Playground: http://localhost:8000/graphql
- API Documentation: http://localhost:8000/docs

### Full Stack Development

Run the complete stack with monitoring:

```bash
docker-compose up -d
```

This starts:

- PostgreSQL (port 5432)
- FastAPI Backend (port 8000)
- OpenTelemetry Collector (ports 4317/4318)
- Prometheus (port 9090)
- Grafana (port 3001)

## Configuration

Environment variables (`.env` file):

```env
# Database
DATABASE_URL=postgresql+asyncpg://gpushield:gpushield@localhost:5432/gpushield

# Server
HOST=0.0.0.0
PORT=8000
DEBUG=false

# CORS
CORS_ORIGINS=["http://localhost:3000","http://localhost:5173"]

# Authentication
REQUIRE_AUTH=true

# SPIRE
SPIRE_SOCKET_PATH=/tmp/spire-agent/public/api.sock

# Telemetry
ANOMALY_THRESHOLD=0.7
BATCH_SIZE=1000

# OpenTelemetry
OTLP_ENDPOINT=http://localhost:4317
```

## API Examples

### Register a Node

```bash
curl -X POST "http://localhost:8000/api/v1/nodes/" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "gpu-node-01",
    "cluster_id": "prod-cluster",
    "ip_address": "10.0.1.100",
    "kubernetes_version": "1.28.0",
    "kernel_version": "5.15.0"
  }'
```

### Add GPU to Node

```bash
curl -X POST "http://localhost:8000/api/v1/nodes/{node_id}/gpus" \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": "{node_id}",
    "vendor": "nvidia",
    "model": "A100-SXM4-80GB",
    "device_id": "0000:00:1e.0",
    "uuid": "GPU-12345678-1234-1234-1234-123456789012",
    "memory_total": 81920,
    "compute_capability": "8.0"
  }'
```

### Ingest Telemetry

```bash
curl -X POST "http://localhost:8000/api/v1/telemetry/records" \
  -H "Content-Type: application/json" \
  -d '{
    "gpu_id": "{gpu_id}",
    "sensor_id": "{sensor_id}",
    "telemetry_type": "metrics",
    "timestamp": "2024-01-01T12:00:00Z",
    "metrics": {
      "gpu_utilization": 85.5,
      "memory_utilization": 70.2,
      "temperature": 78.0,
      "power_usage": 250.0
    }
  }'
```

### Query Alerts

```bash
curl -X POST "http://localhost:8000/api/v1/alerts/query" \
  -H "Content-Type: application/json" \
  -d '{
    "severities": ["high", "critical"],
    "statuses": ["open"],
    "limit": 50
  }'
```

## Integration with Go Services

The backend integrates with Go services for:

### GPU Telemetry Collection

- Go sensors collect metrics via vendor APIs
- Data sent to FastAPI via REST or OTLP
- Async processing and anomaly detection

### eBPF Security Monitoring

- Go eBPF programs monitor kernel events
- Security events forwarded to FastAPI
- Real-time threat detection and alerting

### SPIRE Integration

- Go SPIRE agents provide identity
- FastAPI validates SVID tokens
- Secure workload communication

## Monitoring and Observability

### Metrics

- Prometheus metrics at `/metrics`
- Custom GPU telemetry metrics
- API performance monitoring

### Logging

- Structured logging with correlation IDs
- Security event audit trails
- Performance and error tracking

### Health Checks

- Database connectivity: `/health`
- SPIRE agent status
- Sensor connectivity monitoring

## Testing

```bash
# Run tests
pytest

# With coverage
pytest --cov=ingest

# Integration tests
pytest tests/integration/

# Load testing
pytest tests/load/
```

## Deployment

### Production Considerations

- Use PostgreSQL with connection pooling
- Enable authentication and HTTPS
- Configure proper CORS origins
- Set up log aggregation
- Monitor with Prometheus/Grafana

### Kubernetes Deployment

See `../helm/gpu-runtime-security/` for Helm charts.
