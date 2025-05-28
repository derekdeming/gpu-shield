# GPU Shield

GPU Shield is a comprehensive runtime security monitoring system for GPU workloads, providing real-time telemetry collection, integrity verification, and anomaly detection for GPU-accelerated applications.

## Features

- **Real-time GPU Telemetry**: Collect GPU memory utilization, temperature, power consumption, and performance metrics
- **Security Monitoring**: Integrity verification, anomaly detection, and access control monitoring
- **Kubernetes Native**: Deploy as DaemonSet with proper RBAC and security contexts
- **Multi-vendor Support**: NVIDIA (via nvidia-smi and DCGM), AMD (planned), Intel (planned)
- **Scalable Architecture**: Distributed sensor-collector-alert architecture
- **Standards Compliant**: Protobuf/gRPC APIs, Prometheus metrics, SBOM generation

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Sensor    │───▶│  Collector  │───▶│Alert Engine │
│ (DaemonSet) │    │ (Deployment)│    │(Deployment) │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   GPU Node  │    │  Telemetry  │    │   Alerts    │
│   Metrics   │    │  Database   │    │& Responses  │
└─────────────┘    └─────────────┘    └─────────────┘
```

## Current Implementation Status

### ✅ Completed
- **Protobuf Schemas**: Comprehensive telemetry and integrity message definitions
- **Sensor Implementation**: Functional GPU metrics collection using nvidia-smi
- **Helm Chart**: Complete Kubernetes deployment with DaemonSet, RBAC, and security contexts
- **CI/CD Pipeline**: GitHub Actions with linting, testing, security scanning, and SBOM generation
- **Build System**: Makefile with protobuf generation, building, and testing targets

### 🚧 In Progress
- **DCGM Integration**: Enhanced GPU metrics collection
- **Collector Service**: Telemetry aggregation and storage
- **Alert Engine**: Security event processing and response

### 📋 Planned
- **AMD GPU Support**: ROCm and rocprofiler integration
- **Intel GPU Support**: Level Zero and Intel GPU metrics
- **Advanced Security**: ML-based anomaly detection, behavioral analysis
- **Dashboard**: Grafana dashboards and visualization

## Quick Start

### Prerequisites
- Go 1.24.3+
- Protocol Buffers compiler (`protoc`)
- Kubernetes cluster with GPU nodes
- Helm 3.x
- NVIDIA drivers and nvidia-smi (for NVIDIA GPUs)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ShipKode/gpushield.git
   cd gpushield
   ```

2. **Install development tools**:
   ```bash
   make install-tools
   ```

3. **Generate protobuf stubs**:
   ```bash
   make proto
   ```

4. **Build the sensor**:
   ```bash
   make build-sensor
   ```

5. **Test the sensor locally** (requires nvidia-smi):
   ```bash
   ./bin/sensor --output=text --interval=10s
   ```

### Kubernetes Deployment

1. **Deploy with Helm**:
   ```bash
   helm install gpu-shield ./helm/gpu-runtime-security
   ```

2. **Check deployment status**:
   ```bash
   kubectl get daemonset -l app.kubernetes.io/name=gpu-runtime-security
   kubectl logs -l app.kubernetes.io/component=sensor
   ```

3. **View GPU metrics**:
   ```bash
   kubectl logs -l app.kubernetes.io/component=sensor -f
   ```

## Configuration

### Sensor Configuration

The sensor supports the following configuration options:

```bash
./bin/sensor --help
```

Key options:
- `--interval`: Collection interval (default: 30s)
- `--log-level`: Logging level (debug, info, warn, error)
- `--output`: Output format (json, text)
- `--use-dcgm`: Use DCGM instead of nvidia-smi
- `--node-id`: Node identifier (defaults to hostname)

### Helm Chart Values

Key configuration values in `helm/gpu-runtime-security/values.yaml`:

```yaml
sensor:
  interval: 30                    # Collection interval in seconds
  logLevel: info                  # Log level
  useDCGM: false                 # Use DCGM instead of nvidia-smi
  nodeSelector:
    accelerator: nvidia          # Target GPU nodes
  tolerations:
    - key: nvidia.com/gpu
      operator: Exists
      effect: NoSchedule
```

## Development

### Building

```bash
# Build all components
make build

# Build individual components
make build-sensor
make build-collector
make build-alert

# Generate protobuf stubs
make proto-go
make proto-python
```

### Testing

```bash
# Run Go tests
make test

# Run Python tests
make test-python

# Run linting
make lint
make lint-python
```

### Security Scanning

```bash
# Generate SBOM
make sbom

# Run security scans
make security-scan
```

## API Reference

### Telemetry API

The telemetry API is defined in `api/proto/telemetry.proto` and includes:

- **TelemetryData**: Complete GPU and system metrics
- **GPUMetrics**: Per-GPU device information
- **MemoryMetrics**: GPU memory utilization
- **PerformanceMetrics**: GPU performance counters
- **SecurityMetrics**: Security-related metrics

### Integrity API

The integrity API is defined in `api/proto/integrity.proto` and includes:

- **IntegrityReport**: Comprehensive security assessment
- **ComponentIntegrity**: Per-component integrity verification
- **SecurityEvent**: Security incidents and alerts
- **AttestationData**: Hardware-based attestation

## Monitoring and Observability

### Metrics

GPU Shield exposes Prometheus metrics for:
- GPU utilization and performance
- Memory usage and bandwidth
- Temperature and power consumption
- Security events and integrity status

### Logging

Structured JSON logging with configurable levels:
- **DEBUG**: Detailed execution information
- **INFO**: General operational information
- **WARN**: Warning conditions
- **ERROR**: Error conditions requiring attention

### Dashboards

Grafana dashboards are available for:
- GPU overview and performance
- Security events and alerts
- System health and status

## Security Considerations

### Privileged Access

The sensor runs with privileged access to:
- Access GPU devices and drivers
- Read system information from /proc and /sys
- Monitor container runtime sockets

### Network Security

- All communication uses gRPC with TLS
- RBAC controls limit Kubernetes API access
- Network policies can restrict traffic flow

### Data Protection

- Sensitive configuration stored in Kubernetes secrets
- Metrics data encrypted in transit
- Optional data retention policies

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the full test suite
6. Submit a pull request

### Code Style

- Go: Follow standard Go conventions, use `gofmt` and `golangci-lint`
- Python: Follow PEP 8, use `black` and `isort`
- Protobuf: Use consistent naming and documentation

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/ShipKode/gpushield/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ShipKode/gpushield/discussions)
- **Documentation**: [Project Wiki](https://github.com/ShipKode/gpushield/wiki)

## Roadmap

### v0.2.0
- Complete collector and alert engine implementation
- DCGM integration for enhanced metrics
- Basic anomaly detection

### v0.3.0
- AMD GPU support via ROCm
- Advanced security features
- Performance optimizations

### v1.0.0
- Production-ready release
- Full multi-vendor GPU support
- Comprehensive security monitoring
- Enterprise features
