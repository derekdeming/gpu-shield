# NVIDIA DCGM Integration

This package provides comprehensive NVIDIA GPU monitoring capabilities using NVIDIA's Data Center GPU Manager (DCGM).

## Overview

The NVIDIA DCGM adapter provides two integration modes:

1. **CLI Mode** (Default): Uses `dcgmi` command-line tools
2. **Native Mode** (Optional): Direct integration with DCGM C libraries via CGO

The adapter automatically detects the best available method and falls back gracefully.

## Features

### Supported Metrics

- **Basic GPU Information**
  - GPU name, UUID, device ID
  - PCI bus information
  
- **Memory Metrics**
  - Total, used, and free memory
  - Memory utilization percentage
  
- **Performance Metrics**
  - GPU utilization
  - SM, memory, and graphics clock speeds
  - PCIe throughput (RX/TX)
  - NVLink bandwidth
  
- **Thermal Metrics**
  - GPU temperature
  - Thermal throttling information
  
- **Power Metrics**
  - Current power usage
  - Power limits and management
  
- **Error Monitoring**
  - ECC error counts
  - Retired page counts
  
- **Process Information**
  - Running processes on each GPU
  - Per-process memory usage
  - Process types (compute/graphics)

## Installation

### Prerequisites

#### For CLI Mode (Recommended for Development)

1. **Install NVIDIA Drivers**
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install nvidia-driver-535  # or latest version
   
   # RHEL/CentOS
   sudo dnf install nvidia-driver
   ```

2. **Install DCGM**
   ```bash
   # Ubuntu/Debian
   sudo apt install datacenter-gpu-manager
   
   # RHEL/CentOS
   sudo dnf install datacenter-gpu-manager
   ```

3. **Start DCGM Service**
   ```bash
   sudo systemctl enable nvidia-dcgm
   sudo systemctl start nvidia-dcgm
   ```

#### For Native Mode (Production Recommended)

1. **Install DCGM Development Libraries**
   ```bash
   # Ubuntu/Debian
   sudo apt install datacenter-gpu-manager-dev libdcgm-dev
   
   # RHEL/CentOS
   sudo dnf install datacenter-gpu-manager-devel
   ```

2. **Build with Native Support**
   ```bash
   CGO_ENABLED=1 go build -tags dcgm ./cmd/sensor
   ```

## Usage

### Basic Usage

```go
package main

import (
    "context"
    "log"
    
    "github.com/ShipKode/gpushield/pkg/telemetry/adapters/nvidia"
    "github.com/sirupsen/logrus"
)

func main() {
    logger := logrus.New()
    
    // Create DCGM collector
    collector := nvidia.NewDCGMCollector(logger)
    
    // Check availability
    if !collector.IsAvailable() {
        log.Fatal("DCGM not available")
    }
    
    // Collect metrics
    ctx := context.Background()
    metrics, err := collector.CollectMetrics(ctx)
    if err != nil {
        log.Fatal(err)
    }
    
    // Process metrics
    for _, gpu := range metrics {
        log.Printf("GPU %d: %s, Temp: %.1f°C, Util: %.1f%%", 
            gpu.DeviceID, gpu.Name, gpu.Temperature, gpu.GPUUtilization)
    }
}
```

### Continuous Monitoring

```go
// Start monitoring with 5-second intervals
metricsChan, err := collector.StartMonitoring(ctx, 5*time.Second)
if err != nil {
    log.Fatal(err)
}

for metrics := range metricsChan {
    // Process each batch of metrics
    for _, gpu := range metrics {
        // Handle GPU metrics
    }
}
```

### Integration with GPU Shield Sensor

The DCGM collector integrates seamlessly with the GPU Shield sensor:

```go
// In cmd/sensor/main.go
func collectDCGMMetrics(ctx context.Context, metrics *GPUMemoryMetrics) (*GPUMemoryMetrics, error) {
    dcgmCollector := nvidia.NewDCGMCollector(logger)
    
    if !dcgmCollector.IsAvailable() {
        logger.Debug("DCGM not available, falling back to nvidia-smi")
        return collectNvidiaSMIMetrics(ctx, metrics)
    }
    
    dcgmMetrics, err := dcgmCollector.CollectMetrics(ctx)
    if err != nil {
        logger.WithError(err).Warn("DCGM collection failed")
        return collectNvidiaSMIMetrics(ctx, metrics)
    }
    
    // Convert and return metrics
    return convertDCGMMetrics(dcgmMetrics), nil
}
```

## Configuration

### Environment Variables

- `DCGM_HOST`: DCGM host address (default: localhost)
- `DCGM_PORT`: DCGM port (default: 5555)
- `DCGM_TIMEOUT`: Connection timeout in seconds (default: 30)

### Build Tags

- `dcgm`: Enable native DCGM integration
- `!dcgm`: Use CLI-only mode (default)

### Build Examples

```bash
# CLI mode only (default)
go build ./cmd/sensor

# Native DCGM integration
CGO_ENABLED=1 go build -tags dcgm ./cmd/sensor

# Cross-compilation for different architectures
GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -tags dcgm ./cmd/sensor
```

## Docker Integration

### Multi-stage Dockerfile

```dockerfile
# Build stage with DCGM libraries
FROM nvidia/cuda:12.0-devel-ubuntu22.04 AS builder

RUN apt-get update && apt-get install -y \
    datacenter-gpu-manager-dev \
    libdcgm-dev \
    golang-1.21

WORKDIR /app
COPY . .
RUN CGO_ENABLED=1 go build -tags dcgm -o sensor ./cmd/sensor

# Runtime stage
FROM nvidia/cuda:12.0-runtime-ubuntu22.04

RUN apt-get update && apt-get install -y \
    datacenter-gpu-manager

COPY --from=builder /app/sensor /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/sensor"]
```

### Docker Compose

```yaml
version: '3.8'
services:
  gpu-sensor:
    build: .
    runtime: nvidia
    environment:
      - NVIDIA_VISIBLE_DEVICES=all
      - NVIDIA_DRIVER_CAPABILITIES=utility,compute
    volumes:
      - /var/run/nvidia-dcgm:/var/run/nvidia-dcgm
    command: ["--use-dcgm", "--interval=10s"]
```

## Troubleshooting

### Common Issues

1. **DCGM Service Not Running**
   ```bash
   sudo systemctl status nvidia-dcgm
   sudo systemctl start nvidia-dcgm
   ```

2. **Permission Denied**
   ```bash
   # Add user to nvidia-dcgm group
   sudo usermod -a -G nvidia-dcgm $USER
   
   # Or run with sudo
   sudo ./sensor --use-dcgm
   ```

3. **Library Not Found**
   ```bash
   # Set library path
   export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH
   
   # Or install development packages
   sudo apt install libdcgm-dev
   ```

4. **CGO Build Failures**
   ```bash
   # Install build tools
   sudo apt install build-essential
   
   # Set CGO environment
   export CGO_ENABLED=1
   export CC=gcc
   ```

### Debug Mode

Enable debug logging to troubleshoot issues:

```go
logger := logrus.New()
logger.SetLevel(logrus.DebugLevel)

collector := nvidia.NewDCGMCollector(logger)
```

### Testing DCGM Connection

```bash
# Test DCGM CLI
dcgmi discovery -l

# Test DCGM service
dcgmi dmon -e DCGM_FI_DEV_GPU_UTIL -c 1

# Check DCGM version
dcgmi --version
```

## Performance Considerations

### CLI Mode vs Native Mode

| Aspect | CLI Mode | Native Mode |
|--------|----------|-------------|
| Performance | Slower (subprocess overhead) | Faster (direct API calls) |
| Memory Usage | Higher | Lower |
| Features | Limited to CLI capabilities | Full DCGM API access |
| Dependencies | dcgmi binary only | DCGM libraries + headers |
| Deployment | Easier | More complex |

### Optimization Tips

1. **Use Native Mode for Production**
   - Better performance and lower overhead
   - Access to advanced DCGM features
   - More reliable error handling

2. **Adjust Collection Intervals**
   ```go
   // For high-frequency monitoring
   collector.StartMonitoring(ctx, 1*time.Second)
   
   // For resource-conscious monitoring
   collector.StartMonitoring(ctx, 30*time.Second)
   ```

3. **Filter Metrics**
   ```go
   // Only collect essential metrics
   fields := []string{
       "DCGM_FI_DEV_GPU_UTIL",
       "DCGM_FI_DEV_GPU_TEMP",
       "DCGM_FI_DEV_POWER_USAGE",
   }
   ```

## Contributing

### Adding New Metrics

1. **Add Field ID**
   ```go
   const (
       DCGM_FI_DEV_NEW_METRIC DCGMFieldID = 999
   )
   ```

2. **Update Parser**
   ```go
   case "DCGM_FI_DEV_NEW_METRIC":
       if val, err := strconv.ParseFloat(value, 64); err == nil {
           metrics.NewMetric = val
       }
   ```

3. **Add to Field List**
   ```go
   fields := []string{
       "DCGM_FI_DEV_NEW_METRIC",
       // ... other fields
   }
   ```

### Testing

```bash
# Run unit tests
go test ./pkg/telemetry/adapters/nvidia/...

# Run integration tests (requires NVIDIA GPU)
go test -tags integration ./pkg/telemetry/adapters/nvidia/...

# Benchmark tests
go test -bench=. ./pkg/telemetry/adapters/nvidia/...
```

## License

This integration uses NVIDIA DCGM under the Apache 2.0 license. See [third_party/nvidia-dcgm/LICENSE](../../../third_party/nvidia-dcgm/LICENSE) for details.

## References

- [NVIDIA DCGM Documentation](https://docs.nvidia.com/datacenter/dcgm/)
- [DCGM API Reference](https://docs.nvidia.com/datacenter/dcgm/latest/dcgm-api/)
- [GPU Shield Documentation](../../../../docs/) 