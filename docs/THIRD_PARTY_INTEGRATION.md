# Third-Party Integration Guide

## Overview

GPUShield integrates with several open-source third-party packages to provide comprehensive GPU monitoring and security capabilities. This document outlines our integration strategy, current implementation status, and licensing compliance.

## Third-Party Packages

### 1. NVIDIA DCGM (Data Center GPU Manager)
- **License**: Apache 2.0
- **Purpose**: Advanced NVIDIA GPU monitoring and management
- **Repository**: https://github.com/NVIDIA/DCGM
- **Integration Status**: ⚠️ **Partial** (CLI-based only)

#### Current Implementation
```go
// Current: Command-line interface only
cmd := exec.Command("dcgmi", "discovery", "-l")
```

#### Recommended Implementation
```go
// Recommended: Native C library integration via CGO
/*
#cgo LDFLAGS: -ldcgm
#include <dcgm_agent.h>
*/
import "C"

func (d *DCGMNativeCollector) CollectMetrics() {
    result := C.dcgmInit()
    // Direct library calls for better performance and features
}
```

#### Benefits of Native Integration
- **Performance**: Direct library calls vs subprocess overhead
- **Features**: Access to advanced DCGM APIs not available via CLI
- **Reliability**: Better error handling and connection management
- **Real-time**: Streaming metrics vs polling

### 2. Meta Dynolog
- **License**: MIT
- **Purpose**: Continuous GPU monitoring and PyTorch profiling
- **Repository**: https://github.com/facebookincubator/dynolog
- **Integration Status**: ❌ **Not Integrated**

#### Potential Integration Points
1. **GPU Monitoring**: Leverage Dynolog's DCGM integration
2. **PyTorch Profiling**: On-demand profiling for ML workloads
3. **System Metrics**: CPU, memory, and network monitoring
4. **Distributed Tracing**: Multi-node profiling coordination

#### Implementation Strategy
```go
// Option 1: Embed Dynolog as a library
import "github.com/facebookincubator/dynolog/dynolog"

// Option 2: Interface with Dynolog daemon
type DynologCollector struct {
    client *dynolog.Client
}
```

### 3. ROCm ROCProfiler Compute
- **License**: MIT
- **Purpose**: AMD GPU profiling and performance analysis
- **Repository**: https://github.com/ROCm/rocprofiler-compute
- **Integration Status**: ✅ **Implemented** (Basic)

#### Current Implementation
- ROCm SMI integration for basic metrics
- ROCProfiler Compute for advanced profiling
- Support for AMD GPU monitoring

## License Compliance

### ✅ Current Compliance Status

Our project properly handles third-party licenses:

1. **Main License File**: Apache 2.0 with third-party attribution
2. **Individual Licenses**: Each package retains its original license
3. **Attribution**: Proper attribution in main LICENSE file

```
### Third-party components
This project incorporates code under the following licenses:
- NVIDIA DCGM – Apache-2.0 – see `third_party/nvidia-dcgm/LICENSE`
- ROCm rocprofiler-compute – MIT – see `third_party/rocprofiler-compute/LICENSE`
- Meta Dynolog – MIT – see `third_party/dynolog/LICENSE`
```

### License Compatibility Matrix

| Package | License | Compatible with Apache 2.0 | Notes |
|---------|---------|----------------------------|-------|
| NVIDIA DCGM | Apache 2.0 | ✅ Yes | Same license |
| Meta Dynolog | MIT | ✅ Yes | MIT is compatible |
| ROCProfiler Compute | MIT | ✅ Yes | MIT is compatible |

## Integration Roadmap

### Phase 1: Enhanced DCGM Integration (Priority: High)
- [ ] Implement native DCGM library integration via CGO
- [ ] Add support for advanced DCGM features:
  - [ ] Field groups and watching
  - [ ] Health monitoring
  - [ ] Policy management
  - [ ] Profiling metrics
- [ ] Create Docker images with DCGM libraries
- [ ] Add comprehensive error handling

### Phase 2: Dynolog Integration (Priority: Medium)
- [ ] Evaluate integration approaches:
  - [ ] Library embedding
  - [ ] Daemon communication
  - [ ] Hybrid approach
- [ ] Implement PyTorch profiling capabilities
- [ ] Add distributed tracing support
- [ ] Integrate system-level monitoring

### Phase 3: Advanced ROCm Integration (Priority: Medium)
- [ ] Enhance ROCProfiler Compute integration
- [ ] Add support for ROCm profiling APIs
- [ ] Implement AMD GPU security monitoring
- [ ] Add ROCm-specific anomaly detection

### Phase 4: Cross-Platform Optimization (Priority: Low)
- [ ] Unified GPU abstraction layer
- [ ] Vendor-agnostic security policies
- [ ] Performance optimization across vendors

## Build System Integration

### Current Build Configuration

```makefile
# Makefile targets for third-party integration
build-with-dcgm:
	CGO_ENABLED=1 go build -tags dcgm ./cmd/sensor

build-with-rocm:
	CGO_ENABLED=1 go build -tags rocm ./cmd/sensor

build-with-dynolog:
	CGO_ENABLED=1 go build -tags dynolog ./cmd/sensor
```

### Docker Integration

```dockerfile
# Multi-stage build with third-party libraries
FROM nvidia/cuda:12.0-devel-ubuntu22.04 AS dcgm-builder
RUN apt-get update && apt-get install -y \
    datacenter-gpu-manager-dev \
    libdcgm-dev

FROM rocm/dev-ubuntu-22.04 AS rocm-builder
RUN apt-get update && apt-get install -y \
    rocm-smi-lib \
    rocprofiler-compute

# Final image with all GPU vendor support
FROM ubuntu:22.04
COPY --from=dcgm-builder /usr/lib/x86_64-linux-gnu/libdcgm.so* /usr/lib/
COPY --from=rocm-builder /opt/rocm /opt/rocm
```

## Development Guidelines

### Adding New Third-Party Integrations

1. **License Review**
   - Verify license compatibility with Apache 2.0
   - Add license attribution to main LICENSE file
   - Include original license file in `third_party/`

2. **Integration Pattern**
   ```go
   // Create adapter in pkg/telemetry/adapters/vendor/
   type VendorCollector struct {
       logger *logrus.Logger
       // vendor-specific fields
   }
   
   func (v *VendorCollector) IsAvailable() bool { /* ... */ }
   func (v *VendorCollector) CollectMetrics(ctx context.Context) ([]telemetry.GPUMetrics, error) { /* ... */ }
   ```

3. **Build Tags**
   ```go
   //go:build vendor_name
   // +build vendor_name
   
   package vendor
   ```

4. **Testing**
   - Unit tests with mocked vendor APIs
   - Integration tests with real hardware
   - CI/CD pipeline updates

### Code Organization

```
pkg/telemetry/adapters/
├── nvidia/
│   ├── dcgm_cli.go      # Current CLI-based implementation
│   ├── dcgm_native.go   # Native library integration
│   └── dcgm_test.go
├── amd/
│   ├── rocm_collector.go
│   ├── rocprof_collector.go
│   └── rocm_test.go
├── meta/
│   ├── dynolog_collector.go
│   └── dynolog_test.go
└── common/
    ├── interfaces.go
    └── utils.go
```

## Security Considerations

### Third-Party Code Security

1. **Dependency Scanning**
   - Regular security scans of third-party packages
   - Automated vulnerability detection
   - Update policies for security patches

2. **Sandboxing**
   - Isolate third-party code execution
   - Limit system access and permissions
   - Monitor resource usage

3. **Validation**
   - Input validation for all third-party APIs
   - Output sanitization
   - Error handling and logging

### License Compliance Monitoring

1. **Automated Checks**
   ```bash
   # Add to CI/CD pipeline
   make license-check
   make sbom-generate
   ```

2. **Regular Audits**
   - Quarterly license compliance reviews
   - Update attribution as packages evolve
   - Monitor for license changes in dependencies

## Troubleshooting

### Common Integration Issues

1. **DCGM Library Not Found**
   ```bash
   # Install DCGM development packages
   sudo apt-get install datacenter-gpu-manager-dev
   
   # Set library path
   export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH
   ```

2. **ROCm Tools Missing**
   ```bash
   # Install ROCm
   sudo apt-get install rocm-smi-lib rocprofiler-compute
   
   # Add to PATH
   export PATH=/opt/rocm/bin:$PATH
   ```

3. **CGO Build Failures**
   ```bash
   # Enable CGO and set compiler
   export CGO_ENABLED=1
   export CC=gcc
   
   # Install build dependencies
   sudo apt-get install build-essential
   ```

## Contributing

When contributing third-party integrations:

1. **License Compliance**
   - Verify license compatibility
   - Update LICENSE file with attribution
   - Include original license files

2. **Code Quality**
   - Follow existing adapter patterns
   - Add comprehensive tests
   - Document integration approach

3. **Documentation**
   - Update this guide
   - Add usage examples
   - Document configuration options

## References

- [NVIDIA DCGM Documentation](https://docs.nvidia.com/datacenter/dcgm/)
- [Meta Dynolog Documentation](https://github.com/facebookincubator/dynolog/tree/main/docs)
- [ROCm Documentation](https://rocm.docs.amd.com/)
- [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0)
- [MIT License](https://opensource.org/licenses/MIT) 