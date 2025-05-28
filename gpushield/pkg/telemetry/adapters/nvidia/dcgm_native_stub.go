//go:build !dcgm
// +build !dcgm

package nvidia

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
)

// DCGMNativeCollectorStub is a stub implementation when DCGM native libraries are not available
type DCGMNativeCollectorStub struct {
	logger *logrus.Logger
}

// NewDCGMNativeCollector creates a stub native collector (returns nil when not available)
func NewDCGMNativeCollector(logger *logrus.Logger) DCGMNativeInterface {
	// Return nil to indicate native DCGM is not available
	return nil
}

// IsAvailable always returns false for the stub
func (d *DCGMNativeCollectorStub) IsAvailable() bool {
	return false
}

// CollectMetrics is not implemented in the stub
func (d *DCGMNativeCollectorStub) CollectMetrics(ctx context.Context) ([]GPUMetrics, error) {
	return nil, nil
}

// StartMonitoring is not implemented in the stub
func (d *DCGMNativeCollectorStub) StartMonitoring(ctx context.Context, interval time.Duration) (<-chan []GPUMetrics, error) {
	return nil, nil
}

// Cleanup is not implemented in the stub
func (d *DCGMNativeCollectorStub) Cleanup() {
	// No-op
}
