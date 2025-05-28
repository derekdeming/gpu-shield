//go:build dcgm
// +build dcgm

package nvidia

/*
#cgo LDFLAGS: -ldcgm
#include <dcgm_agent.h>
#include <dcgm_structs.h>
#include <stdlib.h>

// Helper function to convert Go string to C string
char* goStringToCString(char* str) {
    return str;
}
*/
import "C"

import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
)

// DCGMNativeCollector provides native DCGM integration using C libraries
type DCGMNativeCollector struct {
	logger      *logrus.Logger
	handle      C.dcgmHandle_t
	groupId     C.dcgmGpuGrp_t
	fieldGroup  C.dcgmFieldGrp_t
	initialized bool
}

// NewDCGMNativeCollector creates a new native DCGM collector
func NewDCGMNativeCollector(logger *logrus.Logger) DCGMNativeInterface {
	return &DCGMNativeCollector{
		logger: logger,
	}
}

// IsAvailable checks if DCGM is available on the system
func (d *DCGMNativeCollector) IsAvailable() bool {
	// Initialize DCGM
	result := C.dcgmInit()
	if result != C.DCGM_ST_OK {
		d.logger.WithField("dcgm_error", int(result)).Debug("DCGM initialization failed")
		return false
	}

	// Try to start embedded mode
	result = C.dcgmStartEmbedded(C.DCGM_OPERATION_MODE_AUTO, &d.handle)
	if result != C.DCGM_ST_OK {
		d.logger.WithField("dcgm_error", int(result)).Debug("DCGM embedded mode failed")
		C.dcgmShutdown()
		return false
	}

	d.initialized = true
	return true
}

// CollectMetrics collects GPU metrics using native DCGM
func (d *DCGMNativeCollector) CollectMetrics(ctx context.Context) ([]GPUMetrics, error) {
	if !d.initialized {
		if !d.IsAvailable() {
			return nil, fmt.Errorf("DCGM not available")
		}
	}

	// Create GPU group for all GPUs
	if err := d.createGPUGroup(); err != nil {
		return nil, fmt.Errorf("failed to create GPU group: %w", err)
	}

	// Create field group for metrics we want to collect
	if err := d.createFieldGroup(); err != nil {
		return nil, fmt.Errorf("failed to create field group: %w", err)
	}

	// Start watching fields
	if err := d.startWatching(); err != nil {
		return nil, fmt.Errorf("failed to start watching: %w", err)
	}

	// Wait a bit for data collection
	time.Sleep(100 * time.Millisecond)

	// Get latest values
	return d.getLatestValues()
}

func (d *DCGMNativeCollector) createGPUGroup() error {
	// Create a group with all GPUs
	groupName := C.CString("all_gpus")
	defer C.free(unsafe.Pointer(groupName))

	result := C.dcgmGroupCreate(d.handle, C.DCGM_GROUP_DEFAULT, groupName, &d.groupId)
	if result != C.DCGM_ST_OK {
		return fmt.Errorf("dcgmGroupCreate failed: %d", int(result))
	}
	return nil
}

func (d *DCGMNativeCollector) createFieldGroup() error {
	// Create field group
	fieldGroupName := C.CString("gpu_metrics")
	defer C.free(unsafe.Pointer(fieldGroupName))

	result := C.dcgmFieldGroupCreate(d.handle, C.int(10), fieldGroupName, &d.fieldGroup)
	if result != C.DCGM_ST_OK {
		return fmt.Errorf("dcgmFieldGroupCreate failed: %d", int(result))
	}

	// Add fields we want to monitor
	fields := []C.ushort{
		C.DCGM_FI_DEV_NAME,
		C.DCGM_FI_DEV_UUID,
		C.DCGM_FI_DEV_MEM_COPY_UTIL,
		C.DCGM_FI_DEV_GPU_UTIL,
		C.DCGM_FI_DEV_FB_USED,
		C.DCGM_FI_DEV_FB_TOTAL,
		C.DCGM_FI_DEV_GPU_TEMP,
		C.DCGM_FI_DEV_POWER_USAGE,
		C.DCGM_FI_DEV_SM_CLOCK,
		C.DCGM_FI_DEV_MEM_CLOCK,
	}

	for _, field := range fields {
		result := C.dcgmFieldGroupAddField(d.handle, d.fieldGroup, field)
		if result != C.DCGM_ST_OK {
			d.logger.WithFields(logrus.Fields{
				"field": int(field),
				"error": int(result),
			}).Warn("Failed to add field to group")
		}
	}

	return nil
}

func (d *DCGMNativeCollector) startWatching() error {
	updateFreq := C.longlong(1000000) // 1 second in microseconds
	maxKeepAge := C.double(3600.0)    // 1 hour
	maxKeepSamples := C.int(0)        // Use maxKeepAge instead

	result := C.dcgmWatchFields(d.handle, d.groupId, d.fieldGroup, updateFreq, maxKeepAge, maxKeepSamples)
	if result != C.DCGM_ST_OK {
		return fmt.Errorf("dcgmWatchFields failed: %d", int(result))
	}

	return nil
}

func (d *DCGMNativeCollector) getLatestValues() ([]GPUMetrics, error) {
	// This is a simplified implementation
	// In practice, you'd use dcgmGetLatestValues or dcgmGetMultipleLatestLiveSamples
	// to get the actual metric values and convert them to GPUMetrics

	var metrics []GPUMetrics

	// For now, return a placeholder metric to demonstrate the integration
	// This would need proper implementation of dcgmGetLatestValues and value parsing
	placeholder := GPUMetrics{
		DeviceID:    0,
		Name:        "Native DCGM GPU",
		UUID:        "GPU-native-dcgm-placeholder",
		Timestamp:   time.Now(),
		Temperature: 65.0,
		PowerUsage:  150.0,
		Metadata: map[string]interface{}{
			"collector":   "dcgm-native",
			"placeholder": true,
		},
	}

	metrics = append(metrics, placeholder)

	return metrics, nil
}

// StartMonitoring starts continuous monitoring
func (d *DCGMNativeCollector) StartMonitoring(ctx context.Context, interval time.Duration) (<-chan []GPUMetrics, error) {
	resultChan := make(chan []GPUMetrics, 10)

	go func() {
		defer close(resultChan)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				metrics, err := d.CollectMetrics(ctx)
				if err != nil {
					d.logger.WithError(err).Error("Failed to collect DCGM metrics")
					continue
				}

				select {
				case resultChan <- metrics:
				case <-ctx.Done():
					return
				default:
					d.logger.Warn("Metrics channel full, dropping metrics")
				}
			}
		}
	}()

	return resultChan, nil
}

// Cleanup cleans up DCGM resources
func (d *DCGMNativeCollector) Cleanup() {
	if d.initialized {
		if d.fieldGroup != 0 {
			C.dcgmFieldGroupDestroy(d.handle, d.fieldGroup)
		}
		if d.groupId != 0 {
			C.dcgmGroupDestroy(d.handle, d.groupId)
		}
		C.dcgmStopEmbedded(d.handle)
		C.dcgmShutdown()
		d.initialized = false
	}
}
