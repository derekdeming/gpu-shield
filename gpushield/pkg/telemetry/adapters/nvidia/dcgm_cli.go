package nvidia

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// DCGMCLICollector provides DCGM integration via command-line interface
type DCGMCLICollector struct {
	logger *logrus.Logger
}

// NewDCGMCLICollector creates a new CLI-based DCGM collector
func NewDCGMCLICollector(logger *logrus.Logger) *DCGMCLICollector {
	return &DCGMCLICollector{
		logger: logger,
	}
}

// IsAvailable checks if DCGM CLI tools are available
func (d *DCGMCLICollector) IsAvailable() bool {
	// Check if dcgmi command is available
	if _, err := exec.LookPath("dcgmi"); err != nil {
		d.logger.Debug("dcgmi command not found")
		return false
	}

	// Test DCGM connection
	cmd := exec.Command("dcgmi", "discovery", "-l")
	if err := cmd.Run(); err != nil {
		d.logger.WithError(err).Debug("DCGM discovery failed")
		return false
	}

	return true
}

// CollectMetrics collects GPU metrics using DCGM CLI
func (d *DCGMCLICollector) CollectMetrics(ctx context.Context) ([]GPUMetrics, error) {
	dcgmMetrics, err := d.collectDCGMMetrics(ctx)
	if err != nil {
		return nil, err
	}

	// Convert DCGM metrics to standard GPU metrics
	var gpuMetrics []GPUMetrics
	for _, dcgm := range dcgmMetrics {
		gpu := dcgm.ConvertToGPUMetrics()
		gpuMetrics = append(gpuMetrics, gpu)
	}

	return gpuMetrics, nil
}

// StartMonitoring starts continuous monitoring using CLI
func (d *DCGMCLICollector) StartMonitoring(ctx context.Context, interval time.Duration) (<-chan []GPUMetrics, error) {
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
					d.logger.WithError(err).Error("Failed to collect DCGM CLI metrics")
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

// collectDCGMMetrics collects GPU metrics using DCGM CLI (internal method)
func (d *DCGMCLICollector) collectDCGMMetrics(ctx context.Context) ([]DCGMMetrics, error) {
	// Get list of GPUs
	gpuList, err := d.getGPUList(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get GPU list: %w", err)
	}

	var metrics []DCGMMetrics
	for _, gpuID := range gpuList {
		gpuMetrics, err := d.collectGPUMetrics(ctx, gpuID)
		if err != nil {
			d.logger.WithError(err).WithField("gpu_id", gpuID).Error("Failed to collect GPU metrics")
			continue
		}
		metrics = append(metrics, gpuMetrics)
	}

	return metrics, nil
}

// getGPUList gets the list of available GPUs
func (d *DCGMCLICollector) getGPUList(ctx context.Context) ([]int, error) {
	cmd := exec.CommandContext(ctx, "dcgmi", "discovery", "-l")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dcgmi discovery failed: %w", err)
	}

	var gpuIDs []int
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "GPU ") {
			// Parse "GPU 0: Tesla V100-SXM2-32GB (UUID: GPU-...)"
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				gpuIDStr := strings.TrimSpace(strings.TrimPrefix(parts[0], "GPU "))
				if gpuID, err := strconv.Atoi(gpuIDStr); err == nil {
					gpuIDs = append(gpuIDs, gpuID)
				}
			}
		}
	}

	return gpuIDs, nil
}

// collectGPUMetrics collects metrics for a specific GPU
func (d *DCGMCLICollector) collectGPUMetrics(ctx context.Context, gpuID int) (DCGMMetrics, error) {
	metrics := DCGMMetrics{DeviceID: gpuID}

	// Collect basic GPU information
	if err := d.collectGPUInfo(ctx, gpuID, &metrics); err != nil {
		return metrics, fmt.Errorf("failed to collect GPU info: %w", err)
	}

	// Collect performance metrics
	if err := d.collectPerformanceMetrics(ctx, gpuID, &metrics); err != nil {
		d.logger.WithError(err).Warn("Failed to collect performance metrics")
	}

	// Collect process information
	if err := d.collectProcessInfo(ctx, gpuID, &metrics); err != nil {
		d.logger.WithError(err).Warn("Failed to collect process info")
	}

	return metrics, nil
}

// collectGPUInfo collects basic GPU information
func (d *DCGMCLICollector) collectGPUInfo(ctx context.Context, gpuID int, metrics *DCGMMetrics) error {
	fields := []string{
		"DCGM_FI_DEV_NAME",
		"DCGM_FI_DEV_UUID",
		"DCGM_FI_DEV_MEM_COPY_UTIL",
		"DCGM_FI_DEV_GPU_UTIL",
		"DCGM_FI_DEV_FB_USED",
		"DCGM_FI_DEV_FB_TOTAL",
		"DCGM_FI_DEV_GPU_TEMP",
		"DCGM_FI_DEV_POWER_USAGE",
		"DCGM_FI_DEV_POWER_MGMT_LIMIT",
	}

	for _, field := range fields {
		value, err := d.getFieldValue(ctx, gpuID, field)
		if err != nil {
			d.logger.WithError(err).WithFields(logrus.Fields{
				"gpu_id": gpuID,
				"field":  field,
			}).Debug("Failed to get field value")
			continue
		}

		d.parseFieldValue(field, value, metrics)
	}

	// Calculate memory free
	if metrics.MemoryTotal > 0 && metrics.MemoryUsed > 0 {
		metrics.MemoryFree = metrics.MemoryTotal - metrics.MemoryUsed
	}

	return nil
}

// collectPerformanceMetrics collects performance-related metrics
func (d *DCGMCLICollector) collectPerformanceMetrics(ctx context.Context, gpuID int, metrics *DCGMMetrics) error {
	fields := []string{
		"DCGM_FI_DEV_SM_CLOCK",
		"DCGM_FI_DEV_MEM_CLOCK",
		"DCGM_FI_DEV_GRAPHICS_CLOCK",
		"DCGM_FI_DEV_PCIE_RX_THROUGHPUT",
		"DCGM_FI_DEV_PCIE_TX_THROUGHPUT",
		"DCGM_FI_DEV_NVLINK_BANDWIDTH_TOTAL",
		"DCGM_FI_DEV_ECC_SBE_VOL_TOTAL",
		"DCGM_FI_DEV_RETIRED_SBE",
	}

	for _, field := range fields {
		value, err := d.getFieldValue(ctx, gpuID, field)
		if err != nil {
			continue
		}
		d.parseFieldValue(field, value, metrics)
	}

	return nil
}

// collectProcessInfo collects process information for the GPU
func (d *DCGMCLICollector) collectProcessInfo(ctx context.Context, gpuID int, metrics *DCGMMetrics) error {
	cmd := exec.CommandContext(ctx, "dcgmi", "stats", "-g", strconv.Itoa(gpuID), "-p")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("dcgmi stats failed: %w", err)
	}

	// Parse process information from output
	// This is a simplified parser - in practice, you'd need more robust parsing
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "PID") && strings.Contains(line, "Process") {
			// Parse process line
			// Format: PID: 1234, Process: python, Memory: 1024 MB
			// This would need proper parsing based on actual dcgmi output format
		}
	}

	return nil
}

// getFieldValue gets a specific field value from DCGM
func (d *DCGMCLICollector) getFieldValue(ctx context.Context, gpuID int, field string) (string, error) {
	cmd := exec.CommandContext(ctx, "dcgmi", "dmon", "-e", field, "-i", strconv.Itoa(gpuID), "-c", "1")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("dcgmi dmon failed: %w", err)
	}

	// Parse the output to extract the field value
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) >= 2 {
		// Skip header line, get data line
		dataLine := strings.TrimSpace(lines[len(lines)-1])
		fields := strings.Fields(dataLine)
		if len(fields) >= 2 {
			return fields[1], nil // Field value is typically in the second column
		}
	}

	return "", fmt.Errorf("failed to parse field value from output")
}

// parseFieldValue parses a field value and updates the metrics structure
func (d *DCGMCLICollector) parseFieldValue(field, value string, metrics *DCGMMetrics) {
	switch field {
	case "DCGM_FI_DEV_NAME":
		metrics.Name = value
	case "DCGM_FI_DEV_UUID":
		metrics.UUID = value
	case "DCGM_FI_DEV_GPU_UTIL":
		if val, err := strconv.ParseFloat(value, 64); err == nil {
			metrics.GPUUtilization = val
		}
	case "DCGM_FI_DEV_FB_USED":
		if val, err := strconv.ParseUint(value, 10, 64); err == nil {
			metrics.MemoryUsed = val / (1024 * 1024) // Convert to MB
		}
	case "DCGM_FI_DEV_FB_TOTAL":
		if val, err := strconv.ParseUint(value, 10, 64); err == nil {
			metrics.MemoryTotal = val / (1024 * 1024) // Convert to MB
		}
	case "DCGM_FI_DEV_GPU_TEMP":
		if val, err := strconv.ParseFloat(value, 64); err == nil {
			metrics.Temperature = val
		}
	case "DCGM_FI_DEV_POWER_USAGE":
		if val, err := strconv.ParseFloat(value, 64); err == nil {
			metrics.PowerUsage = val
		}
	case "DCGM_FI_DEV_POWER_MGMT_LIMIT":
		if val, err := strconv.ParseFloat(value, 64); err == nil {
			metrics.PowerLimit = val
		}
	case "DCGM_FI_DEV_SM_CLOCK":
		if val, err := strconv.ParseUint(value, 10, 32); err == nil {
			metrics.SMClock = uint32(val)
		}
	case "DCGM_FI_DEV_MEM_CLOCK":
		if val, err := strconv.ParseUint(value, 10, 32); err == nil {
			metrics.MemoryClock = uint32(val)
		}
	case "DCGM_FI_DEV_GRAPHICS_CLOCK":
		if val, err := strconv.ParseUint(value, 10, 32); err == nil {
			metrics.GraphicsClock = uint32(val)
		}
	case "DCGM_FI_DEV_PCIE_RX_THROUGHPUT":
		if val, err := strconv.ParseFloat(value, 64); err == nil {
			metrics.PCIeRxThroughput = val
		}
	case "DCGM_FI_DEV_PCIE_TX_THROUGHPUT":
		if val, err := strconv.ParseFloat(value, 64); err == nil {
			metrics.PCIeTxThroughput = val
		}
	case "DCGM_FI_DEV_NVLINK_BANDWIDTH_TOTAL":
		if val, err := strconv.ParseFloat(value, 64); err == nil {
			metrics.NVLinkBandwidth = val
		}
	case "DCGM_FI_DEV_ECC_SBE_VOL_TOTAL":
		if val, err := strconv.ParseUint(value, 10, 64); err == nil {
			metrics.ECCErrors = val
		}
	case "DCGM_FI_DEV_RETIRED_SBE":
		if val, err := strconv.ParseUint(value, 10, 64); err == nil {
			metrics.RetiredPages = val
		}
	case "DCGM_FI_DEV_MEM_COPY_UTIL":
		if val, err := strconv.ParseFloat(value, 64); err == nil {
			metrics.MemoryUtilization = val
		}
	}
}

// GetSupportedFields returns the list of DCGM fields supported by CLI collector
func (d *DCGMCLICollector) GetSupportedFields() []string {
	return []string{
		"DCGM_FI_DEV_NAME",
		"DCGM_FI_DEV_UUID",
		"DCGM_FI_DEV_MEM_COPY_UTIL",
		"DCGM_FI_DEV_GPU_UTIL",
		"DCGM_FI_DEV_FB_USED",
		"DCGM_FI_DEV_FB_TOTAL",
		"DCGM_FI_DEV_GPU_TEMP",
		"DCGM_FI_DEV_POWER_USAGE",
		"DCGM_FI_DEV_POWER_MGMT_LIMIT",
		"DCGM_FI_DEV_SM_CLOCK",
		"DCGM_FI_DEV_MEM_CLOCK",
		"DCGM_FI_DEV_GRAPHICS_CLOCK",
		"DCGM_FI_DEV_PCIE_RX_THROUGHPUT",
		"DCGM_FI_DEV_PCIE_TX_THROUGHPUT",
		"DCGM_FI_DEV_NVLINK_BANDWIDTH_TOTAL",
		"DCGM_FI_DEV_ECC_SBE_VOL_TOTAL",
		"DCGM_FI_DEV_RETIRED_SBE",
	}
}

// TestConnection tests the DCGM connection
func (d *DCGMCLICollector) TestConnection(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "dcgmi", "discovery", "-l")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("DCGM connection test failed: %w", err)
	}

	if !strings.Contains(string(output), "GPU") {
		return fmt.Errorf("no GPUs found in DCGM discovery output")
	}

	return nil
}
