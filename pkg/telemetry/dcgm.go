package telemetry

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ShipKode/gpushield/pkg/telemetry/adapters/nvidia"
	"github.com/sirupsen/logrus"
)

// DCGMCollector provides enhanced GPU metrics collection using DCGM
type DCGMCollector struct {
	logger    *logrus.Logger
	collector *nvidia.DCGMCollector
}

// DCGMMetrics represents enhanced GPU metrics from DCGM
type DCGMMetrics struct {
	DeviceID int    `json:"device_id"`
	UUID     string `json:"uuid"`
	Name     string `json:"name"`

	// Memory metrics
	MemoryUsed  uint64 `json:"memory_used_mb"`
	MemoryTotal uint64 `json:"memory_total_mb"`
	MemoryFree  uint64 `json:"memory_free_mb"`

	// Utilization metrics
	GPUUtilization    float64 `json:"gpu_utilization_percent"`
	MemoryUtilization float64 `json:"memory_utilization_percent"`

	// Performance metrics
	SMClock       uint32 `json:"sm_clock_mhz"`
	MemoryClock   uint32 `json:"memory_clock_mhz"`
	GraphicsClock uint32 `json:"graphics_clock_mhz"`

	// Thermal metrics
	Temperature float64 `json:"temperature_celsius"`

	// Power metrics
	PowerUsage float64 `json:"power_usage_watts"`
	PowerLimit float64 `json:"power_limit_watts"`

	// Advanced metrics
	PCIeRxThroughput float64 `json:"pcie_rx_throughput_mbps"`
	PCIeTxThroughput float64 `json:"pcie_tx_throughput_mbps"`
	NVLinkBandwidth  float64 `json:"nvlink_bandwidth_mbps"`

	// Error counters
	ECCErrors    uint64 `json:"ecc_errors"`
	RetiredPages uint64 `json:"retired_pages"`

	// Process information
	Processes []DCGMProcess `json:"processes"`
}

// DCGMProcess represents a process using the GPU
type DCGMProcess struct {
	PID           uint32 `json:"pid"`
	Name          string `json:"name"`
	MemoryUsed    uint64 `json:"memory_used_mb"`
	Type          string `json:"type"`
	SMUtilization uint32 `json:"sm_utilization_percent"`
}

// NewDCGMCollector creates a new DCGM collector
func NewDCGMCollector(logger *logrus.Logger) *DCGMCollector {
	return &DCGMCollector{
		logger: logger,
	}
}

// IsAvailable checks if DCGM is available on the system
func (d *DCGMCollector) IsAvailable() bool {
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

// CollectMetrics collects GPU metrics using DCGM and returns them as GPUMetrics
func (d *DCGMCollector) CollectMetrics(ctx context.Context) ([]GPUMetrics, error) {
	dcgmMetrics, err := d.collectDCGMMetrics(ctx)
	if err != nil {
		return nil, err
	}

	// Convert DCGMMetrics to GPUMetrics
	var gpuMetrics []GPUMetrics
	for _, dcgm := range dcgmMetrics {
		gpu := GPUMetrics{
			DeviceID:          dcgm.DeviceID,
			UUID:              dcgm.UUID,
			Name:              dcgm.Name,
			Timestamp:         time.Now(),
			MemoryUsed:        dcgm.MemoryUsed,
			MemoryTotal:       dcgm.MemoryTotal,
			MemoryFree:        dcgm.MemoryFree,
			MemoryUtilization: dcgm.MemoryUtilization,
			GPUUtilization:    dcgm.GPUUtilization,
			SMClock:           dcgm.SMClock,
			MemoryClock:       dcgm.MemoryClock,
			GraphicsClock:     dcgm.GraphicsClock,
			Temperature:       dcgm.Temperature,
			PowerUsage:        dcgm.PowerUsage,
			PowerLimit:        dcgm.PowerLimit,
			PCIeRxThroughput:  dcgm.PCIeRxThroughput,
			PCIeTxThroughput:  dcgm.PCIeTxThroughput,
			NVLinkBandwidth:   dcgm.NVLinkBandwidth,
			ECCErrors:         dcgm.ECCErrors,
			RetiredPages:      dcgm.RetiredPages,
		}

		// Convert processes
		for _, proc := range dcgm.Processes {
			gpu.Processes = append(gpu.Processes, ProcessInfo{
				PID:           proc.PID,
				Name:          proc.Name,
				MemoryUsed:    proc.MemoryUsed,
				Type:          proc.Type,
				SMUtilization: proc.SMUtilization,
			})
		}

		gpuMetrics = append(gpuMetrics, gpu)
	}

	return gpuMetrics, nil
}

// collectDCGMMetrics collects GPU metrics using DCGM (internal method)
func (d *DCGMCollector) collectDCGMMetrics(ctx context.Context) ([]DCGMMetrics, error) {
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
func (d *DCGMCollector) getGPUList(ctx context.Context) ([]int, error) {
	cmd := exec.CommandContext(ctx, "dcgmi", "discovery", "-l")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dcgmi discovery failed: %w", err)
	}

	var gpuIDs []int
	lines := strings.Split(string(output), "\n")
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
func (d *DCGMCollector) collectGPUMetrics(ctx context.Context, gpuID int) (DCGMMetrics, error) {
	metrics := DCGMMetrics{DeviceID: gpuID}

	// Collect basic GPU info
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
func (d *DCGMCollector) collectGPUInfo(ctx context.Context, gpuID int, metrics *DCGMMetrics) error {
	// Get GPU attributes
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

	// Calculate derived metrics
	if metrics.MemoryTotal > 0 {
		metrics.MemoryFree = metrics.MemoryTotal - metrics.MemoryUsed
		if metrics.MemoryUsed > 0 {
			metrics.MemoryUtilization = float64(metrics.MemoryUsed) / float64(metrics.MemoryTotal) * 100
		}
	}

	return nil
}

// collectPerformanceMetrics collects advanced performance metrics
func (d *DCGMCollector) collectPerformanceMetrics(ctx context.Context, gpuID int, metrics *DCGMMetrics) error {
	perfFields := []string{
		"DCGM_FI_DEV_SM_CLOCK",
		"DCGM_FI_DEV_MEM_CLOCK",
		"DCGM_FI_DEV_GRAPHICS_CLOCK",
		"DCGM_FI_DEV_PCIE_RX_THROUGHPUT",
		"DCGM_FI_DEV_PCIE_TX_THROUGHPUT",
		"DCGM_FI_DEV_NVLINK_BANDWIDTH_TOTAL",
		"DCGM_FI_DEV_ECC_SBE_VOL_TOTAL",
		"DCGM_FI_DEV_RETIRED_SBE",
	}

	for _, field := range perfFields {
		value, err := d.getFieldValue(ctx, gpuID, field)
		if err != nil {
			continue
		}
		d.parseFieldValue(field, value, metrics)
	}

	return nil
}

// collectProcessInfo collects information about processes using the GPU
func (d *DCGMCollector) collectProcessInfo(ctx context.Context, gpuID int, metrics *DCGMMetrics) error {
	cmd := exec.CommandContext(ctx, "dcgmi", "stats", "-g", strconv.Itoa(gpuID), "-p")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get process stats: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "PID") && strings.Contains(line, "Name") {
			continue // Skip header
		}

		if process := d.parseProcessLine(line); process.PID != 0 {
			metrics.Processes = append(metrics.Processes, process)
		}
	}

	return nil
}

// getFieldValue gets a specific field value from DCGM
func (d *DCGMCollector) getFieldValue(ctx context.Context, gpuID int, field string) (string, error) {
	cmd := exec.CommandContext(ctx, "dcgmi", "dmon", "-e", field, "-i", strconv.Itoa(gpuID), "-c", "1")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("dcgmi dmon failed: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, field) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[len(parts)-1], nil
			}
		}
	}

	return "", fmt.Errorf("field value not found")
}

// parseFieldValue parses a field value and updates metrics
func (d *DCGMCollector) parseFieldValue(field, value string, metrics *DCGMMetrics) {
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
			metrics.PowerUsage = val / 1000 // Convert mW to W
		}
	case "DCGM_FI_DEV_POWER_MGMT_LIMIT":
		if val, err := strconv.ParseFloat(value, 64); err == nil {
			metrics.PowerLimit = val / 1000 // Convert mW to W
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
	}
}

// parseProcessLine parses a process information line
func (d *DCGMCollector) parseProcessLine(line string) DCGMProcess {
	// Expected format: "PID: 1234, Name: python, Memory: 1024 MB, Type: C"
	process := DCGMProcess{}

	parts := strings.Split(line, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "PID:") {
			if pid, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(part, "PID:")), 10, 32); err == nil {
				process.PID = uint32(pid)
			}
		} else if strings.HasPrefix(part, "Name:") {
			process.Name = strings.TrimSpace(strings.TrimPrefix(part, "Name:"))
		} else if strings.HasPrefix(part, "Memory:") {
			memStr := strings.TrimSpace(strings.TrimPrefix(part, "Memory:"))
			memStr = strings.TrimSuffix(memStr, " MB")
			if mem, err := strconv.ParseUint(memStr, 10, 64); err == nil {
				process.MemoryUsed = mem
			}
		} else if strings.HasPrefix(part, "Type:") {
			process.Type = strings.TrimSpace(strings.TrimPrefix(part, "Type:"))
		}
	}

	return process
}

// StartMonitoring starts continuous DCGM monitoring
func (d *DCGMCollector) StartMonitoring(ctx context.Context, interval time.Duration) (<-chan []GPUMetrics, error) {
	metricsChan := make(chan []GPUMetrics, 10)

	go func() {
		defer close(metricsChan)
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
				case metricsChan <- metrics:
				case <-ctx.Done():
					return
				default:
					d.logger.Warn("Metrics channel full, dropping metrics")
				}
			}
		}
	}()

	return metricsChan, nil
}
