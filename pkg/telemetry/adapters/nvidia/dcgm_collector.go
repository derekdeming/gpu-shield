package nvidia

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
)

// GPUMetrics represents comprehensive GPU metrics
type GPUMetrics struct {
	DeviceID          int                    `json:"device_id"`
	UUID              string                 `json:"uuid"`
	Name              string                 `json:"name"`
	PCIBusID          string                 `json:"pci_bus_id,omitempty"`
	Timestamp         time.Time              `json:"timestamp"`
	MemoryUsed        uint64                 `json:"memory_used_mb"`
	MemoryTotal       uint64                 `json:"memory_total_mb"`
	MemoryFree        uint64                 `json:"memory_free_mb"`
	MemoryUtilization float64                `json:"memory_utilization_percent"`
	GPUUtilization    float64                `json:"gpu_utilization_percent"`
	SMClock           uint32                 `json:"sm_clock_mhz,omitempty"`
	MemoryClock       uint32                 `json:"memory_clock_mhz,omitempty"`
	GraphicsClock     uint32                 `json:"graphics_clock_mhz,omitempty"`
	Temperature       float64                `json:"temperature_celsius"`
	PowerUsage        float64                `json:"power_usage_watts"`
	PowerLimit        float64                `json:"power_limit_watts,omitempty"`
	PCIeRxThroughput  float64                `json:"pcie_rx_throughput_mbps,omitempty"`
	PCIeTxThroughput  float64                `json:"pcie_tx_throughput_mbps,omitempty"`
	NVLinkBandwidth   float64                `json:"nvlink_bandwidth_mbps,omitempty"`
	ECCErrors         uint64                 `json:"ecc_errors,omitempty"`
	RetiredPages      uint64                 `json:"retired_pages,omitempty"`
	Processes         []ProcessInfo          `json:"processes,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// ProcessInfo represents information about a process using the GPU
type ProcessInfo struct {
	PID           uint32 `json:"pid"`
	Name          string `json:"name"`
	MemoryUsed    uint64 `json:"memory_used_mb"`
	Type          string `json:"type"`
	SMUtilization uint32 `json:"sm_utilization_percent,omitempty"`
}

// CollectorInfo provides information about a collector
type CollectorInfo struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Available   bool   `json:"available"`
	Description string `json:"description"`
}

// DCGMCollector provides NVIDIA GPU metrics collection using DCGM
type DCGMCollector struct {
	logger     *logrus.Logger
	useNative  bool
	cliImpl    *DCGMCLICollector
	nativeImpl DCGMNativeInterface
}

// DCGMNativeInterface defines the interface for native DCGM integration
type DCGMNativeInterface interface {
	IsAvailable() bool
	CollectMetrics(ctx context.Context) ([]GPUMetrics, error)
	StartMonitoring(ctx context.Context, interval time.Duration) (<-chan []GPUMetrics, error)
	Cleanup()
}

// NewDCGMCollector creates a new DCGM collector with automatic fallback
func NewDCGMCollector(logger *logrus.Logger) *DCGMCollector {
	collector := &DCGMCollector{
		logger:  logger,
		cliImpl: NewDCGMCLICollector(logger),
	}

	// Try to initialize native implementation if available
	if nativeImpl := NewDCGMNativeCollector(logger); nativeImpl != nil && nativeImpl.IsAvailable() {
		collector.nativeImpl = nativeImpl
		collector.useNative = true
		logger.Info("Using native DCGM integration")
	} else {
		logger.Info("Native DCGM not available, using CLI fallback")
	}

	return collector
}

// IsAvailable checks if DCGM is available on the system
func (d *DCGMCollector) IsAvailable() bool {
	if d.useNative && d.nativeImpl != nil {
		return d.nativeImpl.IsAvailable()
	}
	return d.cliImpl.IsAvailable()
}

// CollectMetrics collects GPU metrics using the best available method
func (d *DCGMCollector) CollectMetrics(ctx context.Context) ([]GPUMetrics, error) {
	if d.useNative && d.nativeImpl != nil {
		metrics, err := d.nativeImpl.CollectMetrics(ctx)
		if err != nil {
			d.logger.WithError(err).Warn("Native DCGM collection failed, falling back to CLI")
			d.useNative = false
			return d.cliImpl.CollectMetrics(ctx)
		}
		return metrics, nil
	}
	return d.cliImpl.CollectMetrics(ctx)
}

// StartMonitoring starts continuous monitoring
func (d *DCGMCollector) StartMonitoring(ctx context.Context, interval time.Duration) (<-chan []GPUMetrics, error) {
	if d.useNative && d.nativeImpl != nil {
		return d.nativeImpl.StartMonitoring(ctx, interval)
	}
	return d.cliImpl.StartMonitoring(ctx, interval)
}

// Cleanup cleans up resources
func (d *DCGMCollector) Cleanup() {
	if d.nativeImpl != nil {
		d.nativeImpl.Cleanup()
	}
}

// GetCollectorInfo returns information about the DCGM collector
func (d *DCGMCollector) GetCollectorInfo() CollectorInfo {
	collectorType := "dcgm-cli"
	description := "NVIDIA DCGM via command-line interface"

	if d.useNative {
		collectorType = "dcgm-native"
		description = "NVIDIA DCGM via native library integration"
	}

	return CollectorInfo{
		Type:        collectorType,
		Name:        "NVIDIA DCGM",
		Version:     "3.x",
		Available:   d.IsAvailable(),
		Description: description,
	}
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

// ConvertToGPUMetrics converts DCGM metrics to standard GPU metrics
func (dm *DCGMMetrics) ConvertToGPUMetrics() GPUMetrics {
	gpu := GPUMetrics{
		DeviceID:          dm.DeviceID,
		UUID:              dm.UUID,
		Name:              dm.Name,
		Timestamp:         time.Now(),
		MemoryUsed:        dm.MemoryUsed,
		MemoryTotal:       dm.MemoryTotal,
		MemoryFree:        dm.MemoryFree,
		MemoryUtilization: dm.MemoryUtilization,
		GPUUtilization:    dm.GPUUtilization,
		SMClock:           dm.SMClock,
		MemoryClock:       dm.MemoryClock,
		GraphicsClock:     dm.GraphicsClock,
		Temperature:       dm.Temperature,
		PowerUsage:        dm.PowerUsage,
		PowerLimit:        dm.PowerLimit,
		PCIeRxThroughput:  dm.PCIeRxThroughput,
		PCIeTxThroughput:  dm.PCIeTxThroughput,
		NVLinkBandwidth:   dm.NVLinkBandwidth,
		ECCErrors:         dm.ECCErrors,
		RetiredPages:      dm.RetiredPages,
	}

	// Convert processes
	for _, proc := range dm.Processes {
		gpu.Processes = append(gpu.Processes, ProcessInfo{
			PID:           proc.PID,
			Name:          proc.Name,
			MemoryUsed:    proc.MemoryUsed,
			Type:          proc.Type,
			SMUtilization: proc.SMUtilization,
		})
	}

	// Add DCGM-specific metadata
	gpu.Metadata = map[string]interface{}{
		"vendor":        "NVIDIA",
		"dcgm_enhanced": true,
		"collector":     "dcgm",
	}

	return gpu
}

// DCGMFieldID represents DCGM field identifiers
type DCGMFieldID uint16

// Common DCGM field IDs
const (
	DCGM_FI_DEV_NAME                   DCGMFieldID = 50
	DCGM_FI_DEV_UUID                   DCGMFieldID = 59
	DCGM_FI_DEV_MEM_COPY_UTIL          DCGMFieldID = 155
	DCGM_FI_DEV_GPU_UTIL               DCGMFieldID = 203
	DCGM_FI_DEV_FB_USED                DCGMFieldID = 252
	DCGM_FI_DEV_FB_TOTAL               DCGMFieldID = 253
	DCGM_FI_DEV_GPU_TEMP               DCGMFieldID = 150
	DCGM_FI_DEV_POWER_USAGE            DCGMFieldID = 155
	DCGM_FI_DEV_POWER_MGMT_LIMIT       DCGMFieldID = 158
	DCGM_FI_DEV_SM_CLOCK               DCGMFieldID = 139
	DCGM_FI_DEV_MEM_CLOCK              DCGMFieldID = 140
	DCGM_FI_DEV_GRAPHICS_CLOCK         DCGMFieldID = 141
	DCGM_FI_DEV_PCIE_RX_THROUGHPUT     DCGMFieldID = 390
	DCGM_FI_DEV_PCIE_TX_THROUGHPUT     DCGMFieldID = 391
	DCGM_FI_DEV_NVLINK_BANDWIDTH_TOTAL DCGMFieldID = 392
	DCGM_FI_DEV_ECC_SBE_VOL_TOTAL      DCGMFieldID = 204
	DCGM_FI_DEV_RETIRED_SBE            DCGMFieldID = 205
)

// DCGMFieldInfo provides information about DCGM fields
type DCGMFieldInfo struct {
	ID          DCGMFieldID
	Name        string
	Description string
	DataType    string
}

// GetDCGMFieldInfo returns information about common DCGM fields
func GetDCGMFieldInfo() []DCGMFieldInfo {
	return []DCGMFieldInfo{
		{DCGM_FI_DEV_NAME, "DCGM_FI_DEV_NAME", "GPU name", "string"},
		{DCGM_FI_DEV_UUID, "DCGM_FI_DEV_UUID", "GPU UUID", "string"},
		{DCGM_FI_DEV_MEM_COPY_UTIL, "DCGM_FI_DEV_MEM_COPY_UTIL", "Memory utilization", "double"},
		{DCGM_FI_DEV_GPU_UTIL, "DCGM_FI_DEV_GPU_UTIL", "GPU utilization", "double"},
		{DCGM_FI_DEV_FB_USED, "DCGM_FI_DEV_FB_USED", "Frame buffer used", "int64"},
		{DCGM_FI_DEV_FB_TOTAL, "DCGM_FI_DEV_FB_TOTAL", "Frame buffer total", "int64"},
		{DCGM_FI_DEV_GPU_TEMP, "DCGM_FI_DEV_GPU_TEMP", "GPU temperature", "double"},
		{DCGM_FI_DEV_POWER_USAGE, "DCGM_FI_DEV_POWER_USAGE", "Power usage", "double"},
		{DCGM_FI_DEV_POWER_MGMT_LIMIT, "DCGM_FI_DEV_POWER_MGMT_LIMIT", "Power limit", "double"},
		{DCGM_FI_DEV_SM_CLOCK, "DCGM_FI_DEV_SM_CLOCK", "SM clock", "int64"},
		{DCGM_FI_DEV_MEM_CLOCK, "DCGM_FI_DEV_MEM_CLOCK", "Memory clock", "int64"},
		{DCGM_FI_DEV_GRAPHICS_CLOCK, "DCGM_FI_DEV_GRAPHICS_CLOCK", "Graphics clock", "int64"},
	}
}
