package telemetry

import (
	"time"
)

// GPUMetrics represents comprehensive GPU metrics from any collector
type GPUMetrics struct {
	// Basic identification
	DeviceID int    `json:"device_id"`
	UUID     string `json:"uuid"`
	Name     string `json:"name"`
	PCIBusID string `json:"pci_bus_id,omitempty"`

	// Timestamp when metrics were collected
	Timestamp time.Time `json:"timestamp"`

	// Memory metrics
	MemoryUsed        uint64  `json:"memory_used_mb"`
	MemoryTotal       uint64  `json:"memory_total_mb"`
	MemoryFree        uint64  `json:"memory_free_mb"`
	MemoryUtilization float64 `json:"memory_utilization_percent"`

	// Utilization metrics
	GPUUtilization     float64 `json:"gpu_utilization_percent"`
	EncoderUtilization float64 `json:"encoder_utilization_percent,omitempty"`
	DecoderUtilization float64 `json:"decoder_utilization_percent,omitempty"`

	// Performance metrics
	SMClock       uint32 `json:"sm_clock_mhz,omitempty"`
	MemoryClock   uint32 `json:"memory_clock_mhz,omitempty"`
	GraphicsClock uint32 `json:"graphics_clock_mhz,omitempty"`
	VideoClock    uint32 `json:"video_clock_mhz,omitempty"`

	// Thermal metrics
	Temperature       float64 `json:"temperature_celsius"`
	MaxOperatingTemp  float64 `json:"max_operating_temp_celsius,omitempty"`
	SlowdownTemp      float64 `json:"slowdown_temp_celsius,omitempty"`
	ShutdownTemp      float64 `json:"shutdown_temp_celsius,omitempty"`
	MemoryTemperature float64 `json:"memory_temperature_celsius,omitempty"`

	// Power metrics
	PowerUsage         float64 `json:"power_usage_watts"`
	PowerLimit         float64 `json:"power_limit_watts,omitempty"`
	DefaultPowerLimit  float64 `json:"default_power_limit_watts,omitempty"`
	EnforcedPowerLimit float64 `json:"enforced_power_limit_watts,omitempty"`
	MinPowerLimit      float64 `json:"min_power_limit_watts,omitempty"`
	MaxPowerLimit      float64 `json:"max_power_limit_watts,omitempty"`

	// Advanced metrics (DCGM/vendor-specific)
	PCIeRxThroughput float64 `json:"pcie_rx_throughput_mbps,omitempty"`
	PCIeTxThroughput float64 `json:"pcie_tx_throughput_mbps,omitempty"`
	NVLinkBandwidth  float64 `json:"nvlink_bandwidth_mbps,omitempty"`

	// Error counters
	ECCErrors    uint64 `json:"ecc_errors,omitempty"`
	RetiredPages uint64 `json:"retired_pages,omitempty"`
	RemappedRows uint64 `json:"remapped_rows,omitempty"`

	// Performance state
	PerformanceState     uint32 `json:"performance_state,omitempty"`
	ClockThrottleReasons uint32 `json:"clock_throttle_reasons,omitempty"`

	// Process information
	Processes []ProcessInfo `json:"processes,omitempty"`

	// Driver and firmware info
	DriverVersion   string `json:"driver_version,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`

	// Compute capability (NVIDIA)
	ComputeCapability string `json:"compute_capability,omitempty"`

	// Additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ProcessInfo represents information about a process using the GPU
type ProcessInfo struct {
	PID                uint32 `json:"pid"`
	Name               string `json:"name"`
	MemoryUsed         uint64 `json:"memory_used_mb"`
	Type               string `json:"type"` // "C" for compute, "G" for graphics, "C+G" for both
	SMUtilization      uint32 `json:"sm_utilization_percent,omitempty"`
	MemoryUtilization  uint32 `json:"memory_utilization_percent,omitempty"`
	EncoderUtilization uint32 `json:"encoder_utilization_percent,omitempty"`
	DecoderUtilization uint32 `json:"decoder_utilization_percent,omitempty"`
	User               string `json:"user,omitempty"`
	Command            string `json:"command,omitempty"`
}

// SystemMetrics represents system-level metrics
type SystemMetrics struct {
	Timestamp time.Time `json:"timestamp"`

	// Driver information
	DriverVersion string `json:"driver_version"`
	CUDAVersion   string `json:"cuda_version,omitempty"`
	ROCmVersion   string `json:"rocm_version,omitempty"`

	// System resources
	CPUUtilization    float64 `json:"cpu_utilization_percent"`
	SystemMemoryTotal uint64  `json:"system_memory_total_bytes"`
	SystemMemoryUsed  uint64  `json:"system_memory_used_bytes"`
	SystemMemoryFree  uint64  `json:"system_memory_free_bytes"`

	// GPU count
	GPUCount       int `json:"gpu_count"`
	ActiveGPUCount int `json:"active_gpu_count"`

	// Network interfaces
	NetworkInterfaces []NetworkInterface `json:"network_interfaces,omitempty"`

	// Storage devices
	StorageDevices []StorageDevice `json:"storage_devices,omitempty"`
}

// NetworkInterface represents network interface metrics
type NetworkInterface struct {
	Name            string `json:"name"`
	BytesSent       uint64 `json:"bytes_sent"`
	BytesReceived   uint64 `json:"bytes_received"`
	PacketsSent     uint64 `json:"packets_sent"`
	PacketsReceived uint64 `json:"packets_received"`
	ErrorsIn        uint64 `json:"errors_in"`
	ErrorsOut       uint64 `json:"errors_out"`
	DropsIn         uint64 `json:"drops_in"`
	DropsOut        uint64 `json:"drops_out"`
}

// StorageDevice represents storage device metrics
type StorageDevice struct {
	Device             string  `json:"device"`
	Mountpoint         string  `json:"mountpoint"`
	TotalBytes         uint64  `json:"total_bytes"`
	UsedBytes          uint64  `json:"used_bytes"`
	FreeBytes          uint64  `json:"free_bytes"`
	UtilizationPercent float64 `json:"utilization_percent"`
}

// TelemetryData represents a complete telemetry collection
type TelemetryData struct {
	Timestamp     time.Time     `json:"timestamp"`
	NodeID        string        `json:"node_id"`
	Hostname      string        `json:"hostname"`
	SensorVersion string        `json:"sensor_version"`
	CollectorType CollectorType `json:"collector_type"`

	// GPU metrics
	GPUs []GPUMetrics `json:"gpus"`

	// System-level metrics
	System SystemMetrics `json:"system,omitempty"`

	// Additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// SecurityMetrics represents security-related metrics
type SecurityMetrics struct {
	Timestamp time.Time `json:"timestamp"`
	NodeID    string    `json:"node_id"`

	// Integrity measurements
	IntegrityMeasurements []IntegrityMeasurement `json:"integrity_measurements,omitempty"`

	// Anomaly events
	AnomalyEvents []AnomalyEvent `json:"anomaly_events,omitempty"`

	// Access events
	AccessEvents []AccessEvent `json:"access_events,omitempty"`
}

// IntegrityMeasurement represents a security integrity measurement
type IntegrityMeasurement struct {
	Component     string    `json:"component"`      // "driver", "firmware", "kernel_module", etc.
	HashAlgorithm string    `json:"hash_algorithm"` // "sha256", "sha512", etc.
	HashValue     string    `json:"hash_value"`
	MeasuredAt    time.Time `json:"measured_at"`
	IsTrusted     bool      `json:"is_trusted"`
}

// AnomalyEvent represents a detected anomaly
type AnomalyEvent struct {
	EventType       string                 `json:"event_type"` // "unusual_memory_pattern", "unexpected_process", etc.
	Description     string                 `json:"description"`
	ConfidenceScore float64                `json:"confidence_score"` // 0.0 to 1.0
	DetectedAt      time.Time              `json:"detected_at"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// AccessEvent represents a GPU access event
type AccessEvent struct {
	EventType   string                 `json:"event_type"` // "process_start", "memory_allocation", "kernel_launch", etc.
	PID         uint32                 `json:"pid"`
	ProcessName string                 `json:"process_name"`
	User        string                 `json:"user"`
	Timestamp   time.Time              `json:"timestamp"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// MetricsFilter represents filters for metrics collection
type MetricsFilter struct {
	// GPU filters
	GPUIDs   []string `json:"gpu_ids,omitempty"`
	GPUUUIDs []string `json:"gpu_uuids,omitempty"`

	// Metric type filters
	IncludeMemory      bool `json:"include_memory"`
	IncludeUtilization bool `json:"include_utilization"`
	IncludeTemperature bool `json:"include_temperature"`
	IncludePower       bool `json:"include_power"`
	IncludeProcesses   bool `json:"include_processes"`
	IncludePerformance bool `json:"include_performance"`

	// Time filters
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`

	// Sampling
	SampleRate time.Duration `json:"sample_rate,omitempty"`
}

// CollectionConfig represents configuration for metrics collection
type CollectionConfig struct {
	// Collection interval
	Interval time.Duration `json:"interval"`

	// Filters
	Filter MetricsFilter `json:"filter"`

	// Output configuration
	OutputFormat string `json:"output_format"` // "json", "prometheus", "csv"
	BufferSize   int    `json:"buffer_size"`

	// Collector preferences
	PreferredCollectors []CollectorType `json:"preferred_collectors,omitempty"`
	FallbackEnabled     bool            `json:"fallback_enabled"`

	// Error handling
	MaxRetries      int           `json:"max_retries"`
	RetryInterval   time.Duration `json:"retry_interval"`
	ContinueOnError bool          `json:"continue_on_error"`
}

// MetricsStats represents statistics about metrics collection
type MetricsStats struct {
	TotalSamples      uint64        `json:"total_samples"`
	SuccessfulSamples uint64        `json:"successful_samples"`
	FailedSamples     uint64        `json:"failed_samples"`
	LastSampleTime    time.Time     `json:"last_sample_time"`
	AverageInterval   time.Duration `json:"average_interval"`
	ErrorRate         float64       `json:"error_rate"`

	// Per-collector stats
	CollectorStats map[CollectorType]CollectorStats `json:"collector_stats,omitempty"`
}

// CollectorStats represents statistics for a specific collector
type CollectorStats struct {
	Samples        uint64        `json:"samples"`
	Errors         uint64        `json:"errors"`
	LastUsed       time.Time     `json:"last_used"`
	AverageLatency time.Duration `json:"average_latency"`
	Available      bool          `json:"available"`
}
