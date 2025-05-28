package telemetry

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
)

// MetricsCollector defines the interface for GPU metrics collection
type MetricsCollector interface {
	// IsAvailable checks if the collector is available on the system
	IsAvailable() bool

	// CollectMetrics collects GPU metrics
	CollectMetrics(ctx context.Context) ([]GPUMetrics, error)

	// StartMonitoring starts continuous monitoring
	StartMonitoring(ctx context.Context, interval time.Duration) (<-chan []GPUMetrics, error)
}

// CollectorManager manages multiple telemetry collectors
type CollectorManager struct {
	collectors []MetricsCollector
	logger     *logrus.Logger
}

// NewCollectorManager creates a new collector manager
func NewCollectorManager(logger *logrus.Logger) *CollectorManager {
	return &CollectorManager{
		collectors: make([]MetricsCollector, 0),
		logger:     logger,
	}
}

// RegisterCollector registers a new metrics collector
func (cm *CollectorManager) RegisterCollector(collector MetricsCollector) {
	cm.collectors = append(cm.collectors, collector)
}

// GetAvailableCollectors returns all available collectors
func (cm *CollectorManager) GetAvailableCollectors() []MetricsCollector {
	var available []MetricsCollector
	for _, collector := range cm.collectors {
		if collector.IsAvailable() {
			available = append(available, collector)
		}
	}
	return available
}

// CollectAllMetrics collects metrics from all available collectors
func (cm *CollectorManager) CollectAllMetrics(ctx context.Context) ([]GPUMetrics, error) {
	var allMetrics []GPUMetrics

	for _, collector := range cm.GetAvailableCollectors() {
		metrics, err := collector.CollectMetrics(ctx)
		if err != nil {
			cm.logger.WithError(err).Warn("Failed to collect metrics from collector")
			continue
		}
		allMetrics = append(allMetrics, metrics...)
	}

	return allMetrics, nil
}

// StartMonitoringAll starts monitoring from all available collectors
func (cm *CollectorManager) StartMonitoringAll(ctx context.Context, interval time.Duration) (<-chan []GPUMetrics, error) {
	resultChan := make(chan []GPUMetrics, 100)

	collectors := cm.GetAvailableCollectors()
	if len(collectors) == 0 {
		close(resultChan)
		return resultChan, nil
	}

	// Start monitoring from each collector
	for _, collector := range collectors {
		go func(c MetricsCollector) {
			metricsChan, err := c.StartMonitoring(ctx, interval)
			if err != nil {
				cm.logger.WithError(err).Error("Failed to start monitoring from collector")
				return
			}

			for metrics := range metricsChan {
				select {
				case resultChan <- metrics:
				case <-ctx.Done():
					return
				default:
					cm.logger.Warn("Metrics channel full, dropping metrics")
				}
			}
		}(collector)
	}

	// Close result channel when context is done
	go func() {
		<-ctx.Done()
		close(resultChan)
	}()

	return resultChan, nil
}

// CollectorType represents the type of metrics collector
type CollectorType string

const (
	CollectorTypeDCGM      CollectorType = "dcgm"
	CollectorTypeNvidiaSMI CollectorType = "nvidia-smi"
	CollectorTypeROCm      CollectorType = "rocm"
	CollectorTypeIntelGPU  CollectorType = "intel-gpu"
)

// CollectorInfo provides information about a collector
type CollectorInfo struct {
	Type        CollectorType `json:"type"`
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	Available   bool          `json:"available"`
	Description string        `json:"description"`
}

// GetCollectorInfo returns information about a collector
func GetCollectorInfo(collector MetricsCollector) CollectorInfo {
	switch collector.(type) {
	case *DCGMCollector:
		return CollectorInfo{
			Type:        CollectorTypeDCGM,
			Name:        "NVIDIA DCGM",
			Version:     "3.x",
			Available:   collector.IsAvailable(),
			Description: "NVIDIA Data Center GPU Manager for comprehensive GPU monitoring",
		}
	default:
		return CollectorInfo{
			Type:        "unknown",
			Name:        "Unknown Collector",
			Version:     "unknown",
			Available:   collector.IsAvailable(),
			Description: "Unknown metrics collector",
		}
	}
}

// MetricsAggregator aggregates metrics from multiple sources
type MetricsAggregator struct {
	logger *logrus.Logger
}

// NewMetricsAggregator creates a new metrics aggregator
func NewMetricsAggregator(logger *logrus.Logger) *MetricsAggregator {
	return &MetricsAggregator{
		logger: logger,
	}
}

// AggregateMetrics combines metrics from multiple collectors
func (ma *MetricsAggregator) AggregateMetrics(metricsSlices ...[]GPUMetrics) []GPUMetrics {
	// Use a map to deduplicate by GPU UUID
	metricsMap := make(map[string]GPUMetrics)

	for _, metrics := range metricsSlices {
		for _, gpu := range metrics {
			if gpu.UUID != "" {
				// If we already have metrics for this GPU, merge them
				if existing, exists := metricsMap[gpu.UUID]; exists {
					merged := ma.mergeGPUMetrics(existing, gpu)
					metricsMap[gpu.UUID] = merged
				} else {
					metricsMap[gpu.UUID] = gpu
				}
			}
		}
	}

	// Convert map back to slice
	var result []GPUMetrics
	for _, gpu := range metricsMap {
		result = append(result, gpu)
	}

	return result
}

// mergeGPUMetrics merges two GPUMetrics for the same GPU
func (ma *MetricsAggregator) mergeGPUMetrics(existing, new GPUMetrics) GPUMetrics {
	// Start with the existing metrics
	merged := existing

	// Update with non-zero values from new metrics
	if new.MemoryUsed > 0 {
		merged.MemoryUsed = new.MemoryUsed
	}
	if new.MemoryTotal > 0 {
		merged.MemoryTotal = new.MemoryTotal
	}
	if new.GPUUtilization > 0 {
		merged.GPUUtilization = new.GPUUtilization
	}
	if new.MemoryUtilization > 0 {
		merged.MemoryUtilization = new.MemoryUtilization
	}
	if new.Temperature > 0 {
		merged.Temperature = new.Temperature
	}
	if new.PowerUsage > 0 {
		merged.PowerUsage = new.PowerUsage
	}

	// Merge performance metrics if available
	if new.SMClock > 0 {
		merged.SMClock = new.SMClock
	}
	if new.MemoryClock > 0 {
		merged.MemoryClock = new.MemoryClock
	}
	if new.GraphicsClock > 0 {
		merged.GraphicsClock = new.GraphicsClock
	}

	// Merge advanced metrics
	if new.PCIeRxThroughput > 0 {
		merged.PCIeRxThroughput = new.PCIeRxThroughput
	}
	if new.PCIeTxThroughput > 0 {
		merged.PCIeTxThroughput = new.PCIeTxThroughput
	}
	if new.NVLinkBandwidth > 0 {
		merged.NVLinkBandwidth = new.NVLinkBandwidth
	}

	// Merge process information (combine both lists)
	processMap := make(map[uint32]ProcessInfo)

	// Add existing processes
	for _, proc := range existing.Processes {
		processMap[proc.PID] = proc
	}

	// Add new processes (will overwrite if same PID)
	for _, proc := range new.Processes {
		processMap[proc.PID] = proc
	}

	// Convert back to slice
	merged.Processes = make([]ProcessInfo, 0, len(processMap))
	for _, proc := range processMap {
		merged.Processes = append(merged.Processes, proc)
	}

	// Update timestamp to the most recent
	if new.Timestamp.After(merged.Timestamp) {
		merged.Timestamp = new.Timestamp
	}

	return merged
}
