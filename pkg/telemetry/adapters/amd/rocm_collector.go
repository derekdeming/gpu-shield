package amd

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ShipKode/gpushield/pkg/telemetry"
	"github.com/sirupsen/logrus"
)

// ROCmCollector provides AMD GPU metrics collection using ROCm tools
type ROCmCollector struct {
	logger *logrus.Logger
}

// ROCmMetrics represents AMD GPU metrics
type ROCmMetrics struct {
	DeviceID    int     `json:"device_id"`
	Name        string  `json:"name"`
	UUID        string  `json:"uuid"`
	MemoryUsed  uint64  `json:"memory_used_mb"`
	MemoryTotal uint64  `json:"memory_total_mb"`
	Temperature float64 `json:"temperature_celsius"`
	PowerUsage  float64 `json:"power_usage_watts"`
	Utilization float64 `json:"utilization_percent"`
}

// NewROCmCollector creates a new ROCm collector
func NewROCmCollector(logger *logrus.Logger) *ROCmCollector {
	return &ROCmCollector{
		logger: logger,
	}
}

// IsAvailable checks if ROCm tools are available on the system
func (r *ROCmCollector) IsAvailable() bool {
	// Check if rocm-smi is available
	if _, err := exec.LookPath("rocm-smi"); err != nil {
		r.logger.Debug("rocm-smi command not found")
		return false
	}

	// Test rocm-smi execution
	cmd := exec.Command("rocm-smi", "--showid")
	if err := cmd.Run(); err != nil {
		r.logger.WithError(err).Debug("rocm-smi execution failed")
		return false
	}

	return true
}

// CollectMetrics collects GPU metrics using ROCm tools
func (r *ROCmCollector) CollectMetrics(ctx context.Context) ([]telemetry.GPUMetrics, error) {
	rocmMetrics, err := r.collectROCmMetrics(ctx)
	if err != nil {
		return nil, err
	}

	// Convert ROCm metrics to standard GPU metrics
	var gpuMetrics []telemetry.GPUMetrics
	for _, rocm := range rocmMetrics {
		gpu := telemetry.GPUMetrics{
			DeviceID:          rocm.DeviceID,
			UUID:              rocm.UUID,
			Name:              rocm.Name,
			Timestamp:         time.Now(),
			MemoryUsed:        rocm.MemoryUsed,
			MemoryTotal:       rocm.MemoryTotal,
			MemoryFree:        rocm.MemoryTotal - rocm.MemoryUsed,
			MemoryUtilization: float64(rocm.MemoryUsed) / float64(rocm.MemoryTotal) * 100,
			GPUUtilization:    rocm.Utilization,
			Temperature:       rocm.Temperature,
			PowerUsage:        rocm.PowerUsage,
		}

		// Add AMD-specific metadata
		gpu.Metadata = map[string]interface{}{
			"vendor":      "AMD",
			"rocm_device": true,
		}

		gpuMetrics = append(gpuMetrics, gpu)
	}

	return gpuMetrics, nil
}

// collectROCmMetrics collects GPU metrics using rocm-smi
func (r *ROCmCollector) collectROCmMetrics(ctx context.Context) ([]ROCmMetrics, error) {
	// Get basic GPU information
	cmd := exec.CommandContext(ctx, "rocm-smi", "--showid", "--showproductname", "--showmeminfo", "--showtemp", "--showpower", "--showuse", "--json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("rocm-smi command failed: %w", err)
	}

	return r.parseROCmOutput(output)
}

// parseROCmOutput parses the JSON output from rocm-smi
func (r *ROCmCollector) parseROCmOutput(output []byte) ([]ROCmMetrics, error) {
	var rocmData map[string]interface{}
	if err := json.Unmarshal(output, &rocmData); err != nil {
		return nil, fmt.Errorf("failed to parse rocm-smi JSON output: %w", err)
	}

	var metrics []ROCmMetrics

	// Parse each GPU device
	for deviceKey, deviceData := range rocmData {
		if !strings.HasPrefix(deviceKey, "card") {
			continue
		}

		deviceMap, ok := deviceData.(map[string]interface{})
		if !ok {
			continue
		}

		metric := ROCmMetrics{}

		// Extract device ID from key (e.g., "card0" -> 0)
		if deviceID, err := strconv.Atoi(strings.TrimPrefix(deviceKey, "card")); err == nil {
			metric.DeviceID = deviceID
		}

		// Extract GPU information
		if name, ok := deviceMap["Product Name"].(string); ok {
			metric.Name = name
		}

		if uuid, ok := deviceMap["Unique ID"].(string); ok {
			metric.UUID = uuid
		}

		// Extract memory information
		if memInfo, ok := deviceMap["VRAM Total Memory (B)"].(string); ok {
			if memBytes, err := strconv.ParseUint(memInfo, 10, 64); err == nil {
				metric.MemoryTotal = memBytes / (1024 * 1024) // Convert to MB
			}
		}

		if memUsed, ok := deviceMap["VRAM Total Used Memory (B)"].(string); ok {
			if memBytes, err := strconv.ParseUint(memUsed, 10, 64); err == nil {
				metric.MemoryUsed = memBytes / (1024 * 1024) // Convert to MB
			}
		}

		// Extract temperature
		if temp, ok := deviceMap["Temperature (Sensor edge) (C)"].(string); ok {
			if tempVal, err := strconv.ParseFloat(temp, 64); err == nil {
				metric.Temperature = tempVal
			}
		}

		// Extract power usage
		if power, ok := deviceMap["Average Graphics Package Power (W)"].(string); ok {
			if powerVal, err := strconv.ParseFloat(power, 64); err == nil {
				metric.PowerUsage = powerVal
			}
		}

		// Extract utilization
		if util, ok := deviceMap["GPU use (%)"].(string); ok {
			if utilVal, err := strconv.ParseFloat(util, 64); err == nil {
				metric.Utilization = utilVal
			}
		}

		metrics = append(metrics, metric)
	}

	return metrics, nil
}

// StartMonitoring starts continuous monitoring
func (r *ROCmCollector) StartMonitoring(ctx context.Context, interval time.Duration) (<-chan []telemetry.GPUMetrics, error) {
	resultChan := make(chan []telemetry.GPUMetrics, 10)

	go func() {
		defer close(resultChan)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				metrics, err := r.CollectMetrics(ctx)
				if err != nil {
					r.logger.WithError(err).Error("Failed to collect ROCm metrics")
					continue
				}

				select {
				case resultChan <- metrics:
				case <-ctx.Done():
					return
				default:
					r.logger.Warn("Metrics channel full, dropping metrics")
				}
			}
		}
	}()

	return resultChan, nil
}

// ROCProfilerCollector provides advanced profiling using ROCProfiler Compute
type ROCProfilerCollector struct {
	logger         *logrus.Logger
	rocprofPath    string
	workloadDir    string
	profileConfigs map[string]string
}

// NewROCProfilerCollector creates a new ROCProfiler collector
func NewROCProfilerCollector(logger *logrus.Logger) *ROCProfilerCollector {
	return &ROCProfilerCollector{
		logger:         logger,
		rocprofPath:    "/opt/rocm/bin/rocprof-compute",
		workloadDir:    "/tmp/rocprof-workloads",
		profileConfigs: make(map[string]string),
	}
}

// IsAvailable checks if ROCProfiler Compute is available
func (r *ROCProfilerCollector) IsAvailable() bool {
	// Check if rocprof-compute is available
	if _, err := exec.LookPath("rocprof-compute"); err != nil {
		// Try the full path
		if _, err := exec.LookPath(r.rocprofPath); err != nil {
			r.logger.Debug("rocprof-compute not found")
			return false
		}
	}

	return true
}

// ProfileWorkload profiles a specific GPU workload
func (r *ROCProfilerCollector) ProfileWorkload(ctx context.Context, workloadCmd string, profileType string) (map[string]interface{}, error) {
	if !r.IsAvailable() {
		return nil, fmt.Errorf("ROCProfiler Compute not available")
	}

	// Create temporary directory for profiling output
	outputDir := fmt.Sprintf("%s/profile_%d", r.workloadDir, time.Now().Unix())

	// Build rocprof-compute command
	args := []string{
		"profile",
		"--name", "gpushield_profile",
		"--path", outputDir,
		"--",
	}
	args = append(args, strings.Fields(workloadCmd)...)

	cmd := exec.CommandContext(ctx, "rocprof-compute", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("rocprof-compute failed: %w, output: %s", err, string(output))
	}

	// Parse the profiling results
	return r.parseProfilingResults(outputDir)
}

// parseProfilingResults parses the profiling output files
func (r *ROCProfilerCollector) parseProfilingResults(outputDir string) (map[string]interface{}, error) {
	// This would parse the CSV/JSON files generated by rocprof-compute
	// For now, return a placeholder structure
	results := map[string]interface{}{
		"output_directory": outputDir,
		"timestamp":        time.Now(),
		"status":           "completed",
		// Add actual parsing logic here based on rocprof-compute output format
	}

	return results, nil
}
