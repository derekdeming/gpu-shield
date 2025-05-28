package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ShipKode/gpushield/pkg/telemetry"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	// Default collection interval
	defaultInterval = 30 * time.Second

	// Sensor version
	version = "0.1.0"
)

// GPUMemoryMetrics represents GPU memory utilization data
type GPUMemoryMetrics struct {
	Timestamp     time.Time `json:"timestamp"`
	NodeID        string    `json:"node_id"`
	Hostname      string    `json:"hostname"`
	SensorVersion string    `json:"sensor_version"`
	GPUs          []GPUInfo `json:"gpus"`
}

// GPUInfo represents information about a single GPU
type GPUInfo struct {
	Index             int                    `json:"index"`
	Name              string                 `json:"name"`
	UUID              string                 `json:"uuid"`
	MemoryTotal       uint64                 `json:"memory_total_mb"`
	MemoryUsed        uint64                 `json:"memory_used_mb"`
	MemoryFree        uint64                 `json:"memory_free_mb"`
	MemoryUtilization float64                `json:"memory_utilization_percent"`
	Temperature       float64                `json:"temperature_celsius"`
	PowerDraw         float64                `json:"power_draw_watts"`
	GPUUtilization    float64                `json:"gpu_utilization_percent"`
	Processes         []ProcessInfo          `json:"processes,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// ProcessInfo represents GPU process information
type ProcessInfo struct {
	PID        uint32 `json:"pid"`
	Name       string `json:"name"`
	MemoryUsed uint64 `json:"memory_used_mb"`
	Type       string `json:"type"`
	User       string `json:"user,omitempty"`
}

// SensorConfig holds configuration for the sensor
type SensorConfig struct {
	Interval        time.Duration
	NodeID          string
	LogLevel        string
	OutputFormat    string
	UseDCGM         bool
	CollectorURL    string
	SendToCollector bool
}

var (
	config = &SensorConfig{}
	logger = logrus.New()
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sensor",
		Short: "GPU Shield sensor for collecting GPU telemetry",
		Long: `GPU Shield sensor collects GPU telemetry data including memory utilization,
temperature, and power consumption using NVIDIA tools like nvidia-smi and DCGM.`,
		Version: version,
		RunE:    runSensor,
	}

	// Add flags
	rootCmd.Flags().DurationVar(&config.Interval, "interval", defaultInterval, "Collection interval")
	rootCmd.Flags().StringVar(&config.NodeID, "node-id", "", "Node identifier (defaults to hostname)")
	rootCmd.Flags().StringVar(&config.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().StringVar(&config.OutputFormat, "output", "json", "Output format (json, text)")
	rootCmd.Flags().BoolVar(&config.UseDCGM, "use-dcgm", false, "Use DCGM instead of nvidia-smi")
	rootCmd.Flags().StringVar(&config.CollectorURL, "collector-url", "", "Collector service URL (if set, sends data to collector)")
	rootCmd.Flags().BoolVar(&config.SendToCollector, "send-to-collector", false, "Send telemetry to collector service")

	if err := rootCmd.Execute(); err != nil {
		logger.WithError(err).Fatal("Failed to execute command")
	}
}

func runSensor(cmd *cobra.Command, args []string) error {
	// Configure logging
	if err := configureLogging(); err != nil {
		return fmt.Errorf("failed to configure logging: %w", err)
	}

	// Set default node ID to hostname if not provided
	if config.NodeID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname: %w", err)
		}
		config.NodeID = hostname
	}

	logger.WithFields(logrus.Fields{
		"node_id":       config.NodeID,
		"interval":      config.Interval,
		"output_format": config.OutputFormat,
		"use_dcgm":      config.UseDCGM,
		"version":       version,
	}).Info("Starting GPU Shield sensor")

	// Check if NVIDIA tools are available
	if err := checkNVIDIATools(); err != nil {
		return fmt.Errorf("NVIDIA tools check failed: %w", err)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.WithField("signal", sig).Info("Received shutdown signal")
		cancel()
	}()

	// Start collection loop
	return collectMetrics(ctx)
}

func configureLogging() error {
	level, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}

	logger.SetLevel(level)
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	})

	return nil
}

func checkNVIDIATools() error {
	// Check if nvidia-smi is available
	if _, err := exec.LookPath("nvidia-smi"); err != nil {
		return fmt.Errorf("nvidia-smi not found in PATH: %w", err)
	}

	// Test nvidia-smi execution
	cmd := exec.Command("nvidia-smi", "-L")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nvidia-smi execution failed: %w", err)
	}

	logger.Info("NVIDIA tools check passed")
	return nil
}

func collectMetrics(ctx context.Context) error {
	ticker := time.NewTicker(config.Interval)
	defer ticker.Stop()

	// Collect initial metrics
	if err := collectAndOutput(ctx); err != nil {
		logger.WithError(err).Error("Failed to collect initial metrics")
	}

	for {
		select {
		case <-ctx.Done():
			logger.Info("Shutting down sensor")
			return nil
		case <-ticker.C:
			if err := collectAndOutput(ctx); err != nil {
				logger.WithError(err).Error("Failed to collect metrics")
			}
		}
	}
}

func collectAndOutput(ctx context.Context) error {
	metrics, err := collectGPUMetrics(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect GPU metrics: %w", err)
	}

	// Send to collector if configured
	if config.SendToCollector && config.CollectorURL != "" {
		if err := sendToCollector(metrics); err != nil {
			logger.WithError(err).Error("Failed to send metrics to collector")
		}
	}

	return outputMetrics(metrics)
}

func collectGPUMetrics(ctx context.Context) (*GPUMemoryMetrics, error) {
	hostname, _ := os.Hostname()

	metrics := &GPUMemoryMetrics{
		Timestamp:     time.Now(),
		NodeID:        config.NodeID,
		Hostname:      hostname,
		SensorVersion: version,
		GPUs:          []GPUInfo{},
	}

	if config.UseDCGM {
		return collectDCGMMetrics(ctx, metrics)
	}

	return collectNvidiaSMIMetrics(ctx, metrics)
}

func collectDCGMMetrics(ctx context.Context, metrics *GPUMemoryMetrics) (*GPUMemoryMetrics, error) {
	// Import the DCGM collector
	dcgmCollector := telemetry.NewDCGMCollector(logger)

	// Check if DCGM is available
	if !dcgmCollector.IsAvailable() {
		logger.Debug("DCGM not available, falling back to nvidia-smi")
		return collectNvidiaSMIMetrics(ctx, metrics)
	}

	// Collect DCGM metrics
	dcgmMetrics, err := dcgmCollector.CollectMetrics(ctx)
	if err != nil {
		logger.WithError(err).Warn("DCGM collection failed, falling back to nvidia-smi")
		return collectNvidiaSMIMetrics(ctx, metrics)
	}

	// Convert DCGM metrics to our format
	for _, dcgmGPU := range dcgmMetrics {
		gpu := GPUInfo{
			Index:             dcgmGPU.DeviceID,
			Name:              dcgmGPU.Name,
			UUID:              dcgmGPU.UUID,
			MemoryTotal:       dcgmGPU.MemoryTotal,
			MemoryUsed:        dcgmGPU.MemoryUsed,
			MemoryFree:        dcgmGPU.MemoryFree,
			MemoryUtilization: dcgmGPU.MemoryUtilization,
			Temperature:       dcgmGPU.Temperature,
			PowerDraw:         dcgmGPU.PowerUsage,
			GPUUtilization:    dcgmGPU.GPUUtilization,
		}

		// Add enhanced DCGM metrics to metadata
		gpu.Metadata = map[string]interface{}{
			"dcgm_enhanced":      true,
			"sm_clock":           dcgmGPU.SMClock,
			"memory_clock":       dcgmGPU.MemoryClock,
			"graphics_clock":     dcgmGPU.GraphicsClock,
			"power_limit":        dcgmGPU.PowerLimit,
			"pcie_rx_throughput": dcgmGPU.PCIeRxThroughput,
			"pcie_tx_throughput": dcgmGPU.PCIeTxThroughput,
			"nvlink_bandwidth":   dcgmGPU.NVLinkBandwidth,
			"ecc_errors":         dcgmGPU.ECCErrors,
			"retired_pages":      dcgmGPU.RetiredPages,
			"process_count":      len(dcgmGPU.Processes),
		}

		// Add process information
		for _, proc := range dcgmGPU.Processes {
			gpu.Processes = append(gpu.Processes, ProcessInfo{
				PID:        proc.PID,
				Name:       proc.Name,
				MemoryUsed: proc.MemoryUsed,
				Type:       proc.Type,
			})
		}

		metrics.GPUs = append(metrics.GPUs, gpu)
	}

	logger.WithField("gpu_count", len(dcgmMetrics)).Info("Successfully collected DCGM metrics")
	return metrics, nil
}

func collectNvidiaSMIMetrics(ctx context.Context, metrics *GPUMemoryMetrics) (*GPUMemoryMetrics, error) {
	// Query GPU information using nvidia-smi
	cmd := exec.CommandContext(ctx, "nvidia-smi",
		"--query-gpu=index,name,uuid,memory.total,memory.used,memory.free,utilization.memory,temperature.gpu,power.draw,utilization.gpu",
		"--format=csv,noheader,nounits")

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nvidia-smi command failed: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		gpu, err := parseNvidiaSMILine(line)
		if err != nil {
			logger.WithError(err).WithField("line", line).Warn("Failed to parse nvidia-smi output line")
			continue
		}

		metrics.GPUs = append(metrics.GPUs, gpu)
	}

	return metrics, nil
}

func parseNvidiaSMILine(line string) (GPUInfo, error) {
	fields := strings.Split(line, ", ")
	if len(fields) < 10 {
		return GPUInfo{}, fmt.Errorf("insufficient fields in nvidia-smi output: %d", len(fields))
	}

	gpu := GPUInfo{}
	var err error

	// Parse index
	if gpu.Index, err = strconv.Atoi(strings.TrimSpace(fields[0])); err != nil {
		return gpu, fmt.Errorf("failed to parse GPU index: %w", err)
	}

	// Parse name and UUID
	gpu.Name = strings.TrimSpace(fields[1])
	gpu.UUID = strings.TrimSpace(fields[2])

	// Parse memory values (in MB)
	if gpu.MemoryTotal, err = parseUint64(fields[3]); err != nil {
		return gpu, fmt.Errorf("failed to parse memory total: %w", err)
	}
	if gpu.MemoryUsed, err = parseUint64(fields[4]); err != nil {
		return gpu, fmt.Errorf("failed to parse memory used: %w", err)
	}
	if gpu.MemoryFree, err = parseUint64(fields[5]); err != nil {
		return gpu, fmt.Errorf("failed to parse memory free: %w", err)
	}

	// Parse utilization percentages
	if gpu.MemoryUtilization, err = parseFloat64(fields[6]); err != nil {
		return gpu, fmt.Errorf("failed to parse memory utilization: %w", err)
	}

	// Parse temperature
	if gpu.Temperature, err = parseFloat64(fields[7]); err != nil {
		return gpu, fmt.Errorf("failed to parse temperature: %w", err)
	}

	// Parse power draw
	if gpu.PowerDraw, err = parseFloat64(fields[8]); err != nil {
		return gpu, fmt.Errorf("failed to parse power draw: %w", err)
	}

	// Parse GPU utilization
	if gpu.GPUUtilization, err = parseFloat64(fields[9]); err != nil {
		return gpu, fmt.Errorf("failed to parse GPU utilization: %w", err)
	}

	return gpu, nil
}

func parseUint64(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "[Not Supported]" || s == "N/A" {
		return 0, nil
	}
	return strconv.ParseUint(s, 10, 64)
}

func parseFloat64(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "[Not Supported]" || s == "N/A" {
		return 0, nil
	}
	return strconv.ParseFloat(s, 64)
}

func outputMetrics(metrics *GPUMemoryMetrics) error {
	switch config.OutputFormat {
	case "json":
		return outputJSON(metrics)
	case "text":
		return outputText(metrics)
	default:
		return fmt.Errorf("unsupported output format: %s", config.OutputFormat)
	}
}

func outputJSON(metrics *GPUMemoryMetrics) error {
	data, err := json.Marshal(metrics)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics to JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func outputText(metrics *GPUMemoryMetrics) error {
	fmt.Printf("=== GPU Metrics - %s ===\n", metrics.Timestamp.Format(time.RFC3339))
	fmt.Printf("Node: %s (%s)\n", metrics.NodeID, metrics.Hostname)
	fmt.Printf("Sensor Version: %s\n", metrics.SensorVersion)
	fmt.Printf("GPUs: %d\n\n", len(metrics.GPUs))

	for _, gpu := range metrics.GPUs {
		fmt.Printf("GPU %d: %s\n", gpu.Index, gpu.Name)
		fmt.Printf("  UUID: %s\n", gpu.UUID)
		fmt.Printf("  Memory: %d/%d MB (%.1f%% used)\n",
			gpu.MemoryUsed, gpu.MemoryTotal, gpu.MemoryUtilization)
		fmt.Printf("  Temperature: %.1f°C\n", gpu.Temperature)
		fmt.Printf("  Power: %.1fW\n", gpu.PowerDraw)
		fmt.Printf("  GPU Utilization: %.1f%%\n\n", gpu.GPUUtilization)
	}

	return nil
}

// sendToCollector sends telemetry data to the collector service
func sendToCollector(metrics *GPUMemoryMetrics) error {
	jsonData, err := json.Marshal(metrics)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}

	url := fmt.Sprintf("%s/telemetry", config.CollectorURL)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("collector returned status %d", resp.StatusCode)
	}

	logger.WithFields(logrus.Fields{
		"collector_url": url,
		"gpu_count":     len(metrics.GPUs),
	}).Debug("Successfully sent metrics to collector")

	return nil
}
