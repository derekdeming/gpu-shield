package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	version = "0.1.0"
)

// CollectorConfig holds configuration for the collector
type CollectorConfig struct {
	Port          int
	BackendURL    string
	LogLevel      string
	BufferSize    int
	FlushInterval time.Duration
	MetricsPort   int
}

// TelemetryData represents incoming telemetry from sensors
type TelemetryData struct {
	Timestamp     time.Time              `json:"timestamp"`
	NodeID        string                 `json:"node_id"`
	Hostname      string                 `json:"hostname"`
	SensorVersion string                 `json:"sensor_version"`
	GPUs          []GPUInfo              `json:"gpus"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// GPUInfo represents GPU telemetry data
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

// Collector manages telemetry collection and forwarding
type Collector struct {
	config     *CollectorConfig
	logger     *logrus.Logger
	buffer     chan TelemetryData
	httpClient *http.Client
	server     *http.Server
}

var (
	config = &CollectorConfig{}
	logger = logrus.New()
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "collector",
		Short: "GPU Shield telemetry collector service",
		Long: `GPU Shield collector aggregates telemetry data from sensors
and forwards it to the backend for processing and storage.`,
		Version: version,
		RunE:    runCollector,
	}

	// Add flags
	rootCmd.Flags().IntVar(&config.Port, "port", 8080, "HTTP server port")
	rootCmd.Flags().StringVar(&config.BackendURL, "backend-url", "http://localhost:8000", "Backend API URL")
	rootCmd.Flags().StringVar(&config.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().IntVar(&config.BufferSize, "buffer-size", 1000, "Telemetry buffer size")
	rootCmd.Flags().DurationVar(&config.FlushInterval, "flush-interval", 30*time.Second, "Buffer flush interval")
	rootCmd.Flags().IntVar(&config.MetricsPort, "metrics-port", 9090, "Prometheus metrics port")

	if err := rootCmd.Execute(); err != nil {
		logger.WithError(err).Fatal("Failed to execute command")
	}
}

func runCollector(cmd *cobra.Command, args []string) error {
	// Configure logging
	if err := configureLogging(); err != nil {
		return fmt.Errorf("failed to configure logging: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"port":           config.Port,
		"backend_url":    config.BackendURL,
		"buffer_size":    config.BufferSize,
		"flush_interval": config.FlushInterval,
		"version":        version,
	}).Info("Starting GPU Shield collector")

	// Create collector instance
	collector := NewCollector(config, logger)

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

	// Start collector
	return collector.Start(ctx)
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

// NewCollector creates a new collector instance
func NewCollector(cfg *CollectorConfig, log *logrus.Logger) *Collector {
	return &Collector{
		config: cfg,
		logger: log,
		buffer: make(chan TelemetryData, cfg.BufferSize),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Start starts the collector service
func (c *Collector) Start(ctx context.Context) error {
	// Start HTTP server
	mux := http.NewServeMux()
	c.setupRoutes(mux)

	c.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", c.config.Port),
		Handler: mux,
	}

	// Start background workers
	go c.bufferProcessor(ctx)
	go c.metricsServer(ctx)

	// Start HTTP server
	go func() {
		c.logger.WithField("port", c.config.Port).Info("Starting HTTP server")
		if err := c.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			c.logger.WithError(err).Error("HTTP server error")
		}
	}()

	// Wait for shutdown
	<-ctx.Done()
	c.logger.Info("Shutting down collector")

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := c.server.Shutdown(shutdownCtx); err != nil {
		c.logger.WithError(err).Error("Server shutdown error")
	}

	// Flush remaining buffer
	c.flushBuffer()

	return nil
}

// setupRoutes configures HTTP routes
func (c *Collector) setupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", c.healthHandler)
	mux.HandleFunc("/telemetry", c.telemetryHandler)
	mux.HandleFunc("/metrics", c.prometheusHandler)
}

// healthHandler handles health check requests
func (c *Collector) healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"status":      "healthy",
		"version":     version,
		"buffer_size": len(c.buffer),
		"timestamp":   time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// telemetryHandler handles incoming telemetry data
func (c *Collector) telemetryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var telemetry TelemetryData
	if err := json.NewDecoder(r.Body).Decode(&telemetry); err != nil {
		c.logger.WithError(err).Error("Failed to decode telemetry data")
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Add to buffer
	select {
	case c.buffer <- telemetry:
		c.logger.WithFields(logrus.Fields{
			"node_id":   telemetry.NodeID,
			"gpu_count": len(telemetry.GPUs),
		}).Debug("Received telemetry data")
	default:
		c.logger.Warn("Buffer full, dropping telemetry data")
		http.Error(w, "Buffer full", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "accepted",
	})
}

// prometheusHandler serves Prometheus metrics
func (c *Collector) prometheusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Basic metrics in Prometheus format
	metrics := fmt.Sprintf(`# HELP gpushield_collector_buffer_size Current buffer size
# TYPE gpushield_collector_buffer_size gauge
gpushield_collector_buffer_size %d

# HELP gpushield_collector_version Collector version info
# TYPE gpushield_collector_version gauge
gpushield_collector_version{version="%s"} 1
`, len(c.buffer), version)

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(metrics))
}

// bufferProcessor processes buffered telemetry data
func (c *Collector) bufferProcessor(ctx context.Context) {
	ticker := time.NewTicker(c.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.flushBuffer()
		}
	}
}

// flushBuffer sends buffered telemetry to backend
func (c *Collector) flushBuffer() {
	var batch []TelemetryData

	// Collect all buffered data
	for {
		select {
		case data := <-c.buffer:
			batch = append(batch, data)
		default:
			goto process
		}
	}

process:
	if len(batch) == 0 {
		return
	}

	c.logger.WithField("batch_size", len(batch)).Info("Flushing telemetry batch to backend")

	// Convert to backend format and send
	if err := c.sendToBackend(batch); err != nil {
		c.logger.WithError(err).Error("Failed to send telemetry to backend")
		// TODO: Implement retry logic or dead letter queue
	}
}

// sendToBackend sends telemetry data to the backend API
func (c *Collector) sendToBackend(batch []TelemetryData) error {
	// Convert to backend API format
	backendRecords := make([]map[string]interface{}, 0, len(batch)*4) // Estimate 4 GPUs per node

	for _, telemetry := range batch {
		for _, gpu := range telemetry.GPUs {
			record := map[string]interface{}{
				"gpu_id":         gpu.UUID, // Use UUID as GPU ID
				"sensor_id":      fmt.Sprintf("%s-sensor", telemetry.NodeID),
				"telemetry_type": "metrics",
				"timestamp":      telemetry.Timestamp.Format(time.RFC3339),
				"metrics": map[string]interface{}{
					"gpu_utilization":    gpu.GPUUtilization,
					"memory_utilization": gpu.MemoryUtilization,
					"memory_total":       gpu.MemoryTotal,
					"memory_used":        gpu.MemoryUsed,
					"memory_free":        gpu.MemoryFree,
					"temperature":        gpu.Temperature,
					"power_usage":        gpu.PowerDraw,
					"gpu_index":          gpu.Index,
					"gpu_name":           gpu.Name,
				},
				"metadata": map[string]interface{}{
					"node_id":           telemetry.NodeID,
					"hostname":          telemetry.Hostname,
					"sensor_version":    telemetry.SensorVersion,
					"collector_version": version,
				},
			}
			backendRecords = append(backendRecords, record)
		}
	}

	// Send to backend
	payload := map[string]interface{}{
		"records": backendRecords,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/telemetry/records/bulk", c.config.BackendURL)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("backend returned status %d", resp.StatusCode)
	}

	c.logger.WithField("records_sent", len(backendRecords)).Info("Successfully sent telemetry to backend")
	return nil
}

// metricsServer starts a separate metrics server
func (c *Collector) metricsServer(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", c.prometheusHandler)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", c.config.MetricsPort),
		Handler: mux,
	}

	go func() {
		c.logger.WithField("port", c.config.MetricsPort).Info("Starting metrics server")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			c.logger.WithError(err).Error("Metrics server error")
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
}
