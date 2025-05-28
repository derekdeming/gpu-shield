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

// AlertEngineConfig holds configuration for the alert engine
type AlertEngineConfig struct {
	Port               int
	BackendURL         string
	LogLevel           string
	ProcessingInterval time.Duration
	AnomalyThreshold   float64
	CriticalThreshold  float64
	MetricsPort        int
	MaxAlertsPerMinute int
}

// SecurityEvent represents a security event from the backend
type SecurityEvent struct {
	ID          string                 `json:"id"`
	NodeID      string                 `json:"node_id"`
	EventType   string                 `json:"event_type"`
	Timestamp   time.Time              `json:"timestamp"`
	RiskScore   float64                `json:"risk_score"`
	Details     map[string]interface{} `json:"details"`
	ProcessInfo ProcessInfo            `json:"process_info,omitempty"`
}

// ProcessInfo represents process information in security events
type ProcessInfo struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	User string `json:"user"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
}

// TelemetryRecord represents telemetry data for anomaly detection
type TelemetryRecord struct {
	ID           string                 `json:"id"`
	GPUID        string                 `json:"gpu_id"`
	SensorID     string                 `json:"sensor_id"`
	Timestamp    time.Time              `json:"timestamp"`
	Metrics      map[string]interface{} `json:"metrics"`
	Metadata     map[string]interface{} `json:"metadata"`
	AnomalyScore float64                `json:"anomaly_score"`
}

// Alert represents an alert to be created
type Alert struct {
	NodeID             string                   `json:"node_id"`
	Title              string                   `json:"title"`
	Description        string                   `json:"description"`
	Severity           string                   `json:"severity"`
	RuleID             string                   `json:"rule_id"`
	Confidence         float64                  `json:"confidence"`
	SecurityEventIDs   []string                 `json:"security_event_ids,omitempty"`
	TelemetryRecordIDs []string                 `json:"telemetry_record_ids,omitempty"`
	FirstSeen          time.Time                `json:"first_seen"`
	LastSeen           time.Time                `json:"last_seen"`
	ResponseActions    []map[string]interface{} `json:"response_actions,omitempty"`
}

// AlertEngine manages security event processing and alert generation
type AlertEngine struct {
	config     *AlertEngineConfig
	logger     *logrus.Logger
	httpClient *http.Client
	server     *http.Server
	alertCount map[string]int // Rate limiting per node
}

var (
	config = &AlertEngineConfig{}
	logger = logrus.New()
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "alert",
		Short: "GPU Shield alert engine service",
		Long: `GPU Shield alert engine processes security events and telemetry data
to generate security alerts and trigger automated responses.`,
		Version: version,
		RunE:    runAlertEngine,
	}

	// Add flags
	rootCmd.Flags().IntVar(&config.Port, "port", 8081, "HTTP server port")
	rootCmd.Flags().StringVar(&config.BackendURL, "backend-url", "http://localhost:8000", "Backend API URL")
	rootCmd.Flags().StringVar(&config.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().DurationVar(&config.ProcessingInterval, "processing-interval", 10*time.Second, "Event processing interval")
	rootCmd.Flags().Float64Var(&config.AnomalyThreshold, "anomaly-threshold", 0.7, "Anomaly detection threshold")
	rootCmd.Flags().Float64Var(&config.CriticalThreshold, "critical-threshold", 0.9, "Critical alert threshold")
	rootCmd.Flags().IntVar(&config.MetricsPort, "metrics-port", 9091, "Prometheus metrics port")
	rootCmd.Flags().IntVar(&config.MaxAlertsPerMinute, "max-alerts-per-minute", 10, "Maximum alerts per node per minute")

	if err := rootCmd.Execute(); err != nil {
		logger.WithError(err).Fatal("Failed to execute command")
	}
}

func runAlertEngine(cmd *cobra.Command, args []string) error {
	// Configure logging
	if err := configureLogging(); err != nil {
		return fmt.Errorf("failed to configure logging: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"port":                config.Port,
		"backend_url":         config.BackendURL,
		"processing_interval": config.ProcessingInterval,
		"anomaly_threshold":   config.AnomalyThreshold,
		"critical_threshold":  config.CriticalThreshold,
		"version":             version,
	}).Info("Starting GPU Shield alert engine")

	// Create alert engine instance
	engine := NewAlertEngine(config, logger)

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

	// Start alert engine
	return engine.Start(ctx)
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

// NewAlertEngine creates a new alert engine instance
func NewAlertEngine(cfg *AlertEngineConfig, log *logrus.Logger) *AlertEngine {
	return &AlertEngine{
		config: cfg,
		logger: log,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		alertCount: make(map[string]int),
	}
}

// Start starts the alert engine service
func (ae *AlertEngine) Start(ctx context.Context) error {
	// Start HTTP server
	mux := http.NewServeMux()
	ae.setupRoutes(mux)

	ae.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", ae.config.Port),
		Handler: mux,
	}

	// Start background workers
	go ae.eventProcessor(ctx)
	go ae.metricsServer(ctx)
	go ae.rateLimitReset(ctx)

	// Start HTTP server
	go func() {
		ae.logger.WithField("port", ae.config.Port).Info("Starting HTTP server")
		if err := ae.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			ae.logger.WithError(err).Error("HTTP server error")
		}
	}()

	// Wait for shutdown
	<-ctx.Done()
	ae.logger.Info("Shutting down alert engine")

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := ae.server.Shutdown(shutdownCtx); err != nil {
		ae.logger.WithError(err).Error("Server shutdown error")
	}

	return nil
}

// setupRoutes configures HTTP routes
func (ae *AlertEngine) setupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", ae.healthHandler)
	mux.HandleFunc("/process", ae.processHandler)
	mux.HandleFunc("/metrics", ae.prometheusHandler)
}

// healthHandler handles health check requests
func (ae *AlertEngine) healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"status":    "healthy",
		"version":   version,
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// processHandler handles manual processing requests
func (ae *AlertEngine) processHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ae.logger.Info("Manual processing triggered")
	go ae.processEvents()

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "processing",
	})
}

// prometheusHandler serves Prometheus metrics
func (ae *AlertEngine) prometheusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	totalAlerts := 0
	for _, count := range ae.alertCount {
		totalAlerts += count
	}

	metrics := fmt.Sprintf(`# HELP gpushield_alert_engine_alerts_generated Total alerts generated
# TYPE gpushield_alert_engine_alerts_generated counter
gpushield_alert_engine_alerts_generated %d

# HELP gpushield_alert_engine_version Alert engine version info
# TYPE gpushield_alert_engine_version gauge
gpushield_alert_engine_version{version="%s"} 1
`, totalAlerts, version)

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(metrics))
}

// eventProcessor processes security events and telemetry data
func (ae *AlertEngine) eventProcessor(ctx context.Context) {
	ticker := time.NewTicker(ae.config.ProcessingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ae.processEvents()
		}
	}
}

// processEvents fetches and processes security events and telemetry
func (ae *AlertEngine) processEvents() {
	ae.logger.Debug("Processing security events and telemetry")

	// Process security events
	if err := ae.processSecurityEvents(); err != nil {
		ae.logger.WithError(err).Error("Failed to process security events")
	}

	// Process telemetry anomalies
	if err := ae.processTelemetryAnomalies(); err != nil {
		ae.logger.WithError(err).Error("Failed to process telemetry anomalies")
	}
}

// processSecurityEvents fetches and processes security events from backend
func (ae *AlertEngine) processSecurityEvents() error {
	// Fetch recent security events (last 5 minutes)
	since := time.Now().Add(-5 * time.Minute)
	url := fmt.Sprintf("%s/api/v1/security-events?since=%s&limit=100",
		ae.config.BackendURL, since.Format(time.RFC3339))

	resp, err := ae.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch security events: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("backend returned status %d", resp.StatusCode)
	}

	var events []SecurityEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return fmt.Errorf("failed to decode security events: %w", err)
	}

	ae.logger.WithField("event_count", len(events)).Debug("Fetched security events")

	// Process each event
	for _, event := range events {
		if err := ae.processSecurityEvent(event); err != nil {
			ae.logger.WithError(err).WithField("event_id", event.ID).Error("Failed to process security event")
		}
	}

	return nil
}

// processSecurityEvent processes a single security event
func (ae *AlertEngine) processSecurityEvent(event SecurityEvent) error {
	// Check rate limiting
	if ae.alertCount[event.NodeID] >= ae.config.MaxAlertsPerMinute {
		ae.logger.WithField("node_id", event.NodeID).Warn("Rate limit exceeded for node")
		return nil
	}

	// Determine alert severity based on event type and risk score
	severity := ae.determineSeverity(event.EventType, event.RiskScore)

	// Skip low-risk events unless they're part of a pattern
	if severity == "low" && event.RiskScore < 0.3 {
		return nil
	}

	// Create alert
	alert := Alert{
		NodeID:           event.NodeID,
		Title:            ae.generateAlertTitle(event),
		Description:      ae.generateAlertDescription(event),
		Severity:         severity,
		RuleID:           fmt.Sprintf("security_event_%s", event.EventType),
		Confidence:       event.RiskScore,
		SecurityEventIDs: []string{event.ID},
		FirstSeen:        event.Timestamp,
		LastSeen:         event.Timestamp,
		ResponseActions:  ae.generateResponseActions(event),
	}

	// Send alert to backend
	if err := ae.createAlert(alert); err != nil {
		return fmt.Errorf("failed to create alert: %w", err)
	}

	ae.alertCount[event.NodeID]++
	ae.logger.WithFields(logrus.Fields{
		"node_id":    event.NodeID,
		"event_type": event.EventType,
		"severity":   severity,
		"risk_score": event.RiskScore,
	}).Info("Created security alert")

	return nil
}

// processTelemetryAnomalies fetches and processes telemetry anomalies
func (ae *AlertEngine) processTelemetryAnomalies() error {
	// Fetch telemetry records with high anomaly scores
	url := fmt.Sprintf("%s/api/v1/telemetry/query", ae.config.BackendURL)

	query := map[string]interface{}{
		"min_anomaly_score": ae.config.AnomalyThreshold,
		"processed":         true,
		"limit":             50,
		"time_range": map[string]string{
			"start": time.Now().Add(-10 * time.Minute).Format(time.RFC3339),
			"end":   time.Now().Format(time.RFC3339),
		},
	}

	jsonData, err := json.Marshal(query)
	if err != nil {
		return fmt.Errorf("failed to marshal query: %w", err)
	}

	resp, err := ae.httpClient.Post(url, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to query telemetry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("backend returned status %d", resp.StatusCode)
	}

	var result struct {
		Items []TelemetryRecord `json:"items"`
		Total int               `json:"total"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode telemetry response: %w", err)
	}

	ae.logger.WithField("anomaly_count", len(result.Items)).Debug("Fetched telemetry anomalies")

	// Group anomalies by node for correlation
	nodeAnomalies := make(map[string][]TelemetryRecord)
	for _, record := range result.Items {
		nodeID := record.Metadata["node_id"].(string)
		nodeAnomalies[nodeID] = append(nodeAnomalies[nodeID], record)
	}

	// Process anomalies per node
	for nodeID, anomalies := range nodeAnomalies {
		if err := ae.processTelemetryAnomaliesForNode(nodeID, anomalies); err != nil {
			ae.logger.WithError(err).WithField("node_id", nodeID).Error("Failed to process node anomalies")
		}
	}

	return nil
}

// processTelemetryAnomaliesForNode processes anomalies for a specific node
func (ae *AlertEngine) processTelemetryAnomaliesForNode(nodeID string, anomalies []TelemetryRecord) error {
	if len(anomalies) == 0 {
		return nil
	}

	// Check rate limiting
	if ae.alertCount[nodeID] >= ae.config.MaxAlertsPerMinute {
		return nil
	}

	// Calculate average anomaly score
	totalScore := 0.0
	recordIDs := make([]string, len(anomalies))
	for i, anomaly := range anomalies {
		totalScore += anomaly.AnomalyScore
		recordIDs[i] = anomaly.ID
	}
	avgScore := totalScore / float64(len(anomalies))

	// Determine severity
	var severity string
	if avgScore >= ae.config.CriticalThreshold {
		severity = "critical"
	} else if avgScore >= 0.8 {
		severity = "high"
	} else if avgScore >= 0.6 {
		severity = "medium"
	} else {
		severity = "low"
	}

	// Create alert
	alert := Alert{
		NodeID:             nodeID,
		Title:              fmt.Sprintf("GPU Anomaly Detected - %d anomalous metrics", len(anomalies)),
		Description:        fmt.Sprintf("Detected %d anomalous GPU metrics with average score %.2f", len(anomalies), avgScore),
		Severity:           severity,
		RuleID:             "telemetry_anomaly_correlation",
		Confidence:         avgScore,
		TelemetryRecordIDs: recordIDs,
		FirstSeen:          anomalies[0].Timestamp,
		LastSeen:           anomalies[len(anomalies)-1].Timestamp,
		ResponseActions:    ae.generateAnomalyResponseActions(avgScore),
	}

	// Send alert to backend
	if err := ae.createAlert(alert); err != nil {
		return fmt.Errorf("failed to create anomaly alert: %w", err)
	}

	ae.alertCount[nodeID]++
	ae.logger.WithFields(logrus.Fields{
		"node_id":       nodeID,
		"anomaly_count": len(anomalies),
		"avg_score":     avgScore,
		"severity":      severity,
	}).Info("Created anomaly alert")

	return nil
}

// determineSeverity determines alert severity based on event type and risk score
func (ae *AlertEngine) determineSeverity(eventType string, riskScore float64) string {
	// High-risk event types
	highRiskEvents := map[string]bool{
		"firmware_hash":      true,
		"module_load":        true,
		"anomalous_behavior": true,
	}

	if highRiskEvents[eventType] || riskScore >= ae.config.CriticalThreshold {
		return "critical"
	} else if riskScore >= 0.7 {
		return "high"
	} else if riskScore >= 0.5 {
		return "medium"
	}
	return "low"
}

// generateAlertTitle generates a descriptive alert title
func (ae *AlertEngine) generateAlertTitle(event SecurityEvent) string {
	titles := map[string]string{
		"driver_ioctl":       "Suspicious GPU Driver IOCTL",
		"dma_buf_mapping":    "Unusual DMA Buffer Mapping",
		"firmware_hash":      "GPU Firmware Integrity Violation",
		"module_load":        "Unauthorized Kernel Module Load",
		"syscall":            "Suspicious System Call",
		"anomalous_behavior": "Anomalous GPU Behavior Detected",
	}

	if title, exists := titles[event.EventType]; exists {
		return title
	}
	return fmt.Sprintf("Security Event: %s", event.EventType)
}

// generateAlertDescription generates a detailed alert description
func (ae *AlertEngine) generateAlertDescription(event SecurityEvent) string {
	base := fmt.Sprintf("Security event of type '%s' detected with risk score %.2f",
		event.EventType, event.RiskScore)

	if event.ProcessInfo.PID != 0 {
		base += fmt.Sprintf(" from process %s (PID: %d, User: %s)",
			event.ProcessInfo.Name, event.ProcessInfo.PID, event.ProcessInfo.User)
	}

	return base
}

// generateResponseActions generates automated response actions
func (ae *AlertEngine) generateResponseActions(event SecurityEvent) []map[string]interface{} {
	actions := []map[string]interface{}{}

	// High-risk events get immediate response
	if event.RiskScore >= ae.config.CriticalThreshold {
		actions = append(actions, map[string]interface{}{
			"type":        "isolate_process",
			"target":      event.ProcessInfo.PID,
			"description": "Isolate suspicious process",
		})
	}

	// Always collect additional forensics
	actions = append(actions, map[string]interface{}{
		"type":        "collect_forensics",
		"target":      event.NodeID,
		"description": "Collect additional forensic data",
	})

	return actions
}

// generateAnomalyResponseActions generates response actions for anomalies
func (ae *AlertEngine) generateAnomalyResponseActions(avgScore float64) []map[string]interface{} {
	actions := []map[string]interface{}{}

	if avgScore >= ae.config.CriticalThreshold {
		actions = append(actions, map[string]interface{}{
			"type":        "throttle_gpu",
			"description": "Throttle GPU performance to safe levels",
		})
	}

	actions = append(actions, map[string]interface{}{
		"type":        "increase_monitoring",
		"description": "Increase telemetry collection frequency",
	})

	return actions
}

// createAlert sends an alert to the backend
func (ae *AlertEngine) createAlert(alert Alert) error {
	url := fmt.Sprintf("%s/api/v1/alerts/", ae.config.BackendURL)

	jsonData, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	resp, err := ae.httpClient.Post(url, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to send alert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("backend returned status %d", resp.StatusCode)
	}

	return nil
}

// rateLimitReset resets rate limiting counters
func (ae *AlertEngine) rateLimitReset(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ae.alertCount = make(map[string]int)
		}
	}
}

// metricsServer starts a separate metrics server
func (ae *AlertEngine) metricsServer(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", ae.prometheusHandler)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", ae.config.MetricsPort),
		Handler: mux,
	}

	go func() {
		ae.logger.WithField("port", ae.config.MetricsPort).Info("Starting metrics server")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			ae.logger.WithError(err).Error("Metrics server error")
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
}
