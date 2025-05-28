package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

const (
	version = "0.1.0"
)

// this is configuration for the backend alert engine
type AlertEngineConfig struct {
	Port               int
	BackendURL         string
	LogLevel           string
	ProcessingInterval time.Duration
	AnomalyThreshold   float64
	CriticalThreshold  float64
	WebhookURL         string
	SlackWebhook       string
	EmailSMTP          string
}

// Alert represents an alert in the system
type Alert struct {
	ID                 string                   `json:"id"`
	NodeID             string                   `json:"node_id"`
	Title              string                   `json:"title"`
	Description        string                   `json:"description"`
	Severity           string                   `json:"severity"`
	Status             string                   `json:"status"`
	RuleID             string                   `json:"rule_id"`
	Confidence         float64                  `json:"confidence"`
	SecurityEventIDs   []string                 `json:"security_event_ids,omitempty"`
	TelemetryRecordIDs []string                 `json:"telemetry_record_ids,omitempty"`
	FirstSeen          time.Time                `json:"first_seen"`
	LastSeen           time.Time                `json:"last_seen"`
	ResponseActions    []map[string]interface{} `json:"response_actions,omitempty"`
	CreatedAt          time.Time                `json:"created_at"`
	UpdatedAt          time.Time                `json:"updated_at"`
}

// SecurityEvent represents a security event
type SecurityEvent struct {
	ID          string                 `json:"id"`
	NodeID      string                 `json:"node_id"`
	EventType   string                 `json:"event_type"`
	Timestamp   time.Time              `json:"timestamp"`
	RiskScore   float64                `json:"risk_score"`
	Details     map[string]interface{} `json:"details"`
	ProcessInfo ProcessInfo            `json:"process_info,omitempty"`
	Processed   bool                   `json:"processed"`
}

// ProcessInfo represents process information
type ProcessInfo struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	User string `json:"user"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
}

// TelemetryRecord represents telemetry data
type TelemetryRecord struct {
	ID           string                 `json:"id"`
	GPUID        string                 `json:"gpu_id"`
	SensorID     string                 `json:"sensor_id"`
	Timestamp    time.Time              `json:"timestamp"`
	Metrics      map[string]interface{} `json:"metrics"`
	Metadata     map[string]interface{} `json:"metadata"`
	AnomalyScore float64                `json:"anomaly_score"`
	Processed    bool                   `json:"processed"`
}

// BackendAlertEngine manages alert processing for the backend
type BackendAlertEngine struct {
	config     *AlertEngineConfig
	logger     *logrus.Logger
	httpClient *http.Client
	server     *http.Server
}

func main() {
	config := &AlertEngineConfig{
		Port:               8082,
		BackendURL:         getEnv("BACKEND_URL", "http://localhost:8000"),
		LogLevel:           getEnv("LOG_LEVEL", "info"),
		ProcessingInterval: 30 * time.Second,
		AnomalyThreshold:   0.7,
		CriticalThreshold:  0.9,
		WebhookURL:         getEnv("WEBHOOK_URL", ""),
		SlackWebhook:       getEnv("SLACK_WEBHOOK", ""),
		EmailSMTP:          getEnv("EMAIL_SMTP", ""),
	}

	// Configure logging
	logger := logrus.New()
	level, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		log.Fatalf("Invalid log level: %v", err)
	}
	logger.SetLevel(level)
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	})

	logger.WithFields(logrus.Fields{
		"port":                config.Port,
		"backend_url":         config.BackendURL,
		"processing_interval": config.ProcessingInterval,
		"anomaly_threshold":   config.AnomalyThreshold,
		"critical_threshold":  config.CriticalThreshold,
		"version":             version,
	}).Info("Starting GPU Shield backend alert engine")

	// Create alert engine
	engine := NewBackendAlertEngine(config, logger)

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
	if err := engine.Start(ctx); err != nil {
		logger.WithError(err).Fatal("Failed to start alert engine")
	}
}

// NewBackendAlertEngine creates a new backend alert engine
func NewBackendAlertEngine(config *AlertEngineConfig, logger *logrus.Logger) *BackendAlertEngine {
	return &BackendAlertEngine{
		config: config,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Start starts the backend alert engine
func (bae *BackendAlertEngine) Start(ctx context.Context) error {
	// Setup HTTP server
	router := mux.NewRouter()
	bae.setupRoutes(router)

	bae.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", bae.config.Port),
		Handler: router,
	}

	// Start background processing
	go bae.processAlerts(ctx)

	// Start HTTP server
	go func() {
		bae.logger.WithField("port", bae.config.Port).Info("Starting HTTP server")
		if err := bae.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			bae.logger.WithError(err).Error("HTTP server error")
		}
	}()

	// Wait for shutdown
	<-ctx.Done()
	bae.logger.Info("Shutting down backend alert engine")

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return bae.server.Shutdown(shutdownCtx)
}

// setupRoutes configures HTTP routes
func (bae *BackendAlertEngine) setupRoutes(router *mux.Router) {
	router.HandleFunc("/health", bae.healthHandler).Methods("GET")
	router.HandleFunc("/alerts", bae.getAlertsHandler).Methods("GET")
	router.HandleFunc("/alerts/{id}", bae.getAlertHandler).Methods("GET")
	router.HandleFunc("/alerts/{id}/acknowledge", bae.acknowledgeAlertHandler).Methods("POST")
	router.HandleFunc("/alerts/{id}/resolve", bae.resolveAlertHandler).Methods("POST")
	router.HandleFunc("/process", bae.processHandler).Methods("POST")
	router.HandleFunc("/metrics", bae.metricsHandler).Methods("GET")
}

// healthHandler handles health check requests
func (bae *BackendAlertEngine) healthHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":    "healthy",
		"version":   version,
		"timestamp": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getAlertsHandler returns all alerts
func (bae *BackendAlertEngine) getAlertsHandler(w http.ResponseWriter, r *http.Request) {
	// Query parameters
	status := r.URL.Query().Get("status")
	severity := r.URL.Query().Get("severity")
	nodeID := r.URL.Query().Get("node_id")

	// Build query URL
	url := fmt.Sprintf("%s/api/v1/alerts/", bae.config.BackendURL)
	params := []string{}
	if status != "" {
		params = append(params, fmt.Sprintf("status=%s", status))
	}
	if severity != "" {
		params = append(params, fmt.Sprintf("severity=%s", severity))
	}
	if nodeID != "" {
		params = append(params, fmt.Sprintf("node_id=%s", nodeID))
	}
	if len(params) > 0 {
		url += "?" + strings.Join(params, "&")
	}

	// Fetch alerts from backend
	resp, err := bae.httpClient.Get(url)
	if err != nil {
		http.Error(w, "Failed to fetch alerts", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Forward response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
}

// getAlertHandler returns a specific alert
func (bae *BackendAlertEngine) getAlertHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	url := fmt.Sprintf("%s/api/v1/alerts/%s", bae.config.BackendURL, alertID)
	resp, err := bae.httpClient.Get(url)
	if err != nil {
		http.Error(w, "Failed to fetch alert", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)

	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
}

// acknowledgeAlertHandler acknowledges an alert
func (bae *BackendAlertEngine) acknowledgeAlertHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	// Update alert status
	updateData := map[string]interface{}{
		"status":     "acknowledged",
		"updated_at": time.Now(),
	}

	jsonData, _ := json.Marshal(updateData)
	url := fmt.Sprintf("%s/api/v1/alerts/%s", bae.config.BackendURL, alertID)

	req, err := http.NewRequest("PATCH", url, strings.NewReader(string(jsonData)))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := bae.httpClient.Do(req)
	if err != nil {
		http.Error(w, "Failed to acknowledge alert", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "acknowledged",
	})
}

// resolveAlertHandler resolves an alert
func (bae *BackendAlertEngine) resolveAlertHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]

	updateData := map[string]interface{}{
		"status":     "resolved",
		"updated_at": time.Now(),
	}

	jsonData, _ := json.Marshal(updateData)
	url := fmt.Sprintf("%s/api/v1/alerts/%s", bae.config.BackendURL, alertID)

	req, err := http.NewRequest("PATCH", url, strings.NewReader(string(jsonData)))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := bae.httpClient.Do(req)
	if err != nil {
		http.Error(w, "Failed to resolve alert", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "resolved",
	})
}

// processHandler triggers manual alert processing
func (bae *BackendAlertEngine) processHandler(w http.ResponseWriter, r *http.Request) {
	bae.logger.Info("Manual alert processing triggered")
	go bae.processUnprocessedEvents()

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "processing",
	})
}

// metricsHandler serves Prometheus metrics
func (bae *BackendAlertEngine) metricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := fmt.Sprintf(`# HELP gpushield_backend_alert_engine_version Backend alert engine version info
# TYPE gpushield_backend_alert_engine_version gauge
gpushield_backend_alert_engine_version{version="%s"} 1
`, version)

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(metrics))
}

// processAlerts continuously processes alerts
func (bae *BackendAlertEngine) processAlerts(ctx context.Context) {
	ticker := time.NewTicker(bae.config.ProcessingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bae.processUnprocessedEvents()
		}
	}
}

// processUnprocessedEvents processes unprocessed security events and telemetry
func (bae *BackendAlertEngine) processUnprocessedEvents() {
	bae.logger.Debug("Processing unprocessed events")

	// Process security events
	if err := bae.processSecurityEvents(); err != nil {
		bae.logger.WithError(err).Error("Failed to process security events")
	}

	// Process telemetry anomalies
	if err := bae.processTelemetryAnomalies(); err != nil {
		bae.logger.WithError(err).Error("Failed to process telemetry anomalies")
	}
}

// processSecurityEvents processes unprocessed security events
func (bae *BackendAlertEngine) processSecurityEvents() error {
	url := fmt.Sprintf("%s/api/v1/security-events?processed=false&limit=100", bae.config.BackendURL)

	resp, err := bae.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch security events: %w", err)
	}
	defer resp.Body.Close()

	var events []SecurityEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return fmt.Errorf("failed to decode security events: %w", err)
	}

	bae.logger.WithField("event_count", len(events)).Debug("Processing security events")

	for _, event := range events {
		if err := bae.processSecurityEvent(event); err != nil {
			bae.logger.WithError(err).WithField("event_id", event.ID).Error("Failed to process security event")
		}
	}

	return nil
}

// processSecurityEvent processes a single security event
func (bae *BackendAlertEngine) processSecurityEvent(event SecurityEvent) error {
	// Determine severity
	severity := bae.determineSeverity(event.EventType, event.RiskScore)

	// Create alert
	alert := Alert{
		NodeID:           event.NodeID,
		Title:            bae.generateAlertTitle(event),
		Description:      bae.generateAlertDescription(event),
		Severity:         severity,
		Status:           "open",
		RuleID:           fmt.Sprintf("security_event_%s", event.EventType),
		Confidence:       event.RiskScore,
		SecurityEventIDs: []string{event.ID},
		FirstSeen:        event.Timestamp,
		LastSeen:         event.Timestamp,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Send alert to backend
	if err := bae.createAlert(alert); err != nil {
		return fmt.Errorf("failed to create alert: %w", err)
	}

	// Mark event as processed
	if err := bae.markEventProcessed(event.ID); err != nil {
		bae.logger.WithError(err).Warn("Failed to mark event as processed")
	}

	// Send notifications for critical alerts
	if severity == "critical" {
		bae.sendNotifications(alert)
	}

	return nil
}

// processTelemetryAnomalies processes telemetry anomalies
func (bae *BackendAlertEngine) processTelemetryAnomalies() error {
	url := fmt.Sprintf("%s/api/v1/telemetry/query", bae.config.BackendURL)

	query := map[string]interface{}{
		"min_anomaly_score": bae.config.AnomalyThreshold,
		"processed":         false,
		"limit":             50,
	}

	jsonData, _ := json.Marshal(query)
	resp, err := bae.httpClient.Post(url, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to query telemetry: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Items []TelemetryRecord `json:"items"`
		Total int               `json:"total"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode telemetry response: %w", err)
	}

	bae.logger.WithField("anomaly_count", len(result.Items)).Debug("Processing telemetry anomalies")

	// Group by node
	nodeAnomalies := make(map[string][]TelemetryRecord)
	for _, record := range result.Items {
		nodeID := record.Metadata["node_id"].(string)
		nodeAnomalies[nodeID] = append(nodeAnomalies[nodeID], record)
	}

	// Process each node's anomalies
	for nodeID, anomalies := range nodeAnomalies {
		if err := bae.processNodeAnomalies(nodeID, anomalies); err != nil {
			bae.logger.WithError(err).WithField("node_id", nodeID).Error("Failed to process node anomalies")
		}
	}

	return nil
}

// processNodeAnomalies processes anomalies for a specific node
func (bae *BackendAlertEngine) processNodeAnomalies(nodeID string, anomalies []TelemetryRecord) error {
	if len(anomalies) == 0 {
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
	if avgScore >= bae.config.CriticalThreshold {
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
		Status:             "open",
		RuleID:             "telemetry_anomaly_correlation",
		Confidence:         avgScore,
		TelemetryRecordIDs: recordIDs,
		FirstSeen:          anomalies[0].Timestamp,
		LastSeen:           anomalies[len(anomalies)-1].Timestamp,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}

	// Send alert to backend
	if err := bae.createAlert(alert); err != nil {
		return fmt.Errorf("failed to create anomaly alert: %w", err)
	}

	// Mark records as processed
	for _, record := range anomalies {
		if err := bae.markTelemetryProcessed(record.ID); err != nil {
			bae.logger.WithError(err).Warn("Failed to mark telemetry as processed")
		}
	}

	return nil
}

// Helper functions
func (bae *BackendAlertEngine) determineSeverity(eventType string, riskScore float64) string {
	highRiskEvents := map[string]bool{
		"firmware_hash":      true,
		"module_load":        true,
		"anomalous_behavior": true,
	}

	if highRiskEvents[eventType] || riskScore >= bae.config.CriticalThreshold {
		return "critical"
	} else if riskScore >= 0.7 {
		return "high"
	} else if riskScore >= 0.5 {
		return "medium"
	}
	return "low"
}

func (bae *BackendAlertEngine) generateAlertTitle(event SecurityEvent) string {
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

func (bae *BackendAlertEngine) generateAlertDescription(event SecurityEvent) string {
	base := fmt.Sprintf("Security event of type '%s' detected with risk score %.2f",
		event.EventType, event.RiskScore)

	if event.ProcessInfo.PID != 0 {
		base += fmt.Sprintf(" from process %s (PID: %d, User: %s)",
			event.ProcessInfo.Name, event.ProcessInfo.PID, event.ProcessInfo.User)
	}

	return base
}

func (bae *BackendAlertEngine) createAlert(alert Alert) error {
	url := fmt.Sprintf("%s/api/v1/alerts/", bae.config.BackendURL)
	jsonData, _ := json.Marshal(alert)

	resp, err := bae.httpClient.Post(url, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("backend returned status %d", resp.StatusCode)
	}

	return nil
}

func (bae *BackendAlertEngine) markEventProcessed(eventID string) error {
	url := fmt.Sprintf("%s/api/v1/security-events/%s", bae.config.BackendURL, eventID)
	updateData := map[string]interface{}{"processed": true}
	jsonData, _ := json.Marshal(updateData)

	req, err := http.NewRequest("PATCH", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := bae.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (bae *BackendAlertEngine) markTelemetryProcessed(recordID string) error {
	url := fmt.Sprintf("%s/api/v1/telemetry/records/%s", bae.config.BackendURL, recordID)
	updateData := map[string]interface{}{"processed": true}
	jsonData, _ := json.Marshal(updateData)

	req, err := http.NewRequest("PATCH", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := bae.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (bae *BackendAlertEngine) sendNotifications(alert Alert) {
	// Send webhook notification
	if bae.config.WebhookURL != "" {
		go bae.sendWebhook(alert)
	}

	// Send Slack notification
	if bae.config.SlackWebhook != "" {
		go bae.sendSlackNotification(alert)
	}
}

func (bae *BackendAlertEngine) sendWebhook(alert Alert) {
	jsonData, _ := json.Marshal(alert)
	resp, err := bae.httpClient.Post(bae.config.WebhookURL, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		bae.logger.WithError(err).Error("Failed to send webhook notification")
		return
	}
	defer resp.Body.Close()
}

func (bae *BackendAlertEngine) sendSlackNotification(alert Alert) {
	message := map[string]interface{}{
		"text": fmt.Sprintf("🚨 *%s Alert*: %s", strings.ToUpper(alert.Severity), alert.Title),
		"attachments": []map[string]interface{}{
			{
				"color": bae.getSlackColor(alert.Severity),
				"fields": []map[string]interface{}{
					{"title": "Node", "value": alert.NodeID, "short": true},
					{"title": "Confidence", "value": fmt.Sprintf("%.2f", alert.Confidence), "short": true},
					{"title": "Description", "value": alert.Description, "short": false},
				},
			},
		},
	}

	jsonData, _ := json.Marshal(message)
	resp, err := bae.httpClient.Post(bae.config.SlackWebhook, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		bae.logger.WithError(err).Error("Failed to send Slack notification")
		return
	}
	defer resp.Body.Close()
}

func (bae *BackendAlertEngine) getSlackColor(severity string) string {
	colors := map[string]string{
		"critical": "danger",
		"high":     "warning",
		"medium":   "good",
		"low":      "#36a64f",
	}
	if color, exists := colors[severity]; exists {
		return color
	}
	return "good"
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
