package ebpf

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// ManagerConfig holds configuration for the eBPF manager
type ManagerConfig struct {
	BackendURL      string         `json:"backend_url"`
	NodeID          string         `json:"node_id"`
	FlushInterval   time.Duration  `json:"flush_interval"`
	BatchSize       int            `json:"batch_size"`
	RiskThresholds  RiskThresholds `json:"risk_thresholds"`
	EnabledMonitors []string       `json:"enabled_monitors"`
}

// RiskThresholds defines risk scoring thresholds
type RiskThresholds struct {
	IOCTLSuspicious   float64 `json:"ioctl_suspicious"`
	DMASuspicious     float64 `json:"dma_suspicious"`
	ProcessSuspicious float64 `json:"process_suspicious"`
	SyscallSuspicious float64 `json:"syscall_suspicious"`
	ModuleSuspicious  float64 `json:"module_suspicious"`
}

// SecurityEvent represents a processed security event
type SecurityEvent struct {
	ID          string                 `json:"id,omitempty"`
	NodeID      string                 `json:"node_id"`
	EventType   string                 `json:"event_type"`
	Timestamp   time.Time              `json:"timestamp"`
	RiskScore   float64                `json:"risk_score"`
	Details     map[string]interface{} `json:"details"`
	ProcessInfo ProcessEventInfo       `json:"process_info"`
	RawEvent    *GPUEvent              `json:"raw_event,omitempty"`
}

// ProcessEventInfo represents process information in security events
type ProcessEventInfo struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	User string `json:"user"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
}

// Manager coordinates eBPF monitoring and security event processing
type Manager struct {
	config     *ManagerConfig
	logger     *logrus.Logger
	loader     *Loader
	httpClient *http.Client
	eventBatch []SecurityEvent
	stopCh     chan struct{}
}

// NewManager creates a new eBPF manager
func NewManager(config *ManagerConfig, logger *logrus.Logger) *Manager {
	return &Manager{
		config: config,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		eventBatch: make([]SecurityEvent, 0, config.BatchSize),
		stopCh:     make(chan struct{}),
	}
}

// Start starts the eBPF manager
func (m *Manager) Start(ctx context.Context) error {
	m.logger.WithFields(logrus.Fields{
		"node_id":        m.config.NodeID,
		"backend_url":    m.config.BackendURL,
		"flush_interval": m.config.FlushInterval,
		"batch_size":     m.config.BatchSize,
	}).Info("Starting eBPF security manager")

	// Create and configure eBPF loader
	loaderConfig := m.createLoaderConfig()
	m.loader = NewLoader(loaderConfig, m.logger)

	// Load eBPF programs
	if err := m.loader.Load(ctx); err != nil {
		return fmt.Errorf("failed to load eBPF programs: %w", err)
	}

	// Start event processing
	go m.processEvents(ctx)
	go m.flushEvents(ctx)

	m.logger.Info("eBPF security manager started successfully")
	return nil
}

// Stop stops the eBPF manager
func (m *Manager) Stop() {
	m.logger.Info("Stopping eBPF security manager")
	close(m.stopCh)

	if m.loader != nil {
		m.loader.Unload()
	}

	// Flush any remaining events
	if len(m.eventBatch) > 0 {
		m.sendEventBatch()
	}
}

// createLoaderConfig creates loader configuration based on manager config
func (m *Manager) createLoaderConfig() *LoaderConfig {
	config := DefaultLoaderConfig()

	// Configure monitors based on enabled list
	enabledMap := make(map[string]bool)
	for _, monitor := range m.config.EnabledMonitors {
		enabledMap[monitor] = true
	}

	config.EnableIOCTLMonitoring = enabledMap["ioctl"] || len(m.config.EnabledMonitors) == 0
	config.EnableDMAMonitoring = enabledMap["dma"] || len(m.config.EnabledMonitors) == 0
	config.EnableProcessMonitoring = enabledMap["process"] || len(m.config.EnabledMonitors) == 0
	config.EnableSyscallMonitoring = enabledMap["syscall"] || len(m.config.EnabledMonitors) == 0
	config.EnableModuleMonitoring = enabledMap["module"] || len(m.config.EnabledMonitors) == 0

	return config
}

// processEvents processes eBPF events and converts them to security events
func (m *Manager) processEvents(ctx context.Context) {
	m.logger.Info("Starting eBPF event processing")

	eventCh := m.loader.Events()

	for {
		select {
		case <-m.stopCh:
			m.logger.Info("Stopping eBPF event processing")
			return
		case <-ctx.Done():
			m.logger.Info("Context cancelled, stopping eBPF event processing")
			return
		case event := <-eventCh:
			if event == nil {
				continue
			}

			// Process the event
			securityEvent := m.processGPUEvent(event)
			if securityEvent != nil {
				m.addEventToBatch(*securityEvent)
			}
		}
	}
}

// processGPUEvent processes a single GPU event and converts it to a security event
func (m *Manager) processGPUEvent(event *GPUEvent) *SecurityEvent {
	var eventType string
	var riskScore float64
	var details map[string]interface{}

	switch event.EventType {
	case EventDriverIOCTL:
		eventType = "driver_ioctl"
		riskScore, details = m.analyzeIOCTLEvent(event)
	case EventDMABufMapping:
		eventType = "dma_buf_mapping"
		riskScore, details = m.analyzeDMAEvent(event)
	case EventProcessStart:
		eventType = "process_start"
		riskScore, details = m.analyzeProcessEvent(event)
	case EventProcessExit:
		eventType = "process_exit"
		riskScore, details = m.analyzeProcessEvent(event)
	case EventSyscall:
		eventType = "syscall"
		riskScore, details = m.analyzeSyscallEvent(event)
	case EventModuleLoad:
		eventType = "module_load"
		riskScore, details = m.analyzeModuleEvent(event)
	default:
		m.logger.WithField("event_type", event.EventType).Warn("Unknown event type")
		return nil
	}

	// Skip low-risk events
	if riskScore < 0.1 {
		return nil
	}

	return &SecurityEvent{
		NodeID:    m.config.NodeID,
		EventType: eventType,
		Timestamp: time.Unix(0, int64(event.Timestamp)),
		RiskScore: riskScore,
		Details:   details,
		ProcessInfo: ProcessEventInfo{
			PID:  int(event.PID),
			Name: event.Comm,
			UID:  int(event.UID),
			GID:  int(event.GID),
		},
		RawEvent: event,
	}
}

// analyzeIOCTLEvent analyzes IOCTL events for suspicious activity
func (m *Manager) analyzeIOCTLEvent(event *GPUEvent) (float64, map[string]interface{}) {
	ioctlData := m.loader.ParseIOCTLData(event.Data)
	if ioctlData == nil {
		return 0.0, nil
	}

	details := map[string]interface{}{
		"major":  ioctlData.Major,
		"minor":  ioctlData.Minor,
		"cmd":    ioctlData.Cmd,
		"arg":    ioctlData.Arg,
		"ret":    ioctlData.Ret,
		"device": fmt.Sprintf("/dev/%d:%d", ioctlData.Major, ioctlData.Minor),
	}

	riskScore := 0.1 // Base risk for any GPU IOCTL

	// Check for suspicious IOCTL commands
	suspiciousCommands := map[uint32]float64{
		0xc0406400: 0.8, // Example: Direct memory access
		0xc0406401: 0.7, // Example: Firmware manipulation
		0xc0406402: 0.9, // Example: Debug interface access
	}

	if score, exists := suspiciousCommands[ioctlData.Cmd]; exists {
		riskScore = score
		details["suspicious_reason"] = "Known suspicious IOCTL command"
	}

	// Check for unusual process making IOCTL calls
	suspiciousProcesses := []string{"nc", "netcat", "wget", "curl", "python", "perl", "bash", "sh"}
	for _, proc := range suspiciousProcesses {
		if strings.Contains(strings.ToLower(event.Comm), proc) {
			riskScore += 0.3
			details["suspicious_reason"] = "Unusual process accessing GPU"
			break
		}
	}

	// Check for failed IOCTLs (might indicate probing)
	if ioctlData.Ret < 0 {
		riskScore += 0.2
		details["failed_ioctl"] = true
	}

	return min(riskScore, 1.0), details
}

// analyzeDMAEvent analyzes DMA mapping events
func (m *Manager) analyzeDMAEvent(event *GPUEvent) (float64, map[string]interface{}) {
	dmaData := m.loader.ParseDMAData(event.Data)
	if dmaData == nil {
		return 0.0, nil
	}

	details := map[string]interface{}{
		"dma_addr":  dmaData.DMAAddr,
		"size":      dmaData.Size,
		"direction": dmaData.Direction,
		"flags":     dmaData.Flags,
	}

	riskScore := 0.1 // Base risk for DMA operations

	// Large DMA mappings might be suspicious
	if dmaData.Size > 1024*1024*100 { // > 100MB
		riskScore += 0.4
		details["large_mapping"] = true
	}

	// Unusual DMA directions
	if dmaData.Direction > 2 { // DMA_BIDIRECTIONAL = 0, DMA_TO_DEVICE = 1, DMA_FROM_DEVICE = 2
		riskScore += 0.3
		details["unusual_direction"] = true
	}

	return min(riskScore, 1.0), details
}

// analyzeProcessEvent analyzes process events
func (m *Manager) analyzeProcessEvent(event *GPUEvent) (float64, map[string]interface{}) {
	processData := m.loader.ParseProcessData(event.Data)
	if processData == nil {
		return 0.0, nil
	}

	details := map[string]interface{}{
		"ppid":      processData.PPID,
		"exit_code": processData.ExitCode,
		"filename":  processData.Filename,
	}

	riskScore := 0.05 // Very low base risk for process events

	// Check for suspicious process names
	suspiciousNames := []string{
		"miner", "cryptonight", "xmrig", "ethminer",
		"backdoor", "rootkit", "keylogger",
		"exploit", "payload", "shell",
	}

	for _, name := range suspiciousNames {
		if strings.Contains(strings.ToLower(event.Comm), name) ||
			strings.Contains(strings.ToLower(processData.Filename), name) {
			riskScore += 0.8
			details["suspicious_name"] = true
			break
		}
	}

	// Check for processes with unusual exit codes
	if event.EventType == EventProcessExit && processData.ExitCode != 0 {
		riskScore += 0.1
		details["abnormal_exit"] = true
	}

	return min(riskScore, 1.0), details
}

// analyzeSyscallEvent analyzes syscall events
func (m *Manager) analyzeSyscallEvent(event *GPUEvent) (float64, map[string]interface{}) {
	syscallData := m.loader.ParseSyscallData(event.Data)
	if syscallData == nil {
		return 0.0, nil
	}

	details := map[string]interface{}{
		"syscall_nr": syscallData.SyscallNr,
		"args":       syscallData.Args,
		"ret":        syscallData.Ret,
	}

	riskScore := 0.1 // Base risk for monitored syscalls

	// Map syscall numbers to names and risk scores
	syscallRisks := map[uint64]struct {
		name string
		risk float64
	}{
		9:   {"mmap", 0.3},
		10:  {"mprotect", 0.5},
		101: {"ptrace", 0.8},
		16:  {"ioctl", 0.2},
	}

	if info, exists := syscallRisks[syscallData.SyscallNr]; exists {
		riskScore = info.risk
		details["syscall_name"] = info.name

		// Additional analysis based on syscall type
		switch syscallData.SyscallNr {
		case 10: // mprotect
			// Check for executable memory protection
			if syscallData.Args[2]&0x4 != 0 { // PROT_EXEC
				riskScore += 0.3
				details["executable_memory"] = true
			}
		case 101: // ptrace
			// Any ptrace is highly suspicious
			riskScore = 0.9
			details["ptrace_operation"] = syscallData.Args[0]
		}
	}

	return min(riskScore, 1.0), details
}

// analyzeModuleEvent analyzes kernel module load events
func (m *Manager) analyzeModuleEvent(event *GPUEvent) (float64, map[string]interface{}) {
	moduleData := m.loader.ParseModuleData(event.Data)
	if moduleData == nil {
		return 0.0, nil
	}

	details := map[string]interface{}{
		"module_name": moduleData.Name,
		"base_addr":   moduleData.BaseAddr,
		"size":        moduleData.Size,
	}

	riskScore := 0.3 // Moderate base risk for module loading

	// Check for suspicious module names
	suspiciousModules := []string{
		"rootkit", "backdoor", "keylogger",
		"stealth", "hidden", "inject",
	}

	for _, name := range suspiciousModules {
		if strings.Contains(strings.ToLower(moduleData.Name), name) {
			riskScore = 0.9
			details["suspicious_module"] = true
			break
		}
	}

	// Check for unsigned modules (simplified check)
	if !strings.HasPrefix(moduleData.Name, "nvidia") &&
		!strings.HasPrefix(moduleData.Name, "amdgpu") &&
		!strings.HasPrefix(moduleData.Name, "i915") {
		riskScore += 0.2
		details["non_gpu_module"] = true
	}

	return min(riskScore, 1.0), details
}

// addEventToBatch adds a security event to the current batch
func (m *Manager) addEventToBatch(event SecurityEvent) {
	m.eventBatch = append(m.eventBatch, event)

	// Flush if batch is full
	if len(m.eventBatch) >= m.config.BatchSize {
		m.sendEventBatch()
	}
}

// flushEvents periodically flushes events to the backend
func (m *Manager) flushEvents(ctx context.Context) {
	ticker := time.NewTicker(m.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if len(m.eventBatch) > 0 {
				m.sendEventBatch()
			}
		}
	}
}

// sendEventBatch sends the current batch of events to the backend
func (m *Manager) sendEventBatch() {
	if len(m.eventBatch) == 0 {
		return
	}

	m.logger.WithField("batch_size", len(m.eventBatch)).Debug("Sending security event batch to backend")

	// Send each event individually (in a real implementation, you might batch them)
	for _, event := range m.eventBatch {
		if err := m.sendSecurityEvent(event); err != nil {
			m.logger.WithError(err).Error("Failed to send security event")
		}
	}

	// Clear the batch
	m.eventBatch = m.eventBatch[:0]
}

// sendSecurityEvent sends a single security event to the backend
func (m *Manager) sendSecurityEvent(event SecurityEvent) error {
	url := fmt.Sprintf("%s/api/v1/security-events/", m.config.BackendURL)

	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	resp, err := m.httpClient.Post(url, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("backend returned status %d", resp.StatusCode)
	}

	return nil
}

// GetStats returns statistics about the eBPF manager
func (m *Manager) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"node_id":          m.config.NodeID,
		"events_in_batch":  len(m.eventBatch),
		"batch_size":       m.config.BatchSize,
		"flush_interval":   m.config.FlushInterval.String(),
		"enabled_monitors": m.config.EnabledMonitors,
	}

	if m.loader != nil {
		loaderStats := m.loader.GetStats()
		stats["loader"] = loaderStats
	}

	return stats
}

// DefaultManagerConfig returns a default manager configuration
func DefaultManagerConfig(nodeID string) *ManagerConfig {
	return &ManagerConfig{
		BackendURL:    "http://localhost:8000",
		NodeID:        nodeID,
		FlushInterval: 30 * time.Second,
		BatchSize:     50,
		RiskThresholds: RiskThresholds{
			IOCTLSuspicious:   0.7,
			DMASuspicious:     0.6,
			ProcessSuspicious: 0.8,
			SyscallSuspicious: 0.7,
			ModuleSuspicious:  0.8,
		},
		EnabledMonitors: []string{"ioctl", "dma", "process", "syscall", "module"},
	}
}

// Helper function to get minimum of two float64 values
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
