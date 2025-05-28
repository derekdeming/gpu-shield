package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ShipKode/gpushield/pkg/telemetry/adapters/nvidia"
	"github.com/sirupsen/logrus"
)

func main() {
	// Create a logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	// Create DCGM collector
	dcgmCollector := nvidia.NewDCGMCollector(logger)

	// Check if DCGM is available
	if !dcgmCollector.IsAvailable() {
		log.Fatal("DCGM is not available on this system")
	}

	fmt.Println("DCGM is available!")

	// Get collector information
	info := dcgmCollector.GetCollectorInfo()
	fmt.Printf("Collector: %s v%s (%s)\n", info.Name, info.Version, info.Description)

	// Collect metrics once
	ctx := context.Background()
	metrics, err := dcgmCollector.CollectMetrics(ctx)
	if err != nil {
		log.Fatalf("Failed to collect metrics: %v", err)
	}

	fmt.Printf("Found %d GPUs:\n", len(metrics))
	for _, gpu := range metrics {
		fmt.Printf("  GPU %d: %s\n", gpu.DeviceID, gpu.Name)
		fmt.Printf("    UUID: %s\n", gpu.UUID)
		fmt.Printf("    Memory: %d/%d MB (%.1f%% used)\n",
			gpu.MemoryUsed, gpu.MemoryTotal, gpu.MemoryUtilization)
		fmt.Printf("    Temperature: %.1f°C\n", gpu.Temperature)
		fmt.Printf("    Power: %.1fW\n", gpu.PowerUsage)
		fmt.Printf("    GPU Utilization: %.1f%%\n", gpu.GPUUtilization)

		if gpu.SMClock > 0 {
			fmt.Printf("    SM Clock: %d MHz\n", gpu.SMClock)
		}
		if gpu.MemoryClock > 0 {
			fmt.Printf("    Memory Clock: %d MHz\n", gpu.MemoryClock)
		}
		if len(gpu.Processes) > 0 {
			fmt.Printf("    Processes: %d\n", len(gpu.Processes))
			for _, proc := range gpu.Processes {
				fmt.Printf("      PID %d: %s (%s, %d MB)\n",
					proc.PID, proc.Name, proc.Type, proc.MemoryUsed)
			}
		}
		fmt.Println()
	}

	// Start continuous monitoring for 30 seconds
	fmt.Println("Starting continuous monitoring for 30 seconds...")
	monitorCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	metricsChan, err := dcgmCollector.StartMonitoring(monitorCtx, 5*time.Second)
	if err != nil {
		log.Fatalf("Failed to start monitoring: %v", err)
	}

	sampleCount := 0
	for metrics := range metricsChan {
		sampleCount++
		fmt.Printf("Sample %d: %d GPUs, avg temp: %.1f°C\n",
			sampleCount, len(metrics), calculateAverageTemperature(metrics))
	}

	fmt.Println("Monitoring completed!")

	// Cleanup
	dcgmCollector.Cleanup()
}

func calculateAverageTemperature(metrics []nvidia.GPUMetrics) float64 {
	if len(metrics) == 0 {
		return 0
	}

	total := 0.0
	for _, gpu := range metrics {
		total += gpu.Temperature
	}
	return total / float64(len(metrics))
}
