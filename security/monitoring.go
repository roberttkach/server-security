package security

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"log"
	"os/exec"
	"strconv"
	"strings"
)

var (
	CPUUsageCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cpu_usage_total",
			Help: "The total CPU usage",
		},
	)
	MemoryUsageCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "memory_usage_total",
			Help: "The total memory usage",
		},
	)
)

// MonitorSystemResources for monitoring CPU load and memory usage
func MonitorSystemResources(logger *log.Logger, cpuThreshold float64, memoryThreshold float64) {
	if highCPUUsage(cpuThreshold) {
		logger.Println("High CPU load detected")
		CPUUsageCounter.Inc()
	} else if highMemoryUsage(memoryThreshold) {
		logger.Println("High memory usage detected")
		MemoryUsageCounter.Inc()
	} else {
		logger.Println("CPU load and memory usage are within normal limits")
	}
}

func highCPUUsage(cpuThreshold float64) bool {
	out, err := exec.Command("sh", "-c", "top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 - $1}'").Output()
	if err != nil {
		log.Printf("Error executing command: %v", err)
		return false
	}
	cpuUsage, _ := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	CPUUsageCounter.Add(cpuUsage)
	return cpuUsage > cpuThreshold
}

func highMemoryUsage(memoryThreshold float64) bool {
	out, err := exec.Command("sh", "-c", "free | grep Mem | awk '{print $3/$2 * 100.0}'").Output()
	if err != nil {
		log.Printf("Error executing command: %v", err)
		return false
	}
	memoryUsage, _ := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	MemoryUsageCounter.Add(memoryUsage)
	return memoryUsage > memoryThreshold
}
