package main

import (
	"fmt"
	"os"
	"server-security/utils"
	"strings"
	_ "strings"

	"github.com/prometheus/client_golang/prometheus"
	"log"
	"server-security/config"
	"server-security/security"
	"time"
)

func sendMetricsToSplunk() {
	counters := []prometheus.Collector{
		security.CPUUsageCounter,
		security.MemoryUsageCounter,
		security.DDOSAttackCounter,
		security.DNSSpoofingCounter,
		security.IpSpoofingCounter,
		security.MacSpoofingCounter,
		security.ARPSpoofingCounter,
		security.DNSHijackingCounter,
		security.SSLCertificateCounter,
		security.OutdatedAccountsCounter,
		security.ConnectionErrorCounter,
		security.AccessControlErrorCounter,
		security.SSLErrorCounter,
		security.EncryptionErrorCounter,
		security.NetworkExposureErrorCounter,
	}

	for _, collector := range counters {
		switch counter := collector.(type) {
		case prometheus.Counter:
			metricName := strings.Split(counter.Desc().String(), "\"")[1]
			counter.Add(0)
			event := utils.SplunkEvent{
				Event: map[string]string{
					"metric_name": metricName,
				},
			}
			err := utils.SendToSplunk(event)
			if err != nil {
				log.Println("Error sending event to Splunk:", err)
			}
		}
	}

	// Output directories with detected malware
	for _, dir := range security.GetMalwareDetectedDirs() {
		event := utils.SplunkEvent{
			Event: map[string]string{
				"message": "Detected malware in directory: " + dir,
			},
		}
		err := utils.SendToSplunk(event)
		if err != nil {
			log.Println("Error sending event to Splunk:", err)
		}
	}

	// Output directories with unauthorized file changes
	for _, dir := range security.GetIntegrityViolatedDirs() {
		event := utils.SplunkEvent{
			Event: map[string]string{
				"message": "Detected unauthorized changes in directory: " + dir,
			},
		}
		err := utils.SendToSplunk(event)
		if err != nil {
			log.Println("Error sending event to Splunk:", err)
		}
	}

	// Output database vulnerabilities
	for _, vulnerability := range security.GetDatabaseVulnerabilities() {
		event := utils.SplunkEvent{
			Event: map[string]string{
				"message": fmt.Sprintf("Detected vulnerabilities in database %s for user %s: %v", vulnerability.Database, vulnerability.User, vulnerability.Error),
			},
		}
		err := utils.SendToSplunk(event)
		if err != nil {
			log.Println("Error sending event to Splunk:", err)
		}
	}
}

func main() {
	err := utils.CheckNetstatInPath()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	logFile, err := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer func(logFile *os.File) {
		err := logFile.Close()
		if err != nil {
			log.Println("Error closing log file:", err)
		}
	}(logFile)

	logger := log.New(logFile, "", log.LstdFlags)

	reg := prometheus.NewRegistry()

	reg.MustRegister(
		security.CPUUsageCounter,
		security.MemoryUsageCounter,
		security.DDOSAttackCounter,
		security.DNSSpoofingCounter,
		security.IpSpoofingCounter,
		security.MacSpoofingCounter,
		security.ARPSpoofingCounter,
		security.DNSHijackingCounter,
		security.SSLCertificateCounter,
		security.OutdatedAccountsCounter,
		security.ConnectionErrorCounter,
		security.AccessControlErrorCounter,
		security.SSLErrorCounter,
		security.EncryptionErrorCounter,
		security.NetworkExposureErrorCounter,
	)

	for {
		security.MonitorFileIntegrity(logger, config.FilePath)
		security.CheckSSLCertificates(logger)
		security.CheckDatabaseSecurity(logger, config.Databases)
		security.MonitorSystemResources(logger, config.SystemConfig.CPUThreshold, config.SystemConfig.MemoryThreshold)
		security.CheckUserAccounts(logger)
		security.MonitorNetworkSecurity(logger, config.NetworkSecurityConfig.DDOSThreshold, config.NetworkSecurityConfig.NetworkInterface, config.NetworkSecurityConfig.MaxPacketSize, config.NetworkSecurityConfig.DNSPort, config.NetworkSecurityConfig.ARPFilter)
		security.CheckForMalware(logger, config.MalwareConfig.ScanDirectories)

		sendMetricsToSplunk()

		time.Sleep(time.Minute * 2)
	}
}
