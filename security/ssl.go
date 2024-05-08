package security

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"log"
	"server-security/config"
	"server-security/utils"
)

var SSLCertificateCounter = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "outdated_ssl_certificates_total",
		Help: "The total number of outdated SSL/TLS certificates",
	},
)

// CheckSSLCertificates for checking the presence of outdated SSL/TLS certificates
func CheckSSLCertificates(logger *log.Logger) {
	result := outdatedSSLCertificates()
	if result == 1 {
		logger.Println("Outdated SSL/TLS certificates detected")
		SSLCertificateCounter.Inc()
	} else if result == 2 {
		logger.Println("Error checking SSL/TLS certificates")
	}
}

func outdatedSSLCertificates() int {

	// Script for checking SSL/TLS certificates
	exitCode := utils.RunScriptSSL("checkSSL.sh", config.SSLhost, config.SSLport)
	if exitCode != 0 {
		fmt.Printf("SSL check script exited with exit code: %d\n", exitCode)
	}
	return exitCode
}
