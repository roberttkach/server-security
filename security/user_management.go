package security

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"log"
	"os/exec"
	"strings"
)

var OutdatedAccountsCounter = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "outdated_accounts_total",
		Help: "The total number of outdated accounts",
	},
)

// CheckUserAccounts for checking the presence of outdated user accounts
func CheckUserAccounts(logger *log.Logger) {
	accounts, err := outdatedAccounts()
	if err != nil {
		logger.Println("Error checking outdated user accounts:", err)
		return
	}
	for account := range accounts {
		logger.Printf("Outdated user account detected: %s\n", account)
		OutdatedAccountsCounter.Inc()
	}
}

func outdatedAccounts() (map[string]bool, error) {
	out, err := exec.Command("lastlog").Output()
	if err != nil {
		return nil, err
	}
	lastlog := string(out)
	lines := strings.Split(lastlog, "\n")
	outdated := make(map[string]bool)

	for _, line := range lines {
		// If the line contains "Never logged in", then the account is outdated
		if strings.Contains(line, "Never logged in") {
			parts := strings.Fields(line)
			account := parts[0]
			outdated[account] = true
		}
	}

	return outdated, nil
}
