package security

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"server-security/config"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

// ConnectionError represents a database connection error
type ConnectionError struct {
	Err error
}

func (e ConnectionError) Error() string {
	return fmt.Sprintf("ConnectionError: %v", e.Err)
}

// AccessControlError represents a database access control error
type AccessControlError struct {
	Err error
}

func (e AccessControlError) Error() string {
	return fmt.Sprintf("AccessControlError: %v", e.Err)
}

// SSLError represents an SSL error in the database
type SSLError struct {
	Err error
}

func (e SSLError) Error() string {
	return fmt.Sprintf("SSLError: %v", e.Err)
}

// EncryptionError represents an encryption error in the database
type EncryptionError struct {
	Err error
}

func (e EncryptionError) Error() string {
	return fmt.Sprintf("EncryptionError: %v", e.Err)
}

// NetworkExposureError represents a network exposure error in the database
type NetworkExposureError struct {
	Err error
}

func (e NetworkExposureError) Error() string {
	return fmt.Sprintf("NetworkExposureError: %v", e.Err)
}

// Vulnerability for storing vulnerability information
type Vulnerability struct {
	Database string
	User     string
	Error    error
}

// Create separate counters for each type of vulnerability
var (
	ConnectionErrorCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "database_connection_errors",
			Help: "Number of database connection errors",
		},
		[]string{"database", "user"},
	)
	AccessControlErrorCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "database_access_control_errors",
			Help: "Number of database access control errors",
		},
		[]string{"database", "user"},
	)
	SSLErrorCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "database_ssl_errors",
			Help: "Number of SSL errors in databases",
		},
		[]string{"database", "user"},
	)
	EncryptionErrorCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "database_encryption_errors",
			Help: "Number of encryption errors in databases",
		},
		[]string{"database", "user"},
	)
	NetworkExposureErrorCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "database_network_exposure_errors",
			Help: "Number of network exposure errors in databases",
		},
		[]string{"database", "user"},
	)
)

// List to store detected vulnerabilities
var vulnerabilities []Vulnerability

// GetDatabaseVulnerabilities to get a list of detected vulnerabilities
func GetDatabaseVulnerabilities() []Vulnerability {
	return vulnerabilities
}

func CheckDatabaseSecurity(logger *log.Logger, databases []config.Database) {
	for _, db := range databases {
		if len(db.Names) == 0 || len(db.Users) == 0 {
			continue
		}

		for _, dbName := range db.Names {
			for _, user := range db.Users {
				connStr := getConnectionString(dbName, user, db.Type)

				var err error
				if db.Type == "postgres" {
					err = postgresVulnerabilitiesFound(connStr)
				} else if db.Type == "mysql" {
					err = mysqlVulnerabilitiesFound(connStr)
				}

				if err != nil {
					logger.Printf("Vulnerabilities detected in database %s for user %s: %v", dbName, user.Username, err)
					var connectionError ConnectionError
					var accessControlError AccessControlError
					var SSLError SSLError
					var encryptionError EncryptionError
					var networkExposureError NetworkExposureError
					switch {
					case errors.As(err, &connectionError):
						ConnectionErrorCounter.With(prometheus.Labels{"database": dbName, "user": user.Username}).Inc()
					case errors.As(err, &accessControlError):
						AccessControlErrorCounter.With(prometheus.Labels{"database": dbName, "user": user.Username}).Inc()
					case errors.As(err, &SSLError):
						SSLErrorCounter.With(prometheus.Labels{"database": dbName, "user": user.Username}).Inc()
					case errors.As(err, &encryptionError):
						EncryptionErrorCounter.With(prometheus.Labels{"database": dbName, "user": user.Username}).Inc()
					case errors.As(err, &networkExposureError):
						NetworkExposureErrorCounter.With(prometheus.Labels{"database": dbName, "user": user.Username}).Inc()
					}

					vulnerabilities = append(vulnerabilities, Vulnerability{
						Database: dbName,
						User:     user.Username,
						Error:    err,
					})
				}
			}
		}
	}
}

func getConnectionString(database string, user config.User, dbType string) string {
	var connStr string
	if dbType == "postgres" {
		connStr = fmt.Sprintf("host=localhost port=5432 user=%s password=%s dbname=%s sslmode=disable",
			user.Username, user.Password, database)
	} else if dbType == "mysql" {
		connStr = fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/%s",
			user.Username, user.Password, database)
	}

	return connStr
}

func postgresVulnerabilitiesFound(connStr string) error {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return ConnectionError{fmt.Errorf("database connection error: %v", err)}
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			log.Printf("Error closing database connection: %v", err)
		}
	}(db)

	// Check for access control and authentication mechanism enablement
	var authMethod string
	err = db.QueryRow("SHOW hba_file").Scan(&authMethod)
	if err != nil {
		return AccessControlError{fmt.Errorf("access control check error: %v", err)}
	}
	if !strings.Contains(authMethod, "md5") && !strings.Contains(authMethod, "scram-sha-256") {
		log.Println("Access control is not enabled or an insecure authentication mechanism is used")
		return AccessControlError{fmt.Errorf("access control is not enabled or an insecure authentication mechanism is used")}
	}

	// Check for TLS/SSL usage for all connections
	var sslEnabled bool
	err = db.QueryRow("SHOW ssl").Scan(&sslEnabled)
	if err != nil {
		return SSLError{fmt.Errorf("TLS/SSL usage check error: %v", err)}
	}
	if !sslEnabled {
		log.Println("TLS/SSL is not used for all connections")
		return SSLError{fmt.Errorf("TLS/SSL is not used for all connections")}
	}

	// Check for data encryption
	var encryptionEnabled bool
	err = db.QueryRow("SELECT EXISTS (SELECT 1 FROM pg_settings WHERE name = 'ssl_cert_file' AND setting IS NOT NULL)").Scan(&encryptionEnabled)
	if err != nil {
		return EncryptionError{fmt.Errorf("data encryption check error: %v", err)}
	}
	if !encryptionEnabled {
		log.Println("Data is not encrypted")
		return EncryptionError{fmt.Errorf("data is not encrypted")}
	}

	// Check for network exposure limitation
	var listenAddresses string
	err = db.QueryRow("SHOW listen_addresses").Scan(&listenAddresses)
	if err != nil {
		NetworkExposureErrorCounter.With(prometheus.Labels{"database": "postgres", "error": "network_exposure_check_error"}).Inc()
		return NetworkExposureError{fmt.Errorf("network exposure limitation check error: %v", err)}
	}

	var maxConnections int
	err = db.QueryRow("SHOW max_connections").Scan(&maxConnections)
	if err != nil {
		NetworkExposureErrorCounter.With(prometheus.Labels{"database": "postgres", "error": "network_exposure_check_error"}).Inc()
		return NetworkExposureError{fmt.Errorf("network exposure limitation check error: %v", err)}
	}

	var superuserReservedConnections int
	err = db.QueryRow("SHOW superuser_reserved_connections").Scan(&superuserReservedConnections)
	if err != nil {
		NetworkExposureErrorCounter.With(prometheus.Labels{"database": "postgres", "error": "network_exposure_check_error"}).Inc()
		return NetworkExposureError{fmt.Errorf("network exposure limitation check error: %v", err)}
	}

	if listenAddresses != "localhost" || maxConnections > 100 || superuserReservedConnections > 3 {
		NetworkExposureErrorCounter.With(prometheus.Labels{"database": "postgres", "error": "network_exposure_not_limited"}).Inc()
		log.Println("Network exposure is not limited")
		return NetworkExposureError{fmt.Errorf("network exposure is not limited")}
	}

	return nil
}

func mysqlVulnerabilitiesFound(connStr string) error {
	db, err := sql.Open("mysql", connStr)
	if err != nil {
		ConnectionErrorCounter.With(prometheus.Labels{"database": "mysql", "error": "connection_error"}).Inc()
		return ConnectionError{fmt.Errorf("database connection error: %v", err)}
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			ConnectionErrorCounter.With(prometheus.Labels{"database": "mysql", "error": "close_connection_error"}).Inc()
			log.Printf("Error closing database connection: %v", err)
		}
	}(db)

	// Check for TLS/SSL usage for all connections
	var sslEnabled string
	err = db.QueryRow("SHOW VARIABLES LIKE 'have_ssl'").Scan(nil, &sslEnabled)
	if err != nil {
		SSLErrorCounter.With(prometheus.Labels{"database": "mysql", "error": "ssl_check_error"}).Inc()
		return SSLError{fmt.Errorf("TLS/SSL usage check error: %v", err)}
	}
	if sslEnabled != "YES" {
		SSLErrorCounter.With(prometheus.Labels{"database": "mysql", "error": "ssl_not_used"}).Inc()
		log.Println("TLS/SSL is not used for all connections")
		return SSLError{fmt.Errorf("TLS/SSL is not used for all connections")}
	}

	// Check for network exposure limitation
	var bindAddress string
	err = db.QueryRow("SHOW VARIABLES LIKE 'bind_address'").Scan(nil, &bindAddress)
	if err != nil {
		NetworkExposureErrorCounter.With(prometheus.Labels{"database": "mysql", "error": "network_exposure_check_error"}).Inc()
		return NetworkExposureError{fmt.Errorf("network exposure limitation check error: %v", err)}
	}

	var maxConnections int
	err = db.QueryRow("SHOW VARIABLES LIKE 'max_connections'").Scan(nil, &maxConnections)
	if err != nil {
		NetworkExposureErrorCounter.With(prometheus.Labels{"database": "mysql", "error": "network_exposure_check_error"}).Inc()
		return NetworkExposureError{fmt.Errorf("network exposure limitation check error: %v", err)}
	}

	if bindAddress != "127.0.0.1" || maxConnections > 100 {
		NetworkExposureErrorCounter.With(prometheus.Labels{"database": "mysql", "error": "network_exposure_not_limited"}).Inc()
		log.Println("Network exposure is not limited")
		return NetworkExposureError{fmt.Errorf("network exposure is not limited")}
	}

	return nil
}
