package config

// =======================DATABASE=======================

// Database structure contains information about the database
type Database struct {
	Type  string   // The type of the database (e.g., "postgres", "mysql", etc.)
	Names []string // The list of database names
	Users []User   // The list of users who have access to the databases
}

// User structure contains information about the database user
type User struct {
	Username string // The username
	Password string // The user's password
}

// Databases is a list of all databases that need to be checked
var Databases = []Database{
	{
		Type:  "postgres",
		Names: []string{"db1", "db2", "db3"},
		Users: []User{
			{
				Username: "user1",
				Password: "password1",
			},
			{
				Username: "user2",
				Password: "password2",
			},
			{
				Username: "user3",
				Password: "password3",
			},
		},
	},
	{
		Type:  "mysql",
		Names: []string{"db1", "db2", "db3"},
		Users: []User{
			{
				Username: "user1",
				Password: "password1",
			},
			{
				Username: "user2",
				Password: "password2",
			},
			{
				Username: "user3",
				Password: "password3",
			},
		},
	},
}

/* Unchecked.
{
	Type: "mysql",
},
*/

// =======================FILE=======================

// FilePath is the path to the file or directory that needs to be monitored for integrity checks
var FilePath = "/path/to"

// =======================MALWARE=======================

// Malware structure contains settings for malware scanning
type Malware struct {
	ClamAVSocketPath string   // The path to the ClamAV socket
	ScanDirectories  []string // The list of directories to scan
}

// MalwareConfig are the settings for malware scanning
var MalwareConfig = Malware{
	ClamAVSocketPath: "/var/run/clamav/clamd.ctl",
	ScanDirectories:  []string{"/path/to/scan1", "/path/to/scan2"},
}

// =======================SYSTEM=======================

// System structure contains settings for system monitoring
type System struct {
	CPUThreshold    float64 // The threshold value for CPU load
	MemoryThreshold float64 // The threshold value for memory usage
}

// SystemConfig are the settings for system monitoring
var SystemConfig = System{
	CPUThreshold:    80.0,
	MemoryThreshold: 65.0,
}

// =======================NETWORK=======================

// NetworkSecurity structure contains settings for network security monitoring
type NetworkSecurity struct {
	DDOSThreshold    int    // The threshold value for detecting a DDoS attack
	NetworkInterface string // The name of the network interface
	MaxPacketSize    int32  // The maximum packet size in bytes
	DNSPort          string // BPF filter for DNS port
	ARPFilter        string // BPF filter for ARP
}

// NetworkSecurityConfig are the settings for network security monitoring
var NetworkSecurityConfig = NetworkSecurity{
	DDOSThreshold:    100000,
	NetworkInterface: "eth0",
	MaxPacketSize:    1600,
	DNSPort:          "udp port 53",
	ARPFilter:        "arp",
}

// =========================SSL=========================

// SSLhost and SSLport are used to define the host and port for SSL/TLS connection.
// These variables are used in the context of establishing a secure connection to a server.
// SSLhost is the domain name or IP address of the server.
// SSLport is the port number on which the server is listening for secure connections.

var (
	// Define host and port
	SSLhost = "example.com" // The host for the SSL/TLS connection
	SSLport = "443"         // The port for the SSL/TLS connection
)
