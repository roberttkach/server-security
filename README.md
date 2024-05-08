# Security Monitoring Server

This repository contains a comprehensive solution for comprehensive security monitoring and threat detection on GNU/Linux servers. Support is provided for the following distributions:

- Ubuntu
- Debian
- CentOS Linux
- Red Hat Enterprise Linux
- Fedora
- openSUSE Leap
- Arch Linux
- Manjaro Linux
- Gentoo
- Mageia

The solution uses advanced logging and monitoring systems based on Prometheus for metric collection and Splunk for centralized logging. The script can be deployed on multiple servers, with a single Splunk host receiving logs from all servers. Servers are differentiated by their MAC addresses, facilitating identification and analysis.

## Features

- **File Integrity Monitoring**: Tracks file changes in specified directories and alerts when unauthorized modifications are detected.

- **Network Security Monitoring**: Detects various network attacks, including DDoS, DNS spoofing, IP spoofing, MAC spoofing, ARP attacks, and DNS hijacking.

- **Database Security Monitoring**: Checks for vulnerabilities in PostgreSQL and MySQL databases, including connection errors, access control issues, improper SSL/TLS configuration, data encryption problems, and network availability.

- **Malware Detection**: Scans files for malware using the ClamAV engine.

- **User Account Management**: Identifies stale user accounts that haven't been used for an extended period.

- **SSL/TLS Certificate Monitoring**: Checks for expired SSL/TLS certificates.

- **System Resource Monitoring**: Monitors CPU and memory usage, alerting when configurable thresholds are exceeded.

## Getting Started

1. **Configuration**: All settings are located in the `config.go` file. Each configuration parameter is thoroughly documented, making it easy to configure the behavior according to your requirements.

2. **Deployment**: For server deployment, it is recommended to use the `tohost.py` script, which is specifically designed to simplify the setup process and ensure proper code functioning.

3. **Installation**: After running `tohost.py`, navigate to `/home/{user}/server-security` and run `sudo go run main.go`.

## Contributing

We welcome any contributions to this project! If you encounter any issues or have ideas for improvements, please create issues or submit pull requests.

## License

This project is distributed under the [MIT License](LICENSE).
