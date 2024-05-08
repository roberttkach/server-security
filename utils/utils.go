package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/gopacket/layers"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// RunScript runs the specified script
func RunScript(scriptName string) error {
	cmd := exec.Command("/bin/bash", scriptName)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error running script %s: %v\n", scriptName, err)
		return err
	}
	fmt.Printf("Script %s successfully executed\n", scriptName)
	return nil
}

// RunScriptSSL runs the specified script with arguments and returns the exit code
func RunScriptSSL(scriptName string, args ...string) int {
	args = append([]string{scriptName}, args...)

	cmd := exec.Command("/bin/bash", args...)
	err := cmd.Run()

	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			fmt.Printf("Error running script %s: %v\n", scriptName, err)
			return exitError.ExitCode()
		}
		fmt.Printf("Error running script %s: %v\n", scriptName, err)
		return -1
	}

	fmt.Printf("Script %s successfully executed\n", scriptName)
	return 0
}

// GetPacketCount gets the number of packets
func GetPacketCount(interfaceName string) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/rx_packets", interfaceName))
	if err != nil {
		return 0, fmt.Errorf("failed to read packet statistics: %v", err)
	}
	packetCount, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("failed to convert %s to a number: %v", data, err)
	}
	return packetCount, nil
}

// GetPacketsPerSecond gets the number of packets per second
func GetPacketsPerSecond(interfaceName string) (int, error) {
	packetCount1, err := GetPacketCount(interfaceName)
	if err != nil {
		return 0, err
	}
	time.Sleep(1 * time.Second)
	packetCount2, err := GetPacketCount(interfaceName)
	if err != nil {
		return 0, err
	}
	return packetCount2 - packetCount1, nil
}

func IsValidDNSResponse(dns *layers.DNS) bool {
	if len(dns.Answers) > 0 {
		return true
	}
	return false
}

func IsValidIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

func IsValidMACAddress(mac string) bool {
	_, err := net.ParseMAC(strings.Replace(mac, ":", "", -1))
	return err == nil
}

func IsValidARPReply(arp *layers.ARP) bool {
	if arp.Operation == 2 {
		return true
	}
	return false
}

type SplunkEvent struct {
	Event      map[string]string `json:"event"`
	MACAddress string            `json:"mac_address"`
}

func GetMACAddress() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, i := range interfaces {
		if i.Flags&net.FlagUp != 0 && bytes.Compare(i.HardwareAddr, nil) != 0 {
			return i.HardwareAddr.String(), nil
		}
	}
	return "", nil
}

func SendToSplunk(event SplunkEvent) error {
	// Getting MAC address
	macAddress, err := GetMACAddress()
	if err != nil {
		log.Printf("Error getting MAC address: %v\n", err)
		return err
	}

	// Adding MAC address to the event
	event.MACAddress = macAddress

	url, err := GetSplunkUrl()
	if err != nil {
		log.Printf("Error getting Splunk URL: %v\n", err)
		return err
	}

	token, err := GetSplunkToken()
	if err != nil {
		log.Printf("Error getting Splunk token: %v\n", err)
		return err
	}

	eventJson, err := json.Marshal(event)
	if err != nil {
		log.Printf("Error marshaling event to JSON: %v\n", err)
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(eventJson))
	if err != nil {
		log.Printf("Error creating new HTTP request: %v\n", err)
		return err
	}

	req.Header.Set("Authorization", "Splunk "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending event to Splunk: %v\n", err)
		return err
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			log.Printf("Error closing response body: %v\n", err)
		}
	}()

	if resp.StatusCode >= 400 {
		err = fmt.Errorf("error sending event to Splunk, received status: %d", resp.StatusCode)
		log.Println(err)
		return err
	}

	return nil
}

// GetSplunkUrl returns the URL of your Splunk server
func GetSplunkUrl() (string, error) {
	url, exists := os.LookupEnv("SPLUNK_URL")
	if !exists {
		return "", fmt.Errorf("environment variable SPLUNK_URL is not set")
	}
	return url, nil
}

// GetSplunkToken returns the Splunk authorization token
func GetSplunkToken() (string, error) {
	token, exists := os.LookupEnv("SPLUNK_TOKEN")
	if !exists {
		return "", fmt.Errorf("environment variable SPLUNK_TOKEN is not set")
	}
	return token, nil
}

func CheckNetstatInPath() error {
	path, ok := os.LookupEnv("PATH")
	if !ok {
		return errors.New("failed to get PATH environment variable")
	}

	paths := strings.Split(path, ":")
	for _, p := range paths {
		fullPath := filepath.Join(p, "netstat")
		if _, err := os.Stat(fullPath); err == nil {
			return nil
		}
	}

	err := installNetstat()
	if err != nil {
		return fmt.Errorf("error installing netstat: %v", err)
	}

	return nil
}

func installNetstat() error {
	cmd := exec.Command("/bin/bash", "./bash/netstat.sh")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error running installation script: %v", err)
	}

	return nil
}
