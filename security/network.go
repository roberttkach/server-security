package security

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"log"
	"server-security/utils"
)

var (
	DDOSAttackCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ddos_attacks_total",
			Help: "The total number of DDoS attacks detected",
		},
	)
	DNSSpoofingCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_spoofing_attacks_total",
			Help: "The total number of DNS spoofing attacks detected",
		},
	)
	IpSpoofingCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ip_spoofing_attacks_total",
			Help: "The total number of IP spoofing attacks detected",
		},
	)
	MacSpoofingCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mac_spoofing_attacks_total",
			Help: "The total number of MAC spoofing attacks detected",
		},
	)
	ARPSpoofingCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "arp_spoofing_attacks_total",
			Help: "The total number of ARP spoofing attacks detected",
		},
	)
	DNSHijackingCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_hijacking_attacks_total",
			Help: "The total number of DNS hijacking attacks detected",
		},
	)
)

// MonitorNetworkSecurity function for monitoring network security events
func MonitorNetworkSecurity(logger *log.Logger, ddosThreshold int, networkInterface string, maxPacketSize int32, dnsPort string, arpFilter string) {
	checks := []func() error{
		func() error { return ddosAttackDetected(networkInterface, ddosThreshold) },
		func() error { return dnsSpoofingDetected(networkInterface, maxPacketSize, dnsPort) },
		func() error { return ipSpoofingDetected(networkInterface, maxPacketSize) },
		func() error { return macSpoofingDetected(networkInterface, maxPacketSize) },
		func() error { return arpSpoofingDetected(networkInterface, maxPacketSize, arpFilter) },
		func() error { return dnsHijackingDetected(networkInterface, maxPacketSize, dnsPort) },
	}

	for _, check := range checks {
		if err := check(); err != nil {
			logger.Println(err)
		}
	}
}

func ddosAttackDetected(interfaceName string, ddosThreshold int) error {
	// Get the number of packets per second
	packetCount, err := utils.GetPacketsPerSecond(interfaceName)
	if err != nil {
		return fmt.Errorf("error getting network statistics: %v", err)
	}

	// If the number of packets per second exceeds the threshold value, we consider that a DDoS attack is happening
	if packetCount > ddosThreshold {
		DDOSAttackCounter.Inc()
		return fmt.Errorf("DDoS attack detected")
	}

	return nil
}

func dnsSpoofingDetected(networkInterface string, maxPacketSize int32, dnsPort string) error {
	handle, err := pcap.OpenLive(networkInterface, maxPacketSize, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening network interface: %v", err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(dnsPort)
	if err != nil {
		return fmt.Errorf("error setting BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)
			if dns.QR && !utils.IsValidDNSResponse(dns) {
				DNSSpoofingCounter.Inc()
				return errors.New("DNS spoofing attack detected")
			}
		}
	}
	return nil
}

func ipSpoofingDetected(networkInterface string, maxPacketSize int32) error {
	handle, err := pcap.OpenLive(networkInterface, maxPacketSize, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening network interface: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			if !utils.IsValidIPAddress(ip.SrcIP.String()) {
				IpSpoofingCounter.Inc()
				return errors.New("IP spoofing attack detected")
			}
		}
	}
	return nil
}

func macSpoofingDetected(networkInterface string, maxPacketSize int32) error {
	handle, err := pcap.OpenLive(networkInterface, maxPacketSize, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening network interface: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			ethernet, _ := ethernetLayer.(*layers.Ethernet)
			if !utils.IsValidMACAddress(ethernet.SrcMAC.String()) {
				MacSpoofingCounter.Inc()
				return errors.New("MAC spoofing attack detected")
			}
		}
	}
	return nil
}

func arpSpoofingDetected(networkInterface string, maxPacketSize int32, arpFilter string) error {
	handle, err := pcap.OpenLive(networkInterface, maxPacketSize, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening network interface: %v", err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(arpFilter)
	if err != nil {
		return fmt.Errorf("error setting BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arp, _ := arpLayer.(*layers.ARP)
			if arp.Operation == layers.ARPReply && !utils.IsValidARPReply(arp) {
				ARPSpoofingCounter.Inc()
				return errors.New("ARP spoofing attack detected")
			}
		}
	}
	return nil
}

func dnsHijackingDetected(networkInterface string, maxPacketSize int32, dnsPort string) error {
	handle, err := pcap.OpenLive(networkInterface, maxPacketSize, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening network interface: %v", err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(dnsPort)
	if err != nil {
		return fmt.Errorf("error setting BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)
			if dns.QR && !utils.IsValidDNSResponse(dns) {
				DNSHijackingCounter.Inc()
				return errors.New("DNS hijacking attack detected")
			}
		}
	}
	return nil
}
