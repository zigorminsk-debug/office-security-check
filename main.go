package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// HostInfo stores information about a discovered host
type HostInfo struct {
	IP        string
	MAC       string
	Hostname  string
	OS        string
	PortState map[int]string // port number -> state (open, closed, filtered)
}

// Result stores the outcome of a vulnerability check
type Result struct {
	Host      HostInfo
	Findings  []string
	Error     error
}

func main() {
	// Check for admin privileges
	if !isAdmin() {
		fmt.Println("ERROR: This program must be run as Administrator to scan the network and check vulnerabilities.")
		fmt.Println("Please right-click and select 'Run as administrator'.")
		os.Exit(1)
	}

	fmt.Println("=== Office Security Check - Network Scanner ===")
	fmt.Println("Scanning for hosts in the local network segment...")

	// Determine the local network segment
	localIPs, err := getLocalIPs()
	if err != nil {
		fmt.Printf("Error getting local IPs: %v\n", err)
		os.Exit(1)
	}

	if len(localIPs) == 0 {
		fmt.Println("No local IP addresses found.")
		os.Exit(1)
	}

	// Use the first available IP to determine the subnet
	baseIP := localIPs[0]
	subnet := determineSubnet(baseIP)

	fmt.Printf("Scanning subnet: %s\n", subnet)

	// Scan for hosts
	hosts, err := scanNetwork(subnet)
	if err != nil {
		fmt.Printf("Error scanning network: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d hosts.\n", len(hosts))

	// Check vulnerabilities for each host
	fmt.Println("\n=== Vulnerability Check ===")
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, host := range hosts {
		wg.Add(1)
		go func(h HostInfo) {
			defer wg.Done()
			result := checkHostVulnerabilities(h)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(host)
	}

	wg.Wait()

	// Print results
	for _, result := range results {
		if result.Error != nil {
			fmt.Printf("Host: %s - Error: %v\n", result.Host.IP, result.Error)
			continue
		}

		fmt.Printf("\nHost: %s (%s)\n", result.Host.IP, result.Host.Hostname)
		if len(result.Findings) == 0 {
			fmt.Println("  No critical vulnerabilities found.")
		} else {
			fmt.Println("  Findings:")
			for _, finding := range result.Findings {
				fmt.Printf("    - %s\n", finding)
			}
		}
	}

	fmt.Println("\n=== Scan Complete ===")
}

// isAdmin checks if the current process is running as administrator
func isAdmin() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	cmd := exec.Command("net", "session")
	cmd.Stdout = nil
	cmd.Stderr = nil
	err := cmd.Run()
	return err == nil
}

// getLocalIPs returns all local IP addresses
func getLocalIPs() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	var ips []string
	for _, addr := range addrs {
		// Check if the address is an IP address
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ips = append(ips, ipNet.IP.String())
			}
		}
	}
	return ips, nil
}

// determineSubnet extracts the subnet from an IP address (e.g., 192.168.1.100 -> 192.168.1)
func determineSubnet(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
}

// scanNetwork scans the given subnet for active hosts
func scanNetwork(subnet string) ([]HostInfo, error) {
	var hosts []HostInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Create a channel to limit concurrency
	sem := make(chan bool, 254)

	for i := 1; i <= 254; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- true // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			ip := fmt.Sprintf("%s.%d", subnet, i)
			host, err := discoverHost(ip)
			if err == nil {
				mu.Lock()
				hosts = append(hosts, host)
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()
	return hosts, nil
}

// discoverHost attempts to discover a host by pinging and resolving its hostname
func discoverHost(ip string) (HostInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Ping the host
	cmd := exec.CommandContext(ctx, "ping", "-n", "1", "-w", "1000", ip)
	err := cmd.Run()
	if err != nil {
		return HostInfo{}, fmt.Errorf("host unreachable")
	}

	// Resolve hostname
	hostname, err := net.LookupAddr(ip)
	if err != nil {
		hostname = []string{"unknown"}
	}

	// Get MAC address (requires ARP table)
	mac, err := getMACAddress(ip)
	if err != nil {
		mac = "unknown"
	}

	// Check common ports
	portState := checkCommonPorts(ip)

	return HostInfo{
		IP:        ip,
		MAC:       mac,
		Hostname:  strings.Join(hostname, ","),
		OS:        detectOS(ip),
		PortState: portState,
	}, nil
}

// getMACAddress retrieves the MAC address of a host using ARP
func getMACAddress(ip string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "arp", "-a", ip)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse ARP output to find MAC address
	// Format: Interface: ---<InterfaceName>
	// Internet Address      Physical Address  Type
	// 192.168.1.1           00-11-22-33-44-55 dynamic
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ip) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[len(parts)-2], nil
			}
		}
	}
	return "", fmt.Errorf("MAC not found")
}

// checkCommonPorts checks a list of common ports on the given IP
func checkCommonPorts(ip string) map[int]string {
	ports := []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 5900, 8080}
	portState := make(map[int]string)

	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			portState[port] = "open"
		} else {
			portState[port] = "closed"
		}
	}
	return portState
}

// detectOS attempts to detect the operating system based on open ports and hostname
func detectOS(ip string) string {
	// This is a simplified detection. In a real tool, you'd use more sophisticated methods.
	// For now, we'll just return "Unknown"
	return "Unknown"
}

// checkHostVulnerabilities performs basic vulnerability checks on a host
func checkHostVulnerabilities(host HostInfo) Result {
	var findings []string

	// Check for SMB vulnerabilities (port 445)
	if host.PortState[445] == "open" {
		findings = append(findings, "SMB (445) is open - Potential EternalBlue vulnerability")
	}

	// Check for RDP vulnerabilities (port 3389)
	if host.PortState[3389] == "open" {
		findings = append(findings, "RDP (3389) is open - Potential BlueKeep vulnerability")
	}

	// Check for weak SMB configuration
	if host.PortState[445] == "open" {
		// Check for null session
		err := checkNullSession(host.IP)
		if err == nil {
			findings = append(findings, "Null session allowed on SMB - Potential information disclosure")
		}
	}

	// Check for default credentials on common services
	if host.PortState[3306] == "open" {
		findings = append(findings, "MySQL (3306) is open - Check for default credentials")
	}

	if host.PortState[8080] == "open" {
		findings = append(findings, "HTTP Proxy (8080) is open - Check for misconfiguration")
	}

	return Result{
		Host:     host,
		Findings: findings,
	}
}

// checkNullSession checks if a null session is allowed on the SMB service
func checkNullSession(ip string) error {
	// This is a simplified check. In a real tool, you'd use a library like go-ntlmssp
	// For now, we'll just return an error to indicate that the check is not implemented
	return fmt.Errorf("null session check not implemented")
}
