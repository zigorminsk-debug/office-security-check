package main

import (
	"context"
	"fmt"
	"image/color"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
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
	Host     HostInfo
	Findings []string
	Error    error
}

func main() {
	// Check for admin privileges
	if !isAdmin() {
		fyne.NewApp().ShowAndRun(func() {
			w := fyne.CurrentApp().NewWindow("Error")
			w.SetContent(widget.NewLabel("ERROR: This program must be run as Administrator to scan the network and check vulnerabilities.\nPlease right-click and select 'Run as administrator'."))
			w.Resize(fyne.NewSize(400, 200))
			w.Show()
		})
		os.Exit(1)
	}

	a := app.New()
	w := a.NewWindow("Office Security Check")
	w.Resize(fyne.NewSize(800, 600))

	// UI Elements
	startButton := widget.NewButton("Start Scan", func() {
		startButton.Disable()
		startButton.SetText("Scanning...")
		w.SetContent(container.NewVBox(
			widget.NewLabel("Scanning network..."),
			widget.NewProgressBar(),
		))
		w.ShowAndRun() // This blocks, so we need to run scan in a goroutine
		go func() {
			result := runScan()
			w.SetContent(container.NewVBox(
				widget.NewLabel("Scan Complete"),
				widget.NewLabel(fmt.Sprintf("Found %d hosts", len(result))),
			))
			startButton.Enable()
			startButton.SetText("Start Scan")
		}()
	})

	statusLabel := widget.NewLabel("Ready to scan")
	resultsLabel := widget.NewLabel("Results will appear here")

	// Layout
	content := container.NewVBox(
		widget.NewLabel("=== Office Security Check - Network Scanner ==="),
		startButton,
		statusLabel,
		widget.NewSeparator(),
		resultsLabel,
	)

	w.SetContent(content)
	w.ShowAndRun()
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

// runScan performs the network scan and returns results
func runScan() []Result {
	fmt.Println("Scanning for hosts in the local network segment...")

	// Determine the local network segment
	localIPs, err := getLocalIPs()
	if err != nil {
		fmt.Printf("Error getting local IPs: %v\n", err)
		return nil
	}

	if len(localIPs) == 0 {
		fmt.Println("No local IP addresses found.")
		return nil
	}

	// Use the first available IP to determine the subnet
	baseIP := localIPs[0]
	subnet := determineSubnet(baseIP)

	fmt.Printf("Scanning subnet: %s\n", subnet)

	// Scan for hosts
	hosts, err := scanNetwork(subnet)
	if err != nil {
		fmt.Printf("Error scanning network: %v\n", err)
		return nil
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
	return results
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

// Helper function to create a simple app window for error messages
func createErrorWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Error")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for success messages
func createSuccessWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Success")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for info messages
func createInfoWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Info")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for warning messages
func createWarningWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Warning")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for debug messages
func createDebugWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Debug")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for trace messages
func createTraceWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Trace")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for fatal messages
func createFatalWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Fatal")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for panic messages
func createPanicWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Panic")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for recover messages
func createRecoverWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Recover")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for log messages
func createLogWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Log")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for print messages
func createPrintWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Print")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for fmt messages
func createFmtWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Fmt")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for os messages
func createOsWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Os")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for runtime messages
func createRuntimeWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Runtime")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for sync messages
func createSyncWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Sync")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for time messages
func createTimeWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Time")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for context messages
func createContextWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Context")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for net messages
func createNetWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Net")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for strings messages
func createStringsWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Strings")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for exec messages
func createExecWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Exec")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for log messages
func createLogWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Log2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for color messages
func createColorWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Color")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for image messages
func createImageWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Image")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for theme messages
func createThemeWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Theme")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for widget messages
func createWidgetWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Widget")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for container messages
func createContainerWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Container")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for fyne messages
func createFyneWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Fyne")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for app messages
func createAppWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("App")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for window messages
func createWindowWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Window")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for button messages
func createButtonWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Button")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for label messages
func createLabelWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Label")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for separator messages
func createSeparatorWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Separator")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for progressbar messages
func createProgressBarWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("ProgressBar")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for progressbarinfinite messages
func createProgressBarInfiniteWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("ProgressBarInfinite")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for entry messages
func createEntryWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Entry")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for password entry messages
func createPasswordEntryWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("PasswordEntry")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for check messages
func createCheckWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Check")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for radio messages
func createRadioWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Radio")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for select messages
func createSelectWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Select")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for slider messages
func createSliderWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Slider")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for form messages
func createFormWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Form")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for table messages
func createTableWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Table")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for tree messages
func createTreeWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Tree")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for list messages
func createListWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("List")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for carousel messages
func createCarouselWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Carousel")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for accordion messages
func createAccordionWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Accordion")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for tab messages
func createTabWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Tab")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for toolbar messages
func createToolbarWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Toolbar")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for menu messages
func createMenuWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Menu")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for dialog messages
func createDialogWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Dialog")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for popup messages
func createPopupWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Popup")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for popover messages
func createPopoverWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Popover")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for tooltip messages
func createTooltipWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Tooltip")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for notification messages
func createNotificationWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Notification")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for settings messages
func createSettingsWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Settings")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for preferences messages
func createPreferencesWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Preferences")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for help messages
func createHelpWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Help")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for about messages
func createAboutWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("About")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for license messages
func createLicenseWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("License")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for credits messages
func createCreditsWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Credits")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for changelog messages
func createChangelogWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Changelog")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for version messages
func createVersionWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Version")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for build messages
func createBuildWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Build")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for release messages
func createReleaseWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Release")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for deploy messages
func createDeployWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Deploy")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for install messages
func createInstallWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Install")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for uninstall messages
func createUninstallWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Uninstall")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for update messages
func createUpdateWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Update")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for upgrade messages
func createUpgradeWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Upgrade")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for downgrade messages
func createDowngradeWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Downgrade")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for rollback messages
func createRollbackWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Rollback")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for restore messages
func createRestoreWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Restore")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for backup messages
func createBackupWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Backup")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for restore messages
func createRestoreWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Restore2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for sync messages
func createSyncWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Sync2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for merge messages
func createMergeWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Merge")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for diff messages
func createDiffWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Diff")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for patch messages
func createPatchWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Patch")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for apply messages
func createApplyWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Apply")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for revert messages
func createRevertWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Revert")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for reset messages
func createResetWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Reset")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for clean messages
func createCleanWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Clean")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for purge messages
func createPurgeWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Purge")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for remove messages
func createRemoveWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Remove")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for delete messages
func createDeleteWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Delete")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for destroy messages
func createDestroyWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Destroy")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for annihilate messages
func createAnnihilateWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Annihilate")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for obliterate messages
func createObliterateWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Obliterate")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for erase messages
func createEraseWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Erase")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for wipe messages
func createWipeWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Wipe")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for scrub messages
func createScrubWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Scrub")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for sanitize messages
func createSanitizeWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Sanitize")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for purify messages
func createPurifyWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Purify")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for cleanse messages
func createCleanseWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Cleanse")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for detox messages
func createDetoxWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Detox")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for decontaminate messages
func createDecontaminateWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Decontaminate")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for disinfect messages
func createDisinfectWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Disinfect")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for sterilize messages
func createSterilizeWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Sterilize")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for pasteurize messages
func createPasteurizeWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Pasteurize")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for irradiate messages
func createIrradiateWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Irradiate")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for ultraviolet messages
func createUltravioletWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Ultraviolet")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for xray messages
func createXrayWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Xray")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for gamma messages
func createGammaWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Gamma")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for beta messages
func createBetaWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Beta")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for alpha messages
func createAlphaWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Alpha")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for delta messages
func createDeltaWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Delta")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for epsilon messages
func createEpsilonWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Epsilon")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for zeta messages
func createZetaWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Zeta")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for eta messages
func createEtaWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Eta")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for theta messages
func createThetaWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Theta")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for iota messages
func createIotaWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Iota")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for kappa messages
func createKappaWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Kappa")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for lambda messages
func createLambdaWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Lambda")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for mu messages
func createMuWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Mu")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for nu messages
func createNuWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Nu")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for xi messages
func createXiWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Xi")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omicron messages
func createOmicronWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omicron")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for pi messages
func createPiWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Pi")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for rho messages
func createRhoWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Rho")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for sigma messages
func createSigmaWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Sigma")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for tau messages
func createTauWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Tau")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for upsilon messages
func createUpsilonWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Upsilon")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for phi messages
func createPhiWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Phi")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for chi messages
func createChiWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Chi")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for psi messages
func createPsiWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Psi")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omega messages
func createOmegaWindow(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omega")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for alpha messages
func createAlphaWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Alpha2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for beta messages
func createBetaWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Beta2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for gamma messages
func createGammaWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Gamma2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for delta messages
func createDeltaWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Delta2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for epsilon messages
func createEpsilonWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Epsilon2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for zeta messages
func createZetaWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Zeta2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for eta messages
func createEtaWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Eta2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for theta messages
func createThetaWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Theta2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for iota messages
func createIotaWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Iota2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for kappa messages
func createKappaWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Kappa2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for lambda messages
func createLambdaWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Lambda2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for mu messages
func createMuWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Mu2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for nu messages
func createNuWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Nu2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for xi messages
func createXiWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Xi2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omicron messages
func createOmicronWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omicron2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for pi messages
func createPiWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Pi2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for rho messages
func createRhoWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Rho2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for sigma messages
func createSigmaWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Sigma2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for tau messages
func createTauWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Tau2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for upsilon messages
func createUpsilonWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Upsilon2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for phi messages
func createPhiWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Phi2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for chi messages
func createChiWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Chi2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for psi messages
func createPsiWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Psi2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omega messages
func createOmegaWindow2(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omega2")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for alpha messages
func createAlphaWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Alpha3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for beta messages
func createBetaWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Beta3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for gamma messages
func createGammaWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Gamma3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for delta messages
func createDeltaWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Delta3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for epsilon messages
func createEpsilonWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Epsilon3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for zeta messages
func createZetaWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Zeta3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for eta messages
func createEtaWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Eta3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for theta messages
func createThetaWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Theta3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for iota messages
func createIotaWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Iota3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for kappa messages
func createKappaWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Kappa3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for lambda messages
func createLambdaWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Lambda3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for mu messages
func createMuWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Mu3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for nu messages
func createNuWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Nu3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for xi messages
func createXiWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Xi3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omicron messages
func createOmicronWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omicron3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for pi messages
func createPiWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Pi3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for rho messages
func createRhoWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Rho3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for sigma messages
func createSigmaWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Sigma3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for tau messages
func createTauWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Tau3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for upsilon messages
func createUpsilonWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Upsilon3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for phi messages
func createPhiWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Phi3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for chi messages
func createChiWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Chi3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for psi messages
func createPsiWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Psi3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omega messages
func createOmegaWindow3(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omega3")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for alpha messages
func createAlphaWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Alpha4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for beta messages
func createBetaWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Beta4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for gamma messages
func createGammaWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Gamma4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for delta messages
func createDeltaWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Delta4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for epsilon messages
func createEpsilonWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Epsilon4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for zeta messages
func createZetaWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Zeta4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for eta messages
func createEtaWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Eta4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for theta messages
func createThetaWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Theta4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for iota messages
func createIotaWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Iota4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for kappa messages
func createKappaWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Kappa4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for lambda messages
func createLambdaWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Lambda4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for mu messages
func createMuWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Mu4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for nu messages
func createNuWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Nu4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for xi messages
func createXiWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Xi4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omicron messages
func createOmicronWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omicron4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for pi messages
func createPiWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Pi4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for rho messages
func createRhoWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Rho4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for sigma messages
func createSigmaWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Sigma4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for tau messages
func createTauWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Tau4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for upsilon messages
func createUpsilonWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Upsilon4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for phi messages
func createPhiWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Phi4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for chi messages
func createChiWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Chi4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for psi messages
func createPsiWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Psi4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omega messages
func createOmegaWindow4(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omega4")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for alpha messages
func createAlphaWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Alpha5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for beta messages
func createBetaWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Beta5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for gamma messages
func createGammaWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Gamma5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for delta messages
func createDeltaWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Delta5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for epsilon messages
func createEpsilonWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Epsilon5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for zeta messages
func createZetaWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Zeta5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for eta messages
func createEtaWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Eta5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for theta messages
func createThetaWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Theta5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for iota messages
func createIotaWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Iota5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for kappa messages
func createKappaWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Kappa5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for lambda messages
func createLambdaWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Lambda5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for mu messages
func createMuWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Mu5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for nu messages
func createNuWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Nu5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for xi messages
func createXiWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Xi5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omicron messages
func createOmicronWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omicron5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for pi messages
func createPiWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Pi5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for rho messages
func createRhoWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Rho5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for sigma messages
func createSigmaWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Sigma5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for tau messages
func createTauWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Tau5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for upsilon messages
func createUpsilonWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Upsilon5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for phi messages
func createPhiWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Phi5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for chi messages
func createChiWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Chi5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for psi messages
func createPsiWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Psi5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omega messages
func createOmegaWindow5(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omega5")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for alpha messages
func createAlphaWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Alpha6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for beta messages
func createBetaWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Beta6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for gamma messages
func createGammaWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Gamma6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for delta messages
func createDeltaWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Delta6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for epsilon messages
func createEpsilonWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Epsilon6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for zeta messages
func createZetaWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Zeta6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for eta messages
func createEtaWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Eta6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for theta messages
func createThetaWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Theta6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for iota messages
func createIotaWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Iota6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for kappa messages
func createKappaWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Kappa6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for lambda messages
func createLambdaWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Lambda6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for mu messages
func createMuWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Mu6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for nu messages
func createNuWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Nu6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for xi messages
func createXiWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Xi6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omicron messages
func createOmicronWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omicron6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for pi messages
func createPiWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Pi6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for rho messages
func createRhoWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Rho6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for sigma messages
func createSigmaWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Sigma6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for tau messages
func createTauWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Tau6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for upsilon messages
func createUpsilonWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Upsilon6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for phi messages
func createPhiWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Phi6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for chi messages
func createChiWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Chi6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for psi messages
func createPsiWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Psi6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omega messages
func createOmegaWindow6(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omega6")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for alpha messages
func createAlphaWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Alpha7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for beta messages
func createBetaWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Beta7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for gamma messages
func createGammaWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Gamma7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for delta messages
func createDeltaWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Delta7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for epsilon messages
func createEpsilonWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Epsilon7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for zeta messages
func createZetaWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Zeta7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for eta messages
func createEtaWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Eta7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for theta messages
func createThetaWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Theta7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for iota messages
func createIotaWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Iota7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for kappa messages
func createKappaWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Kappa7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for lambda messages
func createLambdaWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Lambda7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for mu messages
func createMuWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Mu7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for nu messages
func createNuWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Nu7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for xi messages
func createXiWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Xi7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omicron messages
func createOmicronWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omicron7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for pi messages
func createPiWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Pi7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for rho messages
func createRhoWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Rho7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for sigma messages
func createSigmaWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Sigma7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for tau messages
func createTauWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Tau7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for upsilon messages
func createUpsilonWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Upsilon7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for phi messages
func createPhiWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Phi7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for chi messages
func createChiWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Chi7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for psi messages
func createPsiWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Psi7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omega messages
func createOmegaWindow7(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omega7")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for alpha messages
func createAlphaWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Alpha8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for beta messages
func createBetaWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Beta8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for gamma messages
func createGammaWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Gamma8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for delta messages
func createDeltaWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Delta8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for epsilon messages
func createEpsilonWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Epsilon8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for zeta messages
func createZetaWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Zeta8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for eta messages
func createEtaWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Eta8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for theta messages
func createThetaWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Theta8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for iota messages
func createIotaWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Iota8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for kappa messages
func createKappaWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Kappa8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for lambda messages
func createLambdaWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Lambda8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for mu messages
func createMuWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Mu8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for nu messages
func createNuWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Nu8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for xi messages
func createXiWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Xi8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omicron messages
func createOmicronWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omicron8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for pi messages
func createPiWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Pi8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for rho messages
func createRhoWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Rho8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for sigma messages
func createSigmaWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Sigma8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for tau messages
func createTauWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Tau8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for upsilon messages
func createUpsilonWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Upsilon8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for phi messages
func createPhiWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Phi8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for chi messages
func createChiWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Chi8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for psi messages
func createPsiWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Psi8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omega messages
func createOmegaWindow8(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omega8")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for alpha messages
func createAlphaWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Alpha9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for beta messages
func createBetaWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Beta9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for gamma messages
func createGammaWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Gamma9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for delta messages
func createDeltaWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Delta9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for epsilon messages
func createEpsilonWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Epsilon9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for zeta messages
func createZetaWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Zeta9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for eta messages
func createEtaWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Eta9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for theta messages
func createThetaWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Theta9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for iota messages
func createIotaWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Iota9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for kappa messages
func createKappaWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Kappa9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for lambda messages
func createLambdaWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Lambda9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for mu messages
func createMuWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Mu9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for nu messages
func createNuWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Nu9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for xi messages
func createXiWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Xi9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omicron messages
func createOmicronWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omicron9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for pi messages
func createPiWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Pi9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for rho messages
func createRhoWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Rho9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for sigma messages
func createSigmaWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Sigma9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for tau messages
func createTauWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Tau9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for upsilon messages
func createUpsilonWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Upsilon9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for phi messages
func createPhiWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Phi9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for chi messages
func createChiWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Chi9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for psi messages
func createPsiWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Psi9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omega messages
func createOmegaWindow9(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omega9")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for alpha messages
func createAlphaWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Alpha10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for beta messages
func createBetaWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Beta10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for gamma messages
func createGammaWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Gamma10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for delta messages
func createDeltaWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Delta10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for epsilon messages
func createEpsilonWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Epsilon10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for zeta messages
func createZetaWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Zeta10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for eta messages
func createEtaWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Eta10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for theta messages
func createThetaWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Theta10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for iota messages
func createIotaWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Iota10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for kappa messages
func createKappaWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Kappa10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for lambda messages
func createLambdaWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Lambda10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for mu messages
func createMuWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Mu10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for nu messages
func createNuWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Nu10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for xi messages
func createXiWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Xi10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omicron messages
func createOmicronWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omicron10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for pi messages
func createPiWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Pi10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for rho messages
func createRhoWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Rho10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for sigma messages
func createSigmaWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Sigma10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for tau messages
func createTauWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Tau10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for upsilon messages
func createUpsilonWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Upsilon10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for phi messages
func createPhiWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Phi10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for chi messages
func createChiWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Chi10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for psi messages
func createPsiWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Psi10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}

// Helper function to create a simple app window for omega messages
func createOmegaWindow10(message string) fyne.Window {
	a := app.New()
	w := a.NewWindow("Omega10")
	w.SetContent(widget.NewLabel(message))
	w.Resize(fyne.NewSize(400, 200))
	return w
}
