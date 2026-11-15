// Package scanner реализует движок сканирования сети:
// обнаружение хостов, сканирование портов, определение служб и протокольные проверки.
package scanner

import (
	"time"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
)

// Критические порты — точки входа вирусов, шифровальщиков и злоумышленников.
var quickPorts = []int{
	21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445,
	465, 587, 636, 993, 995, 1433, 1521, 2049, 2375, 2376, 3306, 3389,
	5432, 5900, 5985, 5986, 6379, 8080, 8443, 9200, 9300, 27017, 5672,
	1883, 11211, 5984, 2379, 10250, 9000, 9090, 7001, 9392, 5000, 5001,
	8000, 8888, 3128, 8118, 1080, 512, 513, 514, 623, 1434, 1521, 2181,
}

// Стандартный профиль — расширенный список распространённых портов.
var standardPorts = []int{
	20, 21, 22, 23, 25, 37, 53, 67, 68, 69, 79, 80, 81, 88, 106, 110, 111,
	113, 119, 135, 137, 139, 143, 161, 179, 389, 427, 443, 444, 445, 465,
	500, 512, 513, 514, 515, 520, 548, 554, 563, 587, 591, 593, 623, 631,
	636, 646, 873, 902, 989, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
	1080, 1194, 1433, 1434, 1521, 1720, 1723, 1755, 1900, 2000, 2049, 2082,
	2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375, 2376, 2379, 2483, 2484,
	3128, 3268, 3269, 3306, 3389, 4000, 4040, 4369, 4443, 4444, 4567, 4848,
	5000, 5001, 5009, 5060, 5061, 5357, 5432, 5601, 5672, 5800, 5900, 5901,
	5985, 5986, 5988, 5989, 6000, 6001, 6200, 6379, 6443, 6667, 7001, 7002,
	7070, 7443, 7777, 8000, 8001, 8008, 8009, 8010, 8080, 8081, 8082, 8083,
	8086, 8087, 8088, 8090, 8118, 8123, 8181, 8200, 8443, 8500, 8530, 8531,
	8834, 8880, 8888, 9000, 9001, 9042, 9080, 9090, 9092, 9200, 9300, 9392,
	9418, 9443, 9999, 10000, 10250, 10255, 11211, 15672, 27017, 27018, 28017,
	50000, 50070,
}

// UDP-порты для проверки в глубоком профиле.
var udpProbePorts = []int{53, 69, 123, 137, 161, 500, 514, 5353, 1900}

// DefaultConfig возвращает конфигурацию по умолчанию для профиля.
func DefaultConfig(profile model.ScanProfile) model.ScanConfig {
	cfg := model.ScanConfig{
		Profile:    profile,
		Timeout:    900 * time.Millisecond,
		Workers:    256,
		RatePerSec: 4000,
		TLSAudit:   true,
	}
	switch profile {
	case model.ProfileQuick:
		cfg.Ports = append([]int{}, quickPorts...)
		cfg.Timeout = 500 * time.Millisecond
	case model.ProfileStandard:
		cfg.Ports = append([]int{}, standardPorts...)
		cfg.DeepHTTP = true
	case model.ProfileDeep:
		cfg.Ports = make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			cfg.Ports = append(cfg.Ports, p)
		}
		cfg.DeepHTTP = true
		cfg.UDP = true
		cfg.Timeout = 1200 * time.Millisecond
		cfg.Workers = 512
	}
	return cfg
}

// wellKnownPorts — соответствие порта имени службы (используется как подсказка).
var wellKnownPorts = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	67: "dhcp", 69: "tftp", 79: "finger", 80: "http", 88: "kerberos", 110: "pop3",
	111: "rpcbind", 113: "ident", 119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
	138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp", 179: "bgp",
	389: "ldap", 427: "slp", 443: "https", 445: "smb", 465: "smtps", 500: "isakmp",
	512: "rexec", 513: "rlogin", 514: "rsh", 515: "lpd", 520: "rip", 548: "afp",
	554: "rtsp", 563: "nntps", 587: "submission", 591: "filemaker", 593: "http-rpc",
	623: "ipmi", 631: "ipp", 636: "ldaps", 873: "rsync", 902: "vmware", 989: "ftps-data",
	990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "mssql",
	1434: "mssql-m", 1521: "oracle-tns", 1720: "h323", 1723: "pptp", 1883: "mqtt",
	1900: "ssdp", 2049: "nfs", 2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
	2379: "etcd", 3128: "http-proxy", 3268: "ms-globalcat", 3269: "ms-globalcat-ssl",
	3306: "mysql", 3389: "rdp", 4369: "epmd", 4443: "https-alt", 4567: "kafka?",
	4848: "glassfish", 5000: "http-alt", 5001: "https-alt", 5060: "sip", 5061: "sips",
	5353: "mdns", 5357: "wdnapicn", 5432: "postgresql", 5601: "kibana", 5672: "amqp",
	5800: "vnc-http", 5900: "vnc", 5901: "vnc-1", 5985: "winrm", 5986: "winrms",
	6379: "redis", 6443: "kubernetes", 6667: "irc", 7001: "weblogic", 7443: "https-alt",
	8000: "http-alt", 8008: "http-alt", 8009: "ajp", 8080: "http-proxy", 8081: "http-alt",
	8086: "influxdb", 8087: "influxdb", 8088: "http-alt", 8090: "http-alt", 8118: "privoxy",
	8123: "clickhouse", 8200: "consul", 8443: "https-alt", 8500: "consul", 8530: "http-alt",
	8531: "https-alt", 8834: "nessus", 8880: "http-alt", 8888: "http-alt", 9000: "adminer",
	9042: "cassandra", 9080: "http-alt", 9090: "prometheus", 9092: "kafka", 9200: "elasticsearch",
	9300: "elasticsearch-t", 9392: "veeam", 9418: "git", 9999: "http-alt", 10000: "ndmp",
	10250: "kubelet", 10255: "kubelet-ro", 11211: "memcached", 15672: "rabbitmq-mgmt",
	27017: "mongodb", 27018: "mongodb", 28017: "mongodb-http", 50000: "sap",
}

// serviceByPort возвращает подсказку имени службы по номеру порта.
func serviceByPort(port int) string {
	if name, ok := wellKnownPorts[port]; ok {
		return name
	}
	return ""
}
