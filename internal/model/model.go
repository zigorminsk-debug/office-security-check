// Package model содержит общие типы данных приложения «Аудит защиты»:
// результаты сканирования, находки уязвимостей и параметры проверок.
package model

import "time"

// Severity — уровень опасности находки.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

// String возвращает русское обозначение уровня опасности.
func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "Критический"
	case SevHigh:
		return "Высокий"
	case SevMedium:
		return "Средний"
	case SevLow:
		return "Низкий"
	default:
		return "Информация"
	}
}

// Key возвращает машиночитаемый код уровня.
func (s Severity) Key() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// Weight — вес уровня опасности для расчёта балла защищённости.
func (s Severity) Weight() float64 {
	switch s {
	case SevCritical:
		return 25
	case SevHigh:
		return 10
	case SevMedium:
		return 4
	case SevLow:
		return 1
	default:
		return 0
	}
}

// ParseSeverity преобразует текстовый код в уровень опасности.
func ParseSeverity(key string) Severity {
	switch key {
	case "CRITICAL", "critical":
		return SevCritical
	case "HIGH", "high":
		return SevHigh
	case "MEDIUM", "medium":
		return SevMedium
	case "LOW", "low":
		return SevLow
	default:
		return SevInfo
	}
}

// Category — категория риска: к какому виду атак приводит уязвимость.
type Category string

const (
	// CatMalware — риск заражения вирусами и вредоносным ПО.
	CatMalware Category = "malware"
	// CatUnauthorized — риск несанкционированного доступа злоумышленников.
	CatUnauthorized Category = "unauthorized"
	// CatRansomware — риск шифрования серверов вымогателями (рансомвар).
	CatRansomware Category = "ransomware"
	// CatHardening — укрепление защиты (best practice).
	CatHardening Category = "hardening"
	// CatInfo — информационное сообщение.
	CatInfo Category = "info"
)

// String возвращает русское название категории.
func (c Category) String() string {
	switch c {
	case CatMalware:
		return "Заражение вирусами"
	case CatUnauthorized:
		return "Несанкционированный доступ"
	case CatRansomware:
		return "Шифрование данных (вымогатель)"
	case CatHardening:
		return "Укрепление защиты"
	default:
		return "Информация"
	}
}

// Finding — найденная уязвимость или отклонение от безопасной конфигурации.
type Finding struct {
	ID             string   `json:"id"`
	CheckID        string   `json:"check_id"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       Severity `json:"-"`
	SeverityKey    string   `json:"severity"`
	Category       Category `json:"category"`
	Host           string   `json:"host,omitempty"`
	Port           int      `json:"port,omitempty"`
	Protocol       string   `json:"protocol,omitempty"`
	Service        string   `json:"service,omitempty"`
	Evidence       string   `json:"evidence,omitempty"`
	CVEs           []string `json:"cves,omitempty"`
	CVSS           float64  `json:"cvss,omitempty"`
	Recommendation string   `json:"recommendation"`
	References     []string `json:"references,omitempty"`
}

// Finalize заполняет производные поля перед сохранением в отчёт.
func (f *Finding) Finalize() {
	f.SeverityKey = f.Severity.Key()
}

// NewFinding создаёт находку с заполненными производными полями.
func NewFinding(id, title, desc string, sev Severity, cat Category, rec string) Finding {
	f := Finding{
		ID:             id,
		CheckID:        id,
		Title:          title,
		Description:    desc,
		Severity:       sev,
		Category:       cat,
		Recommendation: rec,
	}
	f.Finalize()
	return f
}

// TLSInfo — сведения о TLS-сертификате и параметрах шифрования.
type TLSInfo struct {
	Version            string   `json:"version"`
	CipherSuite        string   `json:"cipher_suite"`
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	DaysLeft           int      `json:"days_left"`
	SelfSigned         bool     `json:"self_signed"`
	HostnameMismatch   bool     `json:"hostname_mismatch"`
	PublicKeyBits      int      `json:"public_key_bits"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	SANs               []string `json:"sans,omitempty"`
	SupportsTLS10      bool     `json:"supports_tls10"`
	SupportsTLS11      bool     `json:"supports_tls11"`
	SupportsTLS12      bool     `json:"supports_tls12"`
	SupportsTLS13      bool     `json:"supports_tls13"`
	WeakCipher         string   `json:"weak_cipher,omitempty"`
	Heartbleed         bool     `json:"heartbleed"`
}

// HTTPInfo — сведения, полученные при проверке веб-сервера.
type HTTPInfo struct {
	StatusCode      int               `json:"status_code"`
	Server          string            `json:"server"`
	PoweredBy       string            `json:"powered_by"`
	Title           string            `json:"title"`
	SecurityHeaders map[string]string `json:"security_headers,omitempty"`
	MissingHeaders  []string          `json:"missing_headers,omitempty"`
	FoundPaths      map[string]int    `json:"found_paths,omitempty"`
	Methods         []string          `json:"methods,omitempty"`
	Notes           []string          `json:"notes,omitempty"`
}

// Service — открытый порт с определённой службой.
type Service struct {
	Host     string            `json:"host"`
	Port     int               `json:"port"`
	Protocol string            `json:"protocol"`
	State    string            `json:"state"`
	Name     string            `json:"name"`
	Product  string            `json:"product,omitempty"`
	Version  string            `json:"version,omitempty"`
	Banner   string            `json:"banner,omitempty"`
	TLS      *TLSInfo          `json:"tls,omitempty"`
	HTTP     *HTTPInfo         `json:"http,omitempty"`
	Extra    map[string]string `json:"extra,omitempty"`
}

// Label возвращает краткое описание службы для отчёта.
func (s *Service) Label() string {
	name := s.Name
	if s.Product != "" {
		name = s.Product
	}
	if s.Version != "" {
		name += " " + s.Version
	}
	return name
}

// Host — узел сети с результатами проверки.
type Host struct {
	IP        string            `json:"ip"`
	Hostname  string            `json:"hostname,omitempty"`
	Alive     bool              `json:"alive"`
	LatencyMS int64             `json:"latency_ms,omitempty"`
	OSHint    string            `json:"os_hint,omitempty"`
	Services  []Service         `json:"services,omitempty"`
	Extra     map[string]string `json:"extra,omitempty"`
}

// CheckStatus — статус проверки локального хоста.
type CheckStatus string

const (
	CheckPassed  CheckStatus = "passed"
	CheckFailed  CheckStatus = "failed"
	CheckSkipped CheckStatus = "skipped"
	CheckError   CheckStatus = "error"
)

// CheckResult — результат одной проверки защищённости локального хоста.
type CheckResult struct {
	ID             string      `json:"id"`
	Title          string      `json:"title"`
	Category       Category    `json:"category"`
	Status         CheckStatus `json:"status"`
	Value          string      `json:"value,omitempty"`
	Severity       Severity    `json:"-"`
	SeverityKey    string      `json:"severity"`
	Description    string      `json:"description,omitempty"`
	Recommendation string      `json:"recommendation,omitempty"`
}

// Finalize заполняет производные поля.
func (c *CheckResult) Finalize() {
	c.SeverityKey = c.Severity.Key()
}

// ScanProfile — профиль сканирования.
type ScanProfile string

const (
	ProfileQuick    ScanProfile = "quick"
	ProfileStandard ScanProfile = "standard"
	ProfileDeep     ScanProfile = "deep"
	ProfileCustom   ScanProfile = "custom"
)

// ProfileName возвращает русское имя профиля.
func (p ScanProfile) Name() string {
	switch p {
	case ProfileQuick:
		return "Быстрый"
	case ProfileStandard:
		return "Стандартный"
	case ProfileDeep:
		return "Глубокий"
	default:
		return "Пользовательский"
	}
}

// ScanConfig — параметры сканирования сети.
type ScanConfig struct {
	Targets       []string      `json:"targets"`
	Profile       ScanProfile   `json:"profile"`
	Ports         []int         `json:"ports,omitempty"`
	PortRange     string        `json:"port_range,omitempty"`
	Timeout       time.Duration `json:"-"`
	TimeoutMS     int           `json:"timeout_ms"`
	Workers       int           `json:"workers"`
	RatePerSec    int           `json:"rate_per_sec"`
	SkipDiscovery bool          `json:"skip_discovery"`
	DeepHTTP      bool          `json:"deep_http"`
	UDP           bool          `json:"udp"`
	TLSAudit      bool          `json:"tls_audit"`
}

// Report — итоговый отчёт аудита.
type Report struct {
	Tool        string         `json:"tool"`
	Version     string         `json:"version"`
	GeneratedAt time.Time      `json:"generated_at"`
	Config      ScanConfig     `json:"config"`
	Hosts       []Host         `json:"hosts"`
	Findings    []Finding      `json:"findings"`
	HostAudit   []CheckResult  `json:"host_audit,omitempty"`
	Score       float64        `json:"score"`
	Counts      map[string]int `json:"counts"`
}

// Counts заполняет счётчики находок по уровням опасности.
func (r *Report) FillCounts() {
	r.Counts = map[string]int{
		"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
		"hosts": len(r.Hosts), "findings": len(r.Findings),
	}
	for _, f := range r.Findings {
		r.Counts[f.Severity.Key()]++
	}
}
