package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
	"github.com/zigorminsk-debug/office-security-check/internal/netutil"
)

// maxHTTPBody — максимальный объём читаемого тела ответа.
const maxHTTPBody = 256 * 1024

// httpDo выполняет HTTP(S)-запрос с отключённой проверкой сертификатов.
func httpDo(ctx context.Context, url, host string) (body string, status int, err error) {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // аудит чужих сертификатов
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
	}
	client := &http.Client{
		Timeout:   8 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 4 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "OfficeSecurityCheck/1.0 (аудит безопасности)")
	req.Host = host
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxHTTPBody)
	b, _ := io.ReadAll(limited)
	return string(b), resp.StatusCode, nil
}

// httpRaw выполняет произвольный HTTP-запрос и возвращает ответ целиком.
func httpRaw(ctx context.Context, method, url, host string) (string, error) {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // аудит
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}
	client := &http.Client{Timeout: 8 * time.Second, Transport: transport}
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "OfficeSecurityCheck/1.0 (аудит безопасности)")
	req.Host = host
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	headers := make([]string, 0, len(resp.Header))
	for k, v := range resp.Header {
		headers = append(headers, k+": "+strings.Join(v, " "))
	}
	return fmt.Sprintf("HTTP/1.1 %s\r\n%s\r\n\r\n%s", resp.Status, strings.Join(headers, "\r\n"), string(b)), nil
}

// requiredHeaders — заголовки безопасности, наличие которых проверяется.
var requiredHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
}

// sensitivePaths — пути с конфиденциальными данными и служебными страницами.
var sensitivePaths = []struct {
	path  string
	kind  string // sensitive | status | admin
	title string
}{
	{"/.git/HEAD", "sensitive", "Git-репозиторий"},
	{"/.env", "sensitive", "Файл окружения .env"},
	{"/web.config", "sensitive", "Конфигурация IIS"},
	{"/backup.zip", "sensitive", "Резервная копия"},
	{"/dump.sql", "sensitive", "Дамп базы данных"},
	{"/phpinfo.php", "sensitive", "phpinfo()"},
	{"/server-status", "status", "Apache server-status"},
	{"/server-info", "status", "Apache server-info"},
	{"/actuator/env", "status", "Spring Boot Actuator"},
	{"/actuator/health", "status", "Spring Boot Actuator"},
	{"/manager/html", "admin", "Tomcat Manager"},
	{"/wp-login.php", "admin", "WordPress"},
	{"/adminer.php", "admin", "Adminer"},
	{"/phpmyadmin/", "admin", "phpMyAdmin"},
	{"/_cat/indices", "status", "Elasticsearch API"},
}

var (
	reTitle      = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reDirListing = regexp.MustCompile(`(?i)(index of /|directory listing for)`)
)

// httpProbe выполняет комплексную проверку веб-сервера.
func (e *Engine) httpProbe(ctx context.Context, svc *model.Service) {
	scheme := "http"
	if tlsPorts[svc.Port] || svc.Name == "https" {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://%s", scheme, netutil.JoinHostPort(svc.Host, svc.Port))
	info := &model.HTTPInfo{SecurityHeaders: map[string]string{}, FoundPaths: map[string]int{}}
	svc.HTTP = info

	// 1. Главная страница.
	body, status, err := httpDo(ctx, base+"/", svc.Host)
	if err != nil {
		svc.HTTP = nil
		return
	}
	info.StatusCode = status

	// Заголовки повторно через raw, чтобы собрать полный набор.
	if raw, err := httpRaw(ctx, "GET", base+"/", svc.Host); err == nil {
		info.Server = headerValue(raw, "Server:")
		info.PoweredBy = headerValue(raw, "X-Powered-By:")
		for _, h := range requiredHeaders {
			if v := headerValue(raw, h+":"); v != "" {
				info.SecurityHeaders[h] = v
			} else {
				info.MissingHeaders = append(info.MissingHeaders, h)
			}
		}
	}
	if m := reTitle.FindStringSubmatch(body); m != nil {
		info.Title = strings.TrimSpace(strings.ReplaceAll(m[1], "\n", " "))
	}

	// 2. Методы HTTP (OPTIONS/TRACE).
	if raw, err := httpRaw(ctx, "OPTIONS", base+"/", svc.Host); err == nil {
		if allow := headerValue(raw, "Allow:"); allow != "" {
			info.Methods = strings.Split(allow, ",")
			for i := range info.Methods {
				info.Methods[i] = strings.TrimSpace(info.Methods[i])
			}
		}
	}
	if raw, err := httpRaw(ctx, "TRACE", base+"/", svc.Host); err == nil {
		if strings.Contains(raw, "HTTP/1.1 200") || strings.Contains(raw, "TRACE /") {
			svc.Extra["http_trace"] = "true"
		}
	}

	// 3. WebDAV.
	if raw, err := httpRaw(ctx, "PROPFIND", base+"/", svc.Host); err == nil {
		if strings.Contains(raw, "HTTP/1.1 207") || strings.Contains(raw, "HTTP/1.1 200") && strings.Contains(raw, "<D:multistatus") {
			svc.Extra["webdav"] = "true"
		}
	}

	// 4. Открытый прокси (CONNECT).
	e.checkOpenProxy(ctx, svc, base)

	// 5. Опасные пути.
	foundSensitive := false
	for _, p := range sensitivePaths {
		if ctx.Err() != nil {
			break
		}
		_, st, err := httpDo(ctx, base+p.path, svc.Host)
		if err != nil || st != 200 {
			continue
		}
		info.FoundPaths[p.path] = st
		switch p.kind {
		case "sensitive":
			foundSensitive = true
		case "status":
			svc.Extra["status_pages"] = "true"
		case "admin":
			svc.Extra["admin_panel"] = "true"
		}
	}
	if foundSensitive {
		svc.Extra["sensitive_files"] = "true"
	}

	// 6. Листинг каталогов.
	if reDirListing.MatchString(body) {
		svc.Extra["dir_listing"] = "true"
	}

	// 7. Панели администрирования по заголовкам и заголовку страницы.
	detectAdminPanel(svc, info)
}

// checkOpenProxy проверяет, работает ли сервер как открытый прокси.
func (e *Engine) checkOpenProxy(ctx context.Context, svc *model.Service, base string) {
	transport := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // аудит
		DisableKeepAlives:  true,
		DialContext:        (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		DisableCompression: true,
	}
	client := &http.Client{
		Timeout:   6 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, "CONNECT", base+"/", nil)
	if err != nil {
		return
	}
	req.URL.Opaque = "www.example.com:443"
	req.Host = "www.example.com:443"
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		svc.Extra["open_proxy"] = "true"
	}
}

// detectAdminPanel определяет панель администрирования.
func detectAdminPanel(svc *model.Service, info *model.HTTPInfo) {
	title := strings.ToLower(info.Title)
	server := strings.ToLower(info.Server + " " + info.PoweredBy)
	combined := title + " " + server + " " + strings.ToLower(svc.Banner)
	markers := map[string]string{
		"jenkins":    "Jenkins",
		"phpmyadmin": "phpMyAdmin",
		"adminer":    "Adminer",
		"portainer":  "Portainer",
		"grafana":    "Grafana",
		"kibana":     "Kibana",
		"zabbix":     "Zabbix",
		"weblogic":   "Oracle WebLogic",
		"tomcat":     "Apache Tomcat",
		"jboss":      "JBoss/WildFly",
		"wildfly":    "JBoss/WildFly",
		"webmin":     "Webmin",
		"cpanel":     "cPanel",
		"plesk":      "Plesk",
		"synology":   "Synology NAS",
		"qnap":       "QNAP NAS",
		"gitlab":     "GitLab",
		"wordpress":  "WordPress",
		"solr":       "Apache Solr",
		"rabbitmq":   "RabbitMQ Management",
		"sonarqube":  "SonarQube",
		"traefik":    "Traefik",
		"harbor":     "Harbor Registry",
		"veeam":      "Veeam Backup",
		"vsphere":    "VMware vSphere",
		"proxmox":    "Proxmox",
	}
	for marker, name := range markers {
		if strings.Contains(combined, marker) {
			svc.Extra["admin_panel"] = "true"
			if svc.Extra["panel_name"] == "" {
				svc.Extra["panel_name"] = name
			}
			switch marker {
			case "weblogic":
				svc.Extra["weblogic"] = "true"
			case "jboss", "wildfly":
				svc.Extra["jboss"] = "true"
			}
			break
		}
	}
}

// headerValue извлекает значение заголовка из текста HTTP-ответа.
func headerValue(raw, name string) string {
	idx := strings.Index(raw, "\r\n")
	if idx < 0 {
		return ""
	}
	headerBlock := raw
	if end := strings.Index(raw, "\r\n\r\n"); end > 0 {
		headerBlock = raw[:end]
	}
	for _, line := range strings.Split(headerBlock, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(name)) {
			return strings.TrimSpace(line[len(name):])
		}
	}
	return ""
}
