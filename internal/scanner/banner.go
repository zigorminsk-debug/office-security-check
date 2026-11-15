package scanner

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// httpPorts — порты, на которых вероятен обычный HTTP.
var httpPorts = map[int]bool{
	80: true, 81: true, 591: true, 593: true, 2080: true, 2082: true, 2083: true,
	2086: true, 2087: true, 2095: true, 2096: true, 3000: true, 3128: true,
	4000: true, 4040: true, 4567: true, 4848: true, 5000: true, 5060: true,
	5601: true, 5800: true, 5985: true, 5988: true, 6000: true, 6001: true,
	7001: true, 7002: true, 7070: true, 7777: true, 8000: true, 8001: true,
	8008: true, 8010: true, 8080: true, 8081: true, 8082: true, 8083: true,
	8086: true, 8087: true, 8088: true, 8090: true, 8118: true, 8123: true,
	8181: true, 8200: true, 8500: true, 8530: true, 8834: true, 8880: true,
	8888: true, 9000: true, 9001: true, 9080: true, 9090: true, 9092: true,
	9200: true, 9392: true, 9418: true, 9999: true, 10000: true, 15672: true,
	28017: true, 50070: true,
}

// tlsPorts — порты, на которых вероятен TLS.
var tlsPorts = map[int]bool{
	443: true, 465: true, 636: true, 989: true, 990: true, 993: true, 995: true,
	1443: true, 2376: true, 3269: true, 4443: true, 5061: true, 5986: true,
	6443: true, 7443: true, 8443: true, 8531: true, 9443: true, 10250: true,
}

// grabAndFingerprint читает баннер открытого порта и определяет службу.
// Возвращает баннер, канонический продукт и версию.
func grabAndFingerprint(ctx context.Context, conn net.Conn, port int) (banner, product, version string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))

	// 1. Спонтанный баннер (SSH, FTP, SMTP, Telnet, VNC...).
	raw := readBanner(conn, 800*time.Millisecond)
	banner = cleanBanner(raw)

	// 2. Нет баннера — пробуем HTTP или TLS.
	if banner == "" {
		if isTLSRecord(raw) {
			banner = "[TLS-сервис]"
		} else if httpPorts[port] {
			_, _ = fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: OfficeSecurityCheck/1.0\r\n\r\n")
			raw = readBanner(conn, 1200*time.Millisecond)
			banner = cleanBanner(raw)
		} else {
			// 3. Универсальный провокационный запрос.
			_, _ = conn.Write([]byte("\r\n"))
			raw = readBanner(conn, 500*time.Millisecond)
			banner = cleanBanner(raw)
		}
	} else if strings.HasPrefix(banner, "HTTP/") {
		// HTTP-ответ на спонтанный запрос.
	}

	product, version = fingerprint(port, banner, raw)
	return banner, product, version
}

// readBanner читает данные из соединения до тайм-аута.
func readBanner(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var sb strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
			if sb.Len() > 4096 {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return sb.String()
}

// isTLSRecord определяет TLS-запись по сигнатуре (0x16 0x03 ...).
func isTLSRecord(raw string) bool {
	if len(raw) < 3 {
		return false
	}
	b := []byte(raw)
	return b[0] == 0x16 && b[1] == 0x03
}

// cleanBanner очищает баннер от управляющих символов.
func cleanBanner(raw string) string {
	raw = strings.TrimSpace(raw)
	var sb strings.Builder
	for _, r := range raw {
		if r == '\r' || r == '\n' {
			if sb.Len() > 0 && !strings.HasSuffix(sb.String(), " | ") {
				sb.WriteString(" | ")
			}
			continue
		}
		if r < 32 && r != '\t' {
			sb.WriteRune('.')
			continue
		}
		sb.WriteRune(r)
	}
	s := strings.TrimSuffix(sb.String(), " | ")
	s = strings.TrimSuffix(s, "|")
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

var (
	reServerApache  = regexp.MustCompile(`(?i)apache[/ ](\d+\.\d+(?:\.\d+)?)`)
	reServerNginx   = regexp.MustCompile(`(?i)nginx[/ ](\d+\.\d+(?:\.\d+)?)`)
	reServerIIS     = regexp.MustCompile(`(?i)microsoft-iis[/ ](\d+\.\d+)`)
	reServerLight   = regexp.MustCompile(`(?i)lighttpd[/ ](\d+\.\d+(?:\.\d+)?)`)
	reOpenSSH       = regexp.MustCompile(`(?i)openssh[_ ](\d+\.\d+(?:p\d+)?)`)
	reDropbear      = regexp.MustCompile(`(?i)dropbear[_ ](\d+\.\d+)`)
	reProFTPD       = regexp.MustCompile(`(?i)proftpd[^\d]*(\d+\.\d+\.\d+)`)
	reVsFTPD        = regexp.MustCompile(`(?i)vsftpd[^\d]*(\d+\.\d+\.\d+)`)
	reFileZilla     = regexp.MustCompile(`(?i)filezilla server[^\d]*(\d+\.\d+)`)
	reExim          = regexp.MustCompile(`(?i)exim[^\d]*(\d+\.\d+(?:\.\d+)?)`)
	rePostfix       = regexp.MustCompile(`(?i)postfix`)
	reMySQL         = regexp.MustCompile(`(?i)(?:mysql|mariadb)[^\d]*(\d+\.\d+\.\d+)`)
	rePHP           = regexp.MustCompile(`(?i)php[/ ](\d+\.\d+\.\d+)`)
	reRFB           = regexp.MustCompile(`RFB (\d+\.\d+)`)
	reTomcat        = regexp.MustCompile(`(?i)(?:tomcat|apache-coyote)[^\d]*(\d+\.\d+\.\d+)`)
	reJetty         = regexp.MustCompile(`(?i)jetty[^\d]*(\d+\.\d+(?:\.\d+)?)`)
	reWebLogic      = regexp.MustCompile(`(?i)weblogic`)
	reJBoss         = regexp.MustCompile(`(?i)jboss|wildfly`)
	reOracleTNS     = regexp.MustCompile(`(?i)oracle|tns`)
	reElastic       = regexp.MustCompile(`(?i)elasticsearch|"cluster_name"`)
	reCouchDB       = regexp.MustCompile(`(?i)couchdb`)
	reMongo         = regexp.MustCompile(`(?i)ismaster|mongodb|mongo`)
	reKafka         = regexp.MustCompile(`(?i)kafka`)
	reZabbix        = regexp.MustCompile(`(?i)zabbix`)
	reSSHOther      = regexp.MustCompile(`SSH-2\.0-([A-Za-z0-9._\-]+)`)
	reServerGeneric = regexp.MustCompile(`(?i)server:\s*([^\r\n]+)`)
)

// fingerprint определяет продукт и версию по баннеру и порту.
func fingerprint(port int, banner string, raw string) (product, version string) {
	low := strings.ToLower(banner)

	// SSH.
	if m := reOpenSSH.FindStringSubmatch(banner); m != nil {
		return "openssh", m[1]
	}
	if strings.HasPrefix(banner, "SSH-") {
		if m := reDropbear.FindStringSubmatch(banner); m != nil {
			return "dropbear", m[1]
		}
		if m := reSSHOther.FindStringSubmatch(banner); m != nil {
			return strings.ToLower(m[1]), ""
		}
		return "ssh", ""
	}

	// FTP.
	if m := reVsFTPD.FindStringSubmatch(banner); m != nil {
		return "vsftpd", m[1]
	}
	if m := reProFTPD.FindStringSubmatch(banner); m != nil {
		return "proftpd", m[1]
	}
	if m := reFileZilla.FindStringSubmatch(banner); m != nil {
		return "filezilla", m[1]
	}
	if strings.Contains(low, "microsoft ftp") {
		return "iis-ftp", ""
	}
	if strings.Contains(low, "ftp") && strings.HasPrefix(banner, "220") {
		return "ftp", ""
	}

	// SMTP.
	if m := reExim.FindStringSubmatch(banner); m != nil {
		return "exim", m[1]
	}
	if rePostfix.MatchString(banner) {
		return "postfix", ""
	}
	if strings.Contains(low, "microsoft esmtp") {
		return "microsoft-smtp", ""
	}

	// HTTP и заголовок Server.
	serverHdr := ""
	if m := reServerGeneric.FindStringSubmatch(banner); m != nil {
		serverHdr = m[1]
	}
	combined := banner
	if serverHdr != "" {
		combined += " " + serverHdr
	}
	if m := reServerApache.FindStringSubmatch(combined); m != nil {
		return "apache", m[1]
	}
	if m := reServerNginx.FindStringSubmatch(combined); m != nil {
		return "nginx", m[1]
	}
	if m := reServerIIS.FindStringSubmatch(combined); m != nil {
		return "iis", m[1]
	}
	if m := reServerLight.FindStringSubmatch(combined); m != nil {
		return "lighttpd", m[1]
	}
	if m := rePHP.FindStringSubmatch(combined); m != nil {
		return "php", m[1]
	}
	if m := reTomcat.FindStringSubmatch(combined); m != nil {
		return "tomcat", m[1]
	}
	if m := reJetty.FindStringSubmatch(combined); m != nil {
		return "jetty", m[1]
	}
	if reWebLogic.MatchString(combined) {
		return "weblogic", ""
	}
	if reJBoss.MatchString(combined) {
		return "jboss", ""
	}

	// MySQL/MariaDB (гreeting содержит версию).
	if m := reMySQL.FindStringSubmatch(banner); m != nil {
		return "mysql", m[1]
	}
	if len(raw) > 5 && raw[4] == 0x0a && strings.ContainsAny(raw[5:], "0123456789") {
		// MySQL greeting packet: длина + 0x0a + версия.
		ver := extractMySQLVersion(raw)
		if ver != "" {
			return "mysql", ver
		}
	}

	// VNC.
	if m := reRFB.FindStringSubmatch(banner); m != nil {
		return "vnc", m[1]
	}

	// Прочие.
	if reElastic.MatchString(banner) {
		return "elasticsearch", ""
	}
	if reCouchDB.MatchString(banner) {
		return "couchdb", ""
	}
	if reMongo.MatchString(banner) {
		return "mongodb", ""
	}
	if reKafka.MatchString(banner) {
		return "kafka", ""
	}
	if reZabbix.MatchString(banner) {
		return "zabbix", ""
	}
	if reOracleTNS.MatchString(banner) && (port == 1521 || port == 2483 || port == 2484) {
		return "oracle-tns", ""
	}

	// Подсказка по порту для HTTP(S).
	if banner != "" && (strings.HasPrefix(banner, "HTTP/") || httpPorts[port]) {
		return httpProductFromBanner(banner)
	}
	return "", ""
}

// httpProductFromBanner извлекает продукт из HTTP-ответа.
func httpProductFromBanner(banner string) (string, string) {
	low := strings.ToLower(banner)
	if m := reServerApache.FindStringSubmatch(low); m != nil {
		return "apache", m[1]
	}
	if m := reServerNginx.FindStringSubmatch(low); m != nil {
		return "nginx", m[1]
	}
	if m := reServerIIS.FindStringSubmatch(low); m != nil {
		return "iis", m[1]
	}
	if m := reServerLight.FindStringSubmatch(low); m != nil {
		return "lighttpd", m[1]
	}
	if strings.Contains(low, "microsoft-iis") {
		return "iis", ""
	}
	if strings.Contains(low, "caddy") {
		return "caddy", ""
	}
	if strings.Contains(low, "openresty") {
		return "openresty", ""
	}
	return "http", ""
}

// extractMySQLVersion извлекает версию из MySQL greeting-пакета.
func extractMySQLVersion(raw string) string {
	b := []byte(raw)
	if len(b) < 8 || b[4] != 0x0a {
		return ""
	}
	end := -1
	for i := 5; i < len(b); i++ {
		if b[i] == 0x00 {
			end = i
			break
		}
	}
	if end <= 5 {
		return ""
	}
	return string(b[5:end])
}

// canonicalService возвращает каноническое имя службы по продукту.
func canonicalService(product string) string {
	switch product {
	case "apache", "nginx", "iis", "lighttpd", "caddy", "openresty":
		return "http"
	case "openssh", "dropbear":
		return "ssh"
	case "vsftpd", "proftpd", "filezilla", "iis-ftp":
		return "ftp"
	case "exim", "postfix", "microsoft-smtp":
		return "smtp"
	case "mysql", "mariadb":
		return "mysql"
	}
	return product
}

// hexPreview возвращает hex-представление баннера (для отчётов о бинарных службах).
func hexPreview(raw string, n int) string {
	b := []byte(raw)
	if len(b) > n {
		b = b[:n]
	}
	return hex.EncodeToString(b)
}

// readLine читает одну строку из буферизованного соединения (для протокольных диалогов).
func readLine(r *bufio.Reader) string {
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimRight(line, "\r\n")
}
