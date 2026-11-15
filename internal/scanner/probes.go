package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
	"github.com/zigorminsk-debug/office-security-check/internal/netutil"
)

// probeTimeout — тайм-аут одной протокольной проверки.
const probeTimeout = 4 * time.Second

// runProbes запускает протокольные проверки для одной службы.
func (e *Engine) runProbes(ctx context.Context, svc *model.Service) {
	if svc.Extra == nil {
		svc.Extra = make(map[string]string)
	}
	switch svc.Name {
	case "smb", "netbios-ssn":
		e.smbProbe(ctx, svc)
	case "rdp":
		e.rdpProbe(ctx, svc)
	case "ftp":
		e.ftpProbe(ctx, svc)
	case "smtp", "submission", "smtps":
		e.smtpProbe(ctx, svc)
	case "redis":
		e.redisProbe(ctx, svc)
	case "mongodb":
		e.mongoProbe(ctx, svc)
	case "elasticsearch":
		e.elasticProbe(ctx, svc)
	case "couchdb":
		e.httpJSONProbe(ctx, svc, "/", "couchdb", "couchdb_unauth")
	case "memcached":
		e.memcachedProbe(ctx, svc)
	case "mqtt":
		e.mqttProbe(ctx, svc)
	case "amqp":
		e.amqpProbe(ctx, svc)
	case "docker", "docker-tls":
		e.httpJSONProbe(ctx, svc, "/_ping", "", "docker_unauth")
	case "kubernetes":
		e.httpAuthProbe(ctx, svc, "/api", "k8s_unauth")
	case "kubelet", "kubelet-ro":
		e.httpAuthProbe(ctx, svc, "/runningpods/", "kubelet_unauth")
	case "etcd":
		e.etcdProbe(ctx, svc)
	case "ldap", "ldaps":
		e.ldapProbe(ctx, svc)
	case "vnc", "vnc-1", "vnc-http":
		e.vncProbe(ctx, svc)
	case "telnet":
		// Баннер уже собран; Telnet сам по себе опасен (правило по имени).
	case "winrm", "winrms":
		if svc.Port == 5986 {
			e.tlsProbe(ctx, svc)
		}
	}

	// TLS-аудит для TLS-портов.
	if tlsPorts[svc.Port] && svc.TLS == nil {
		e.tlsProbe(ctx, svc)
	}

	// HTTP-проверка: если служба веб-сервер или отвечает по HTTP.
	if e.Cfg.DeepHTTP && svc.HTTP == nil && (httpPorts[svc.Port] || svc.Name == "http" ||
		svc.Name == "https" || strings.Contains(svc.Banner, "HTTP/")) {
		e.httpProbe(ctx, svc)
	}
}

// dialProbe открывает соединение для проверки.
func dialProbe(ctx context.Context, svc *model.Service) (net.Conn, error) {
	return netutil.DialTCP(ctx, netutil.JoinHostPort(svc.Host, svc.Port), probeTimeout)
}

// exchange отправляет данные и читает ответ.
func exchange(conn net.Conn, payload []byte, wait time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(wait))
	if len(payload) > 0 {
		_, _ = conn.Write(payload)
	}
	var sb strings.Builder
	buf := make([]byte, 2048)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
			if sb.Len() > 8192 {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return sb.String()
}

// ---------- Redis ----------

func (e *Engine) redisProbe(ctx context.Context, svc *model.Service) {
	conn, err := dialProbe(ctx, svc)
	if err != nil {
		return
	}
	defer conn.Close()
	resp := exchange(conn, []byte("PING\r\n"), 3*time.Second)
	if strings.Contains(resp, "+PONG") {
		svc.Extra["redis_unauth"] = "true"
		svc.Product = "redis"
		// Проверяем INFO для версии.
		conn2, err := dialProbe(ctx, svc)
		if err == nil {
			info := exchange(conn2, []byte("INFO server\r\n"), 3*time.Second)
			conn2.Close()
			if idx := strings.Index(info, "redis_version:"); idx >= 0 {
				ver := info[idx+len("redis_version:"):]
				if nl := strings.IndexAny(ver, "\r\n"); nl > 0 {
					svc.Version = ver[:nl]
				}
			}
		}
		return
	}
	if strings.Contains(resp, "-NOAUTH") || strings.Contains(resp, "-ERR") {
		svc.Product = "redis"
	}
}

// ---------- MongoDB ----------

func (e *Engine) mongoProbe(ctx context.Context, svc *model.Service) {
	conn, err := dialProbe(ctx, svc)
	if err != nil {
		return
	}
	defer conn.Close()
	// OP_QUERY isMaster (устаревший, но понятен всем версиям).
	payload := buildMongoIsMaster()
	resp := exchange(conn, payload, 3*time.Second)
	if len(resp) > 40 && strings.Contains(strings.ToLower(resp), "ismaster") ||
		strings.Contains(resp, "maxBsonObjectSize") || strings.Contains(resp, "maxWireVersion") {
		svc.Extra["mongo_unauth"] = "true"
		svc.Product = "mongodb"
		return
	}
	if len(resp) > 16 {
		svc.Product = "mongodb"
	}
}

// buildMongoIsMaster формирует OP_QUERY с командой isMaster.
func buildMongoIsMaster() []byte {
	// BSON: {isMaster: 1}
	bson := []byte{
		0x13, 0x00, 0x00, 0x00, // размер документа 19
		0x10, 'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00,
		0x01, 0x00, 0x00, 0x00, // int32 = 1
		0x00, // конец документа
	}
	msg := make([]byte, 0, 64)
	// Заголовок OP_QUERY: длина, requestID, responseTo, opCode(2004)
	header := []byte{0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xd4, 0x07, 0x00, 0x00}
	msg = append(msg, header...)
	msg = append(msg, 0x00, 0x00, 0x00, 0x00)                                 // flags
	msg = append(msg, 'a', 'd', 'm', 'i', 'n', '.', '$', 'c', 'm', 'd', 0x00) // fullCollectionName
	msg = append(msg, 0x00, 0x00, 0x00, 0x00)                                 // numberToSkip
	msg = append(msg, 0xff, 0xff, 0xff, 0xff)                                 // numberToReturn
	msg = append(msg, bson...)
	// Длина сообщения.
	total := len(msg)
	msg[0] = byte(total)
	msg[1] = byte(total >> 8)
	msg[2] = byte(total >> 16)
	msg[3] = byte(total >> 24)
	return msg
}

// ---------- Elasticsearch / CouchDB / Docker / K8s ----------

// httpJSONProbe выполняет HTTP GET и ищет сигнатуру JSON-сервиса.
func (e *Engine) httpJSONProbe(ctx context.Context, svc *model.Service, path, marker, flag string) {
	body, status := e.httpGet(ctx, svc, path)
	if body == "" {
		return
	}
	low := strings.ToLower(body)
	if marker != "" && !strings.Contains(low, strings.ToLower(marker)) {
		if status != 200 {
			return
		}
	}
	if status == 200 {
		svc.Extra[flag] = "true"
	}
	switch {
	case strings.Contains(low, "cluster_name"), strings.Contains(low, "tagline"):
		svc.Product = "elasticsearch"
	case strings.Contains(low, "couchdb"):
		svc.Product = "couchdb"
	case strings.Contains(low, "ok"), strings.Contains(low, "version"):
		if svc.Product == "" && svc.Name == "docker" {
			svc.Product = "docker"
		}
	}
}

// httpAuthProbe проверяет, отвечает ли сервис без аутентификации (200 = успех).
func (e *Engine) httpAuthProbe(ctx context.Context, svc *model.Service, path, flag string) {
	_, status := e.httpGet(ctx, svc, path)
	if status == 200 {
		svc.Extra[flag] = "true"
	}
}

// elasticProbe проверяет Elasticsearch без аутентификации и извлекает версию.
func (e *Engine) elasticProbe(ctx context.Context, svc *model.Service) {
	body, status := e.httpGet(ctx, svc, "/")
	if status != 200 || body == "" {
		return
	}
	low := strings.ToLower(body)
	if !strings.Contains(low, "cluster_name") && !strings.Contains(low, "elasticsearch") {
		return
	}
	svc.Product = "elasticsearch"
	svc.Extra["elastic_unauth"] = "true"
	// Версия вида "number" : "7.10.2".
	if m := reESVersion.FindStringSubmatch(body); m != nil {
		svc.Version = m[1]
	}
}

// reESVersion извлекает версию Elasticsearch из JSON-ответа.
var reESVersion = regexp.MustCompile(`"number"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"`)

// etcdProbe проверяет etcd без аутентификации.
func (e *Engine) etcdProbe(ctx context.Context, svc *model.Service) {
	body, status := e.httpGet(ctx, svc, "/version")
	if status == 200 && strings.Contains(body, "etcd") {
		svc.Extra["etcd_unauth"] = "true"
		svc.Product = "etcd"
	}
}

// ---------- Memcached ----------

func (e *Engine) memcachedProbe(ctx context.Context, svc *model.Service) {
	conn, err := dialProbe(ctx, svc)
	if err != nil {
		return
	}
	defer conn.Close()
	resp := exchange(conn, []byte("stats\r\n"), 3*time.Second)
	if strings.Contains(resp, "STAT pid") || strings.Contains(resp, "STAT version") {
		svc.Extra["memcached_unauth"] = "true"
		svc.Product = "memcached"
		if idx := strings.Index(resp, "STAT version "); idx >= 0 {
			ver := resp[idx+len("STAT version "):]
			if nl := strings.IndexAny(ver, "\r\n"); nl > 0 {
				svc.Version = ver[:nl]
			}
		}
	}
}

// ---------- MQTT ----------

func (e *Engine) mqttProbe(ctx context.Context, svc *model.Service) {
	conn, err := dialProbe(ctx, svc)
	if err != nil {
		return
	}
	defer conn.Close()
	// CONNECT без имени пользователя и пароля.
	payload := []byte{
		0x10, 0x0c, // CONNECT, длина
		0x00, 0x04, 'M', 'Q', 'T', 'T', // протокол
		0x04,       // уровень 3.1.1
		0x02,       // флаги: clean session
		0x00, 0x3c, // keep alive 60
		0x00, 0x00, // client id пустой
	}
	resp := exchange(conn, payload, 3*time.Second)
	if len(resp) >= 4 && resp[0] == 0x20 {
		// CONNACK: 0 = accepted.
		if resp[3] == 0x00 {
			svc.Extra["mqtt_unauth"] = "true"
		}
		svc.Product = "mqtt"
	}
}

// ---------- AMQP ----------

func (e *Engine) amqpProbe(ctx context.Context, svc *model.Service) {
	conn, err := dialProbe(ctx, svc)
	if err != nil {
		return
	}
	defer conn.Close()
	resp := exchange(conn, []byte("AMQP\x00\x00\x09\x01"), 3*time.Second)
	if strings.HasPrefix(resp, "AMQP") {
		svc.Product = "amqp"
		// Начало обмена без credentials — сервер принял протокол.
		svc.Extra["amqp_unauth"] = "true"
	}
}

// ---------- FTP ----------

func (e *Engine) ftpProbe(ctx context.Context, svc *model.Service) {
	conn, err := dialProbe(ctx, svc)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	r := bufio.NewReader(conn)
	greeting := readLine(r)
	if !strings.HasPrefix(greeting, "220") {
		return
	}
	_, _ = fmt.Fprintf(conn, "USER anonymous\r\n")
	resp := readLine(r)
	if strings.HasPrefix(resp, "331") {
		_, _ = fmt.Fprintf(conn, "PASS audit@example.com\r\n")
		resp = readLine(r)
	}
	if strings.HasPrefix(resp, "230") {
		svc.Extra["ftp_anon"] = "true"
	}
}

// ---------- SMTP ----------

func (e *Engine) smtpProbe(ctx context.Context, svc *model.Service) {
	conn, err := dialProbe(ctx, svc)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	r := bufio.NewReader(conn)
	greeting := readLine(r)
	if !strings.HasPrefix(greeting, "220") {
		return
	}
	_, _ = fmt.Fprintf(conn, "EHLO security-audit.local\r\n")
	ehlo := ""
	for {
		line := readLine(r)
		if line == "" {
			break
		}
		ehlo += line + "\n"
		if !strings.HasPrefix(line, "250-") {
			break
		}
	}
	// Проверка открытого релея: RCPT TO внешнему получателю без аутентификации.
	_, _ = fmt.Fprintf(conn, "MAIL FROM:<audit@security-audit.local>\r\n")
	ma := readLine(r)
	if strings.HasPrefix(ma, "250") {
		_, _ = fmt.Fprintf(conn, "RCPT TO:<relay-test@invalid.example>\r\n")
		rc := readLine(r)
		if strings.HasPrefix(rc, "250") || strings.HasPrefix(rc, "251") {
			svc.Extra["smtp_open_relay"] = "true"
		}
	}
	_, _ = fmt.Fprintf(conn, "QUIT\r\n")
	if strings.Contains(ehlo, "VRFY") {
		svc.Extra["smtp_vrfy"] = "true"
	}
}

// ---------- LDAP ----------

func (e *Engine) ldapProbe(ctx context.Context, svc *model.Service) {
	conn, err := dialProbe(ctx, svc)
	if err != nil {
		return
	}
	defer conn.Close()
	// LDAP Simple Bind Request с пустым DN и паролем (anonymous bind).
	payload := []byte{
		0x30, 0x0c, // SEQUENCE
		0x02, 0x01, 0x01, // messageID = 1
		0x60, 0x07, // BindRequest
		0x02, 0x01, 0x03, // version 3
		0x04, 0x00, // name: пустой
		0x80, 0x00, // simple auth: пустой пароль
	}
	resp := exchange(conn, payload, 3*time.Second)
	// Ответ BindResponse (0x61) с resultCode 0 (success).
	if len(resp) >= 7 && resp[0] == 0x61 && strings.ContainsRune(resp, 0x00) {
		for _, b := range []byte(resp) {
			_ = b
			break
		}
		// resultCode находится в структуре; проверяем код успеха (0x00).
		if bindSuccess(resp) {
			svc.Extra["ldap_anon"] = "true"
		}
		svc.Product = "ldap"
	}
}

// bindSuccess анализирует LDAP BindResponse.
func bindSuccess(resp string) bool {
	b := []byte(resp)
	// Простой поиск: после 0x61 (BindResponse) идёт SEQUENCE с resultCode ENUMERATED 0.
	for i := 0; i < len(b)-2; i++ {
		if b[i] == 0x0a && b[i+1] == 0x01 && b[i+2] == 0x00 {
			return true
		}
	}
	return false
}

// ---------- VNC ----------

func (e *Engine) vncProbe(ctx context.Context, svc *model.Service) {
	conn, err := dialProbe(ctx, svc)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	r := bufio.NewReader(conn)
	banner := readLine(r) // RFB x.y.z
	if !strings.HasPrefix(banner, "RFB ") {
		return
	}
	// Клиент поддерживает версию 3.3.
	_, _ = conn.Write([]byte("RFB 003.003\n"))
	// Типы безопасности (версия 3.3): uint32. 1 = None.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4)
	n, err := r.Read(buf)
	if err != nil || n < 4 {
		return
	}
	secType := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
	if secType == 1 {
		svc.Extra["vnc_noauth"] = "true"
	}
	svc.Product = "vnc"
}

// ---------- HTTP вспомогательное ----------

// httpGet выполняет GET-запрос к службе, возвращает тело и статус.
func (e *Engine) httpGet(ctx context.Context, svc *model.Service, path string) (string, int) {
	url := fmt.Sprintf("http://%s%s", netutil.JoinHostPort(svc.Host, svc.Port), path)
	if tlsPorts[svc.Port] || svc.Name == "https" || svc.Name == "winrms" || svc.Name == "kubernetes" ||
		svc.Name == "kubelet" || svc.Name == "kubelet-ro" || svc.Name == "docker-tls" {
		url = fmt.Sprintf("https://%s%s", netutil.JoinHostPort(svc.Host, svc.Port), path)
	}
	body, status, err := httpDo(ctx, url, svc.Host)
	if err != nil {
		return "", 0
	}
	return body, status
}

// ---------- JSON-диспетчеризация для отчёта ----------

// jsonMarshal — безопасная сериализация (используется в отладке).
func jsonMarshal(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
