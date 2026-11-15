package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
	"github.com/zigorminsk-debug/office-security-check/internal/netutil"
)

// tlsRecord — типы записей TLS.
const (
	recChangeCipherSpec = 0x14
	recAlert            = 0x15
	recHandshake        = 0x16
	recHeartbeat        = 0x18
)

// tlsVersion — коды версий протокола.
const (
	tlsVerSSL30 = 0x0300
	tlsVerTLS10 = 0x0301
	tlsVerTLS11 = 0x0302
	tlsVerTLS12 = 0x0303
	tlsVerTLS13 = 0x0304
)

// weakCipherSuites — слабые и небезопасные наборы шифров для проверки.
var weakCipherSuites = map[uint16]string{
	0x0001: "NULL-MD5",
	0x0002: "NULL-SHA",
	0x0003: "EXPORT-RC4-40-MD5",
	0x0004: "RC4-MD5",
	0x0005: "RC4-SHA",
	0x0006: "EXPORT-RC2-40-MD5",
	0x0008: "EXPORT-DES40-SHA",
	0x0009: "DES-CBC-SHA",
	0x000A: "3DES-EDE-CBC-SHA",
	0x0017: "DH-anon-EXPORT",
	0x0018: "DH-anon-RC4",
	0x0019: "DH-anon-DES",
	0x001A: "DH-anon-3DES",
	0x001B: "DH-anon-AES128",
	0x0034: "DH-anon-AES128-SHA",
	0x003A: "DH-anon-AES256-SHA",
	0x0096: "RSA-SEED-SHA",
	0x00A8: "PSK-RC4",
}

// commonCipherSuites — наборы для проверки поддержки версий TLS.
var commonCipherSuites = []uint16{
	0xC030, 0xC02F, 0xC028, 0xC027, 0xC014, 0xC013, // ECDHE-RSA
	0x009D, 0x009C, 0x003D, 0x003C, 0x0035, 0x002F, 0x000A, // RSA
	0xC02C, 0xC02B, 0xC024, 0xC023, 0xC00A, 0xC009, // ECDHE-ECDSA
	0x00FF, // SCSV
}

// tlsProbe выполняет аудит TLS-сервиса: сертификат, версии, шифры, Heartbleed.
func (e *Engine) tlsProbe(ctx context.Context, svc *model.Service) {
	info := &model.TLSInfo{}

	// 1. Полная проверка сертификата средствами crypto/tls.
	conn, err := tlsProbeHandshake(ctx, svc)
	if err == nil {
		state := conn.ConnectionState()
		info.Version = tlsVersionName(state.Version)
		info.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			info.Subject = cert.Subject.String()
			info.Issuer = cert.Issuer.String()
			info.NotBefore = cert.NotBefore.Format("2006-01-02")
			info.NotAfter = cert.NotAfter.Format("2006-01-02")
			info.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
			info.SelfSigned = cert.Subject.String() == cert.Issuer.String()
			info.SignatureAlgorithm = cert.SignatureAlgorithm.String()
			for _, name := range cert.DNSNames {
				info.SANs = append(info.SANs, name)
			}
			info.PublicKeyBits = publicKeyBits(cert)
			// Проверка соответствия имени хоста.
			info.HostnameMismatch = cert.VerifyHostname(svc.Host) != nil &&
				!info.SelfSigned && len(cert.DNSNames) > 0
		}
		_ = conn.Close()
	} else {
		info.Version = "не определено"
	}

	// 2. Проверка поддержки устаревших версий TLS (raw ClientHello).
	info.SupportsTLS10 = e.probeTLSVersion(ctx, svc, tlsVerTLS10)
	info.SupportsTLS11 = e.probeTLSVersion(ctx, svc, tlsVerTLS11)
	info.SupportsTLS12 = e.probeTLSVersion(ctx, svc, tlsVerTLS12) || info.Version == "TLS 1.2"
	info.SupportsTLS13 = info.Version == "TLS 1.3"

	// 3. Проверка слабых шифров.
	info.WeakCipher = e.probeWeakCiphers(ctx, svc)

	// 4. Проверка уязвимости Heartbleed (CVE-2014-0160).
	info.Heartbleed = e.detectHeartbleed(ctx, svc)

	svc.TLS = info
	if svc.Name == "https" || svc.Name == "http" || svc.Name == "http-alt" || svc.Name == "http-proxy" {
		// HTTP поверх TLS тоже проверяем.
		if svc.HTTP == nil && e.Cfg.DeepHTTP {
			e.httpProbe(ctx, svc)
		}
	}
}

// tlsProbeHandshake выполняет стандартное TLS-рукопожатие.
func tlsProbeHandshake(ctx context.Context, svc *model.Service) (*tls.Conn, error) {
	addr := netutil.JoinHostPort(svc.Host, svc.Port)
	d := &net.Dialer{Timeout: probeTimeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // аудит сертификатов
		ServerName:         svc.Host,
	}
	conn := tls.Client(raw, cfg)
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// publicKeyBits определяет размер открытого ключа сертификата.
func publicKeyBits(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// tlsVersionName возвращает читаемое имя версии TLS.
func tlsVersionName(v uint16) string {
	switch v {
	case tlsVerSSL30:
		return "SSL 3.0"
	case tlsVerTLS10:
		return "TLS 1.0"
	case tlsVerTLS11:
		return "TLS 1.1"
	case tlsVerTLS12:
		return "TLS 1.2"
	case tlsVerTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// ---------- Низкоуровневый разбор TLS-записей ----------

// buildClientHello формирует ClientHello.
func buildClientHello(version uint16, ciphers []uint16, extensions []byte) []byte {
	random := make([]byte, 32)
	_, _ = rand.Read(random)

	var hello []byte
	hello = append(hello, byte(version>>8), byte(version)) // client_version
	hello = append(hello, random...)
	hello = append(hello, 0x00) // session_id length = 0
	// cipher_suites
	cs := make([]byte, 0, len(ciphers)*2+2)
	cs = append(cs, byte(len(ciphers)*2>>8), byte(len(ciphers)*2))
	for _, c := range ciphers {
		cs = append(cs, byte(c>>8), byte(c))
	}
	hello = append(hello, cs...)
	hello = append(hello, 0x01, 0x00) // compression: null
	if len(extensions) > 0 {
		ext := make([]byte, 0, len(extensions)+2)
		ext = append(ext, byte(len(extensions)>>8), byte(len(extensions)))
		ext = append(ext, extensions...)
		hello = append(hello, ext...)
	}

	// Рукопожатие: type 0x01 + длина (3 байта) + тело.
	hs := []byte{0x01, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}
	hs = append(hs, hello...)

	// Запись TLS.
	rec := []byte{recHandshake, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}

// extHeartbeat — расширение heartbeat (тип 0x000f, режим peer_allowed).
var extHeartbeat = []byte{0x00, 0x0f, 0x00, 0x01, 0x01}

// extSupportedVersions формирует расширение supported_versions для ClientHello.
func extSupportedVersions(versions ...uint16) []byte {
	list := []byte{byte(len(versions) * 2)}
	for _, v := range versions {
		list = append(list, byte(v>>8), byte(v))
	}
	body := append([]byte{byte(len(list))}, list...)
	return append([]byte{0x00, 0x2b, byte(len(body) >> 8), byte(len(body))}, body...)
}

// extKeyShareX25519 — расширение key_share с фиктивным ключом x25519.
func extKeyShareX25519() []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	key[31] |= 0x01 // правильная длина
	var body []byte
	body = append(body, 0x00, 0x1d) // группа x25519
	body = append(body, 0x00, 0x20) // длина ключа 32
	body = append(body, key...)     // ключ
	entry := body                   // key_share_entry
	total := append([]byte{0x00, byte(len(entry))}, entry...)
	ext := append([]byte{0x00, 0x33, byte(len(total) >> 8), byte(len(total))}, total...)
	return ext
}

// readTLSRecords читает TLS-записи из соединения.
func readTLSRecords(conn net.Conn, max int) []tlsRecord {
	var out []tlsRecord
	buf := make([]byte, 8192)
	total := 0
	_ = conn.SetReadDeadline(time.Now().Add(3500 * time.Millisecond))
	for total < max {
		n, err := conn.Read(buf)
		if n <= 0 {
			break
		}
		out = append(out, parseTLSRecords(buf[:n])...)
		total += n
		if err != nil {
			break
		}
	}
	return out
}

// tlsRecord — распознанная TLS-запись.
type tlsRecord struct {
	contentType byte
	version     uint16
	payload     []byte
}

// parseTLSRecords разбирает буфер на TLS-записи.
func parseTLSRecords(b []byte) []tlsRecord {
	var out []tlsRecord
	for len(b) >= 5 {
		length := int(b[3])<<8 | int(b[4])
		if len(b) < 5+length {
			break
		}
		out = append(out, tlsRecord{
			contentType: b[0],
			version:     uint16(b[1])<<8 | uint16(b[2]),
			payload:     b[5 : 5+length],
		})
		b = b[5+length:]
	}
	return out
}

// serverHelloInfo разбирает ServerHello.
func serverHelloInfo(recs []tlsRecord) (version uint16, cipher uint16, isHello, isAlert bool, alertDesc byte) {
	for _, r := range recs {
		switch r.contentType {
		case recAlert:
			isAlert = true
			if len(r.payload) >= 2 {
				alertDesc = r.payload[1]
			}
		case recHandshake:
			if len(r.payload) >= 6 && r.payload[0] == 0x02 { // ServerHello
				isHello = true
				version = uint16(r.payload[4])<<8 | uint16(r.payload[5])
				// Ищем cipher suite: 32 байта random после версии.
				off := 6 + 32
				if len(r.payload) > off+3 {
					sidLen := int(r.payload[off])
					off += 1 + sidLen
					if len(r.payload) >= off+2 {
						cipher = uint16(r.payload[off])<<8 | uint16(r.payload[off+1])
					}
				}
				// TLS 1.3: версия в расширении supported_versions (0x002b).
				if version == tlsVerTLS12 {
					if v13 := findSupportedVersions(r.payload); v13 != 0 {
						version = v13
					}
				}
				return
			}
		}
	}
	return
}

// findSupportedVersions ищет расширение supported_versions в ServerHello.
func findSupportedVersions(hs []byte) uint16 {
	for i := 0; i+4 < len(hs); i++ {
		if hs[i] == 0x00 && hs[i+1] == 0x2b {
			extLen := int(hs[i+2])<<8 | int(hs[i+3])
			if extLen >= 2 && i+4+2 <= len(hs) {
				if extLen == 2 {
					return uint16(hs[i+4])<<8 | uint16(hs[i+5])
				}
				// Список версий (ClientHello-подобная структура).
				n := int(hs[i+4])
				if n >= 2 && i+6 <= len(hs) {
					return uint16(hs[i+5])<<8 | uint16(hs[i+6])
				}
			}
		}
	}
	return 0
}

// probeTLSVersion проверяет, поддерживает ли сервер указанную версию TLS.
func (e *Engine) probeTLSVersion(ctx context.Context, svc *model.Service, version uint16) bool {
	ext := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}                             // ec_point_formats
	ext = append(ext, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18) // elliptic_curves
	hello := buildClientHello(version, commonCipherSuites, ext)
	recs, err := e.tlsRoundTrip(ctx, svc, hello)
	if err != nil {
		return false
	}
	sv, _, isHello, isAlert, _ := serverHelloInfo(recs)
	if isHello {
		return true
	}
	_ = sv
	_ = isAlert
	return false
}

// probeWeakCiphers проверяет поддержку слабых наборов шифров.
func (e *Engine) probeWeakCiphers(ctx context.Context, svc *model.Service) string {
	// Проверяем слабые наборы пачкой: если сервер выбирает один из них — он уязвим.
	weak := make([]uint16, 0, len(weakCipherSuites))
	for id := range weakCipherSuites {
		weak = append(weak, id)
	}
	hello := buildClientHello(tlsVerTLS12, weak, nil)
	recs, err := e.tlsRoundTrip(ctx, svc, hello)
	if err != nil {
		return ""
	}
	_, cipher, isHello, _, _ := serverHelloInfo(recs)
	if isHello {
		if name, ok := weakCipherSuites[cipher]; ok {
			return name
		}
		if cipher != 0 {
			return fmt.Sprintf("0x%04x", cipher)
		}
	}
	return ""
}

// tlsRoundTrip отправляет запись TLS и читает ответ.
func (e *Engine) tlsRoundTrip(ctx context.Context, svc *model.Service, payload []byte) ([]tlsRecord, error) {
	conn, err := dialProbe(ctx, svc)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	recs := readTLSRecords(conn, 32*1024)
	if len(recs) == 0 {
		return nil, fmt.Errorf("нет ответа")
	}
	return recs, nil
}

// detectHeartbleed проверяет уязвимость Heartbleed (CVE-2014-0160).
// Методика: ClientHello с расширением heartbeat, затем запрос heartbeat с
// завышенной длиной полезной нагрузки. Уязвимый сервер эхом возвращает память.
func (e *Engine) detectHeartbleed(ctx context.Context, svc *model.Service) bool {
	conn, err := dialProbe(ctx, svc)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	hello := buildClientHello(tlsVerTLS12, commonCipherSuites, extHeartbeat)
	if _, err := conn.Write(hello); err != nil {
		return false
	}
	// Даём серверу обработать приветствие.
	time.Sleep(300 * time.Millisecond)

	// HeartbeatRequest: payload_length = 0x4000, реальная нагрузка 1 байт.
	payload := "A"
	hb := []byte{0x01, 0x40, 0x00}
	hb = append(hb, payload...)
	padding := make([]byte, 16)
	_, _ = rand.Read(padding)
	hb = append(hb, padding...)
	record := []byte{recHeartbeat, 0x03, 0x02, byte(len(hb) >> 8), byte(len(hb))}
	record = append(record, hb...)
	if _, err := conn.Write(record); err != nil {
		return false
	}

	recs := readTLSRecords(conn, 64*1024)
	for _, r := range recs {
		if r.contentType == recHeartbeat && len(r.payload) > 3+1+16 {
			// Ответ heartbeat содержит эхо + утечку памяти.
			if r.payload[0] == 0x02 {
				return true
			}
		}
	}
	return false
}

// tlsVersionLabel — краткое описание версии для отчёта.
func tlsVersionLabel(info *model.TLSInfo) string {
	if info == nil {
		return ""
	}
	var parts []string
	if info.SupportsTLS10 {
		parts = append(parts, "TLS 1.0")
	}
	if info.SupportsTLS11 {
		parts = append(parts, "TLS 1.1")
	}
	if info.SupportsTLS12 {
		parts = append(parts, "TLS 1.2")
	}
	if info.SupportsTLS13 {
		parts = append(parts, "TLS 1.3")
	}
	return strings.Join(parts, ", ")
}
