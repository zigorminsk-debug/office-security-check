package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
	"github.com/zigorminsk-debug/office-security-check/internal/netutil"
)

// probeUDP выполняет UDP-проверки ключевых служб (глубокий профиль).
func (e *Engine) probeUDP(ctx context.Context, hosts []model.Host) {
	total := len(hosts) * len(udpProbePorts)
	if total == 0 {
		return
	}
	done := 0
	for hi := range hosts {
		for _, port := range udpProbePorts {
			if ctx.Err() != nil {
				return
			}
			svc := model.Service{
				Host: hosts[hi].IP, Port: port, Protocol: "udp", State: "open|filtered",
				Name: serviceByPort(port),
			}
			if svc.Name == "" {
				svc.Name = "udp"
			}
			svc.Extra = map[string]string{}
			switch port {
			case 161:
				e.snmpProbe(ctx, &svc)
			case 53:
				e.dnsProbe(ctx, &svc)
			case 69:
				e.tftpProbe(ctx, &svc)
			case 123:
				e.ntpProbe(ctx, &svc)
			}
			// Фиксируем службу, только если она ответила.
			if svc.Banner != "" || svc.Product != "" || len(svc.Extra) > 0 {
				hosts[hi].Services = append(hosts[hi].Services, svc)
			}
			done++
			e.report(Progress{Phase: "udp", Current: done, Total: total,
				Message: fmt.Sprintf("UDP-проверка %s:%d", hosts[hi].IP, port)})
		}
	}
}

// udpExchange отправляет UDP-датаграмму и ждёт ответ.
func udpExchange(ctx context.Context, host string, port int, payload []byte) (string, error) {
	addr := netutil.JoinHostPort(host, port)
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return "", err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// ---------- SNMP ----------

// snmpProbe отправляет SNMPv1 GET с community «public».
func (e *Engine) snmpProbe(ctx context.Context, svc *model.Service) {
	pdu := buildSNMPGet("public", []int{1, 3, 6, 1, 2, 1, 1, 1, 0})
	resp, err := udpExchange(ctx, svc.Host, svc.Port, pdu)
	if err != nil || len(resp) < 10 {
		return
	}
	b := []byte(resp)
	if b[0] != 0x30 {
		return
	}
	svc.Banner = "SNMPv1/v2c откликнулся"
	svc.Product = "snmp"
	// GetResponse-PDU (0xa2) означает, что community «public» принята.
	for _, c := range b {
		if c == 0xa2 {
			svc.Extra["snmp_public"] = "true"
			return
		}
	}
	// Ответ с ошибкой community — служба жива, но строка не подошла.
	svc.Extra["snmp_alive"] = "true"
}

// buildSNMPGet формирует SNMPv1 GET-запрос (BER).
func buildSNMPGet(community string, oid []int) []byte {
	var oidEnc []byte
	oidEnc = append(oidEnc, byte(oid[0]*40+oid[1]))
	for _, v := range oid[2:] {
		if v < 128 {
			oidEnc = append(oidEnc, byte(v))
		} else {
			oidEnc = append(oidEnc, byte(v>>7)|0x80, byte(v&0x7f))
		}
	}
	varbind := []byte{0x30, byte(len(oidEnc) + 4), 0x06, byte(len(oidEnc))}
	varbind = append(varbind, oidEnc...)
	varbind = append(varbind, 0x05, 0x00) // NULL

	vbl := []byte{0x30, byte(len(varbind))}
	vbl = append(vbl, varbind...)

	pdu := []byte{0xa0, byte(len(vbl) + 8)}
	pdu = append(pdu,
		0x02, 0x01, 0x01, // request-id
		0x02, 0x01, 0x00, // error-status
		0x02, 0x01, 0x00, // error-index
	)
	pdu = append(pdu, vbl...)

	msg := []byte{0x02, 0x01, 0x00} // version: SNMPv1
	msg = append(msg, 0x04, byte(len(community)))
	msg = append(msg, community...)
	msg = append(msg, pdu...)

	out := []byte{0x30, byte(len(msg))}
	out = append(out, msg...)
	return out
}

// ---------- DNS ----------

// dnsProbe проверяет, является ли DNS-сервер открытым рекурсивным резолвером.
func (e *Engine) dnsProbe(ctx context.Context, svc *model.Service) {
	query := buildDNSQuery("example.com")
	resp, err := udpExchange(ctx, svc.Host, svc.Port, query)
	if err != nil || len(resp) < 12 {
		return
	}
	b := []byte(resp)
	svc.Banner = "DNS-сервер отвечает"
	svc.Product = "dns"
	// RA (recursion available) в флагах ответа — признак открытого резолвера.
	flags := uint16(b[2])<<8 | uint16(b[3])
	answers := uint16(b[6])<<8 | uint16(b[7])
	if flags&0x0080 != 0 && answers > 0 {
		svc.Extra["dns_open_resolver"] = "true"
	}
}

// buildDNSQuery формирует DNS-запрос A-записи с флагом RD.
func buildDNSQuery(name string) []byte {
	q := []byte{0x12, 0x34, // transaction id
		0x01, 0x00, // flags: RD
		0x00, 0x01, // questions
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	for _, part := range strings.Split(name, ".") {
		q = append(q, byte(len(part)))
		q = append(q, part...)
	}
	q = append(q, 0x00, 0x00, 0x01, 0x00, 0x01) // type A, class IN
	return q
}

// ---------- TFTP ----------

// tftpProbe проверяет доступность TFTP (RRQ на несуществующий файл).
func (e *Engine) tftpProbe(ctx context.Context, svc *model.Service) {
	req := []byte{0x00, 0x01} // RRQ
	req = append(req, "audit-probe"...)
	req = append(req, 0x00)
	req = append(req, "octet"...)
	req = append(req, 0x00)
	resp, err := udpExchange(ctx, svc.Host, svc.Port, req)
	if err != nil || len(resp) < 4 {
		return
	}
	opcode := uint16(resp[0])<<8 | uint16(resp[1])
	if opcode == 5 || opcode == 3 || opcode == 6 {
		// ERROR (файл не найден), DATA или OACK — сервер работает.
		svc.Banner = "TFTP-сервер отвечает"
		svc.Product = "tftp"
	}
}

// ---------- NTP ----------

// ntpProbe запрашивает версию NTP (monlist не используется — слишком опасен).
func (e *Engine) ntpProbe(ctx context.Context, svc *model.Service) {
	req := make([]byte, 48)
	req[0] = 0x1b // LI=0, VN=3, Mode=3 (client)
	resp, err := udpExchange(ctx, svc.Host, svc.Port, req)
	if err != nil || len(resp) < 1 {
		return
	}
	version := (resp[0] >> 3) & 0x07
	svc.Banner = fmt.Sprintf("NTP v%d", version)
	svc.Product = "ntp"
}
