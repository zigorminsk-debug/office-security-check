package scanner

import (
	"context"
	"encoding/binary"
	"strings"
	"time"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
)

// ---------- RDP: проверка протокола безопасности и обязательной NLA ----------
//
// Диалог: TPKT + X.224 Connection Request с RDP Negotiation Request (тип 0x01).
// Сервер отвечает RDP Negotiation Response (тип 0x02) с выбранным протоколом:
//
//	0x00 — стандартная безопасность RDP (без NLA, опасно)
//	0x01 — TLS (шифрование есть, но NLA не требуется)
//	0x02 — CredSSP / NLA (безопасно)
//	0x08 — Hybrid (CredSSP + ранняя аутентификация, безопасно)

// rdpProbe определяет, требуется ли сетевая аутентификация (NLA/CredSSP) для RDP.
func (e *Engine) rdpProbe(ctx context.Context, svc *model.Service) {
	req := buildRDPNegotiateRequest()
	conn, err := dialProbe(ctx, svc)
	if err != nil {
		return
	}
	defer conn.Close()
	resp := exchange(conn, req, 3*time.Second)
	if resp == "" {
		return
	}
	selected, hasNeg := parseRDPResponse([]byte(resp))
	if !hasNeg {
		// Старый RDP без блока согласования — NLA отсутствует.
		svc.Extra["rdp_nla"] = "false"
		svc.Extra["rdp_protocol"] = "RDP (standard security)"
		return
	}
	nla := selected&0x02 != 0 || selected&0x08 != 0
	if nla {
		svc.Extra["rdp_nla"] = "true"
	} else {
		svc.Extra["rdp_nla"] = "false"
	}
	svc.Extra["rdp_protocol"] = rdpProtoName(selected)
}

// buildRDPNegotiateRequest формирует TPKT/X.224 Connection Request с cookie и
// RDP Negotiation Request (запрашиваем все протоколы безопасности).
func buildRDPNegotiateRequest() []byte {
	cookie := []byte("Cookie: mstshash=audit\r\n")
	// RDP Negotiation Request: тип 0x01, флаги 0x00, длина 0x0008, requestedProtocols.
	neg := []byte{0x01, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00}

	// X.224 CR TPDU: LI, код 0xE0, dst-ref, src-ref, class, переменная часть.
	tpdu := make([]byte, 0, 64)
	tpdu = append(tpdu, 0x00) // Length indicator (заполним ниже)
	tpdu = append(tpdu, 0xe0) // CR
	tpdu = append(tpdu, 0x00, 0x00)
	tpdu = append(tpdu, 0x12, 0x34) // src-ref
	tpdu = append(tpdu, 0x00)       // class
	tpdu = append(tpdu, cookie...)
	tpdu = append(tpdu, neg...)
	tpdu[0] = byte(len(tpdu) - 1) // LI = число байт после LI

	tpkt := make([]byte, 0, len(tpdu)+4)
	tpkt = append(tpkt, 0x03, 0x00)
	total := len(tpdu) + 4
	tpkt = append(tpkt, byte(total>>8), byte(total))
	tpkt = append(tpkt, tpdu...)
	return tpkt
}

// parseRDPResponse ищет блок RDP Negotiation Response (тип 0x02) в ответе сервера.
func parseRDPResponse(resp []byte) (selected uint32, found bool) {
	for i := 0; i+8 <= len(resp); i++ {
		if resp[i] == 0x02 && resp[i+2] == 0x08 && resp[i+3] == 0x00 {
			selected = binary.LittleEndian.Uint32(resp[i+4 : i+8])
			return selected, true
		}
	}
	return 0, false
}

// rdpProtoName возвращает название выбранного протокола безопасности RDP.
func rdpProtoName(selected uint32) string {
	var names []string
	if selected&0x01 != 0 {
		names = append(names, "TLS")
	}
	if selected&0x02 != 0 {
		names = append(names, "CredSSP/NLA")
	}
	if selected&0x08 != 0 {
		names = append(names, "Hybrid")
	}
	if selected&0x10 != 0 {
		names = append(names, "HybridEx")
	}
	if len(names) == 0 {
		return "RDP (standard security)"
	}
	return strings.Join(names, "+")
}
