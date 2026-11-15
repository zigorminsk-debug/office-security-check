package scanner

import (
	"context"
	"encoding/binary"
	"time"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
)

// ---------- SMB: определение диалектов, подписывания, анонимного доступа и MS17-010 ----------
//
// Проверки (все — только обнаружение, без эксплуатации):
//  1. SMB-NEGOTIATE (мультипротокольный): выбранный диалект SMB1/SMB2/SMB3.
//  2. SMB-NEGOTIATE (только NT LM 0.12): поддерживается ли SMBv1.
//  3. SecurityMode: требуется ли подписывание пакетов (SMB signing).
//  4. Анонимная сессия + TREE CONNECT к IPC$: доступна ли общая папка без пароля.
//  5. TRANS_PEEK_NMPIPE: проверка уязвимости MS17-010 (EternalBlue/WannaCry).

// smbCommand — коды команд SMB1.
const (
	smbCmdNegotiate       = 0x72
	smbCmdSessionSetup    = 0x73
	smbCmdTreeConnect     = 0x75
	smbCmdTransaction     = 0x25
	smbStatusSuccess      = 0x00000000
	smbStatusInsuffRes    = 0xC000009A
	smbStatusNotSupported = 0xC00000BB
)

// smbProbe выполняет проверки SMB-сервера.
func (e *Engine) smbProbe(ctx context.Context, svc *model.Service) {
	// 1. Мультипротокольный NEGOTIATE.
	resp, err := e.smbExchange(ctx, svc, buildSMB1Negotiate([]string{
		"PC NETWORK PROGRAM 1.0",
		"LANMAN1.0",
		"Windows for Workgroups 3.1a",
		"LM1.2X002",
		"LANMAN2.1",
		"NT LM 0.12",
		"SMB 2.002",
		"SMB 2.???",
	}))
	if err != nil || len(resp) < 36 {
		return
	}

	dialects := []string{
		"PC NETWORK PROGRAM 1.0", "LANMAN1.0", "Windows for Workgroups 3.1a",
		"LM1.2X002", "LANMAN2.1", "NT LM 0.12", "SMB 2.002", "SMB 2.???",
	}
	smb1Selected := false
	signingRequired := false

	switch {
	case resp[0] == 0xfe && resp[1] == 'S' && resp[2] == 'M' && resp[3] == 'B':
		// Ответ SMB2+: диалект и режим безопасности.
		svc.Extra["smb_dialect"] = smb2DialectName(resp)
		signingRequired = smb2SigningRequired(resp)
		svc.Product = "microsoft-ds"
	case resp[0] == 0xff && resp[1] == 'S' && resp[2] == 'M' && resp[3] == 'B':
		// Ответ SMB1.
		smb1Selected = true
		idx := int(binary.LittleEndian.Uint16(resp[33:35]))
		if idx < len(dialects) {
			svc.Extra["smb_dialect"] = dialects[idx]
		} else {
			svc.Extra["smb_dialect"] = "NT LM 0.12"
		}
		signingRequired = smb1SigningRequired(resp)
		svc.Product = "microsoft-ds"
	default:
		return
	}

	if signingRequired {
		svc.Extra["smb_signing_required"] = "true"
	} else {
		svc.Extra["smb_signing_required"] = "false"
	}

	// 2. Поддерживается ли SMBv1 (отдельный NEGOTIATE только с NT LM 0.12).
	smb1Resp, err := e.smbExchange(ctx, svc, buildSMB1Negotiate([]string{"NT LM 0.12"}))
	if err == nil && len(smb1Resp) >= 36 && smb1Resp[0] == 0xff {
		status := binary.LittleEndian.Uint32(smb1Resp[5:9])
		if status == smbStatusSuccess {
			svc.Extra["smb_v1"] = "true"
			smb1Selected = true
		} else {
			svc.Extra["smb_v1"] = "false"
		}
	} else if smb1Selected {
		svc.Extra["smb_v1"] = "true"
	} else {
		svc.Extra["smb_v1"] = "false"
	}

	// 3. Анонимный доступ и проверка MS17-010 (только при SMBv1).
	if svc.Extra["smb_v1"] == "true" {
		e.smbSessionChecks(ctx, svc)
	}
}

// smbSessionChecks выполняет анонимный вход, подключение к IPC$ и проверку MS17-010.
func (e *Engine) smbSessionChecks(ctx context.Context, svc *model.Service) {
	uid, tid, ok := e.smbAnonSession(ctx, svc)
	if ok {
		svc.Extra["smb_anonymous"] = "true"
	} else {
		svc.Extra["smb_anonymous"] = "false"
	}

	// Проверка MS17-010: TRANS_PEEK_NMPIPE с FID=0.
	status := e.smbPeekNamedPipe(ctx, svc, uid, tid)
	if status == 0 {
		svc.Extra["ms17_010"] = "unknown"
		return
	}
	switch status {
	case smbStatusInsuffRes:
		svc.Extra["ms17_010"] = "vulnerable"
	case smbStatusSuccess, 0xC0000008: // STATUS_INVALID_HANDLE — признак исправленной системы
		svc.Extra["ms17_010"] = "patched"
	default:
		svc.Extra["ms17_010"] = "patched"
	}
}

// smbExchange отправляет SMB-пакет и возвращает ответ без NetBIOS-заголовка.
func (e *Engine) smbExchange(ctx context.Context, svc *model.Service, packet []byte) ([]byte, error) {
	conn, err := dialProbe(ctx, svc)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return nil, err
	}
	raw := buf[:n]
	// Пропускаем NetBIOS-заголовок (4 байта).
	if raw[0] == 0x00 && n > 4 {
		out := make([]byte, n-4)
		copy(out, raw[4:])
		return out, nil
	}
	out := make([]byte, n)
	copy(out, raw)
	return out, nil
}

// nbWrap добавляет NetBIOS session header к SMB-пакету.
func nbWrap(smb []byte) []byte {
	out := make([]byte, 0, len(smb)+4)
	out = append(out, 0x00, byte(len(smb)>>16), byte(len(smb)>>8), byte(len(smb)))
	out = append(out, smb...)
	return out
}

// smbHeader формирует SMB1-заголовок (32 байта).
func smbHeader(cmd byte, status uint32, tid, uid, mid uint16) []byte {
	h := make([]byte, 32)
	h[0], h[1], h[2], h[3] = 0xff, 'S', 'M', 'B'
	h[4] = cmd
	binary.LittleEndian.PutUint32(h[5:9], status)
	h[9] = 0x18               // FLAGS: case insensitive + canonical paths
	h[10], h[11] = 0x01, 0xc0 // FLAGS2: unicode | NT status | long names
	binary.LittleEndian.PutUint16(h[24:26], tid)
	binary.LittleEndian.PutUint16(h[26:28], 0x4b2f) // PID
	binary.LittleEndian.PutUint16(h[28:30], uid)
	binary.LittleEndian.PutUint16(h[30:32], mid)
	return h
}

// buildSMB1Negotiate формирует SMB_COM_NEGOTIATE с указанными диалектами.
func buildSMB1Negotiate(dialects []string) []byte {
	var bc []byte
	for _, d := range dialects {
		bc = append(bc, 0x02) // buffer format
		bc = append(bc, d...)
		bc = append(bc, 0x00)
	}
	pkt := smbHeader(smbCmdNegotiate, 0, 0, 0, 1)
	pkt = append(pkt, 0x00) // WordCount
	pkt = append(pkt, byte(len(bc)), byte(len(bc)>>8))
	pkt = append(pkt, bc...)
	return nbWrap(pkt)
}

// buildSessionSetupAnon формирует SESSION_SETUP_ANDX с пустыми учётными данными.
func buildSessionSetupAnon(tid, uid, mid uint16) []byte {
	pkt := smbHeader(smbCmdSessionSetup, 0, tid, uid, mid)
	pkt = append(pkt, 13)                     // WordCount
	pkt = append(pkt, 0xff, 0x00)             // AndXCommand, reserved
	pkt = append(pkt, 0x00, 0x00)             // AndXOffset
	pkt = append(pkt, 0x04, 0x11)             // MaxBuffer
	pkt = append(pkt, 0x02, 0x00)             // MaxMpxCount
	pkt = append(pkt, 0x01, 0x00)             // VCNumber
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00) // SessionKey
	pkt = append(pkt, 0x01, 0x00)             // AnsiPasswordLength (1 = пустой пароль)
	pkt = append(pkt, 0x00, 0x00)             // UnicodePasswordLength
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00) // Reserved
	pkt = append(pkt, 0xd4, 0x00, 0x00, 0x00) // Capabilities: UNICODE|NT_SMBS|STATUS32|LOCK_AND_READ|NT_FIND

	var body []byte
	body = append(body, 0x00)                                               // пустой ANSI-пароль
	body = append(body, 0x00, 0x00)                                         // пустое имя пользователя (unicode)
	body = append(body, 0x00, 0x00)                                         // пустой домен (unicode)
	body = append(body, 'U', 0, 'n', 0, 'i', 0, 'x', 0, 0x00, 0x00)         // NativeOS
	body = append(body, 'S', 0, 'a', 0, 'm', 0, 'b', 0, 'a', 0, 0x00, 0x00) // NativeLM

	pkt = append(pkt, byte(len(body)), byte(len(body)>>8))
	pkt = append(pkt, body...)
	return nbWrap(pkt)
}

// buildTreeConnectIPC формирует TREE_CONNECT_ANDX к \\host\IPC$.
func buildTreeConnectIPC(host string, tid, uid, mid uint16) []byte {
	pkt := smbHeader(smbCmdTreeConnect, 0, tid, uid, mid)
	pkt = append(pkt, 4)          // WordCount
	pkt = append(pkt, 0xff, 0x00) // AndX
	pkt = append(pkt, 0x00, 0x00) // AndXOffset
	pkt = append(pkt, 0x00, 0x00) // Flags
	pkt = append(pkt, 0x01, 0x00) // PasswordLength

	var body []byte
	body = append(body, 0x00) // пароль
	// Путь: \\host\IPC$ (unicode).
	path := "\\\\" + host + "\\IPC$"
	for _, r := range path {
		body = append(body, byte(r), 0x00)
	}
	body = append(body, 0x00, 0x00)                    // терминатор
	body = append(body, '?', '?', '?', '?', '?', 0x00) // Service "?????"

	pkt = append(pkt, byte(len(body)), byte(len(body)>>8))
	pkt = append(pkt, body...)
	return nbWrap(pkt)
}

// buildTransPeekNMPipe формирует SMB_COM_TRANSACTION (TRANS_PEEK_NMPIPE, FID=0).
func buildTransPeekNMPipe(tid, uid, mid uint16) []byte {
	pkt := smbHeader(smbCmdTransaction, 0, tid, uid, mid)
	pkt = append(pkt, 16)                     // WordCount
	pkt = append(pkt, 0x00, 0x00)             // TotalParamCount
	pkt = append(pkt, 0x00, 0x00)             // TotalDataCount
	pkt = append(pkt, 0xff, 0xff)             // MaxParamCount
	pkt = append(pkt, 0xff, 0xff)             // MaxDataCount
	pkt = append(pkt, 0x00)                   // MaxSetupCount
	pkt = append(pkt, 0x00)                   // Reserved
	pkt = append(pkt, 0x00, 0x00)             // Flags
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00) // Timeout
	pkt = append(pkt, 0x00, 0x00)             // Reserved2
	pkt = append(pkt, 0x00, 0x00)             // ParamCount
	pkt = append(pkt, 0x4a, 0x00)             // ParamOffset
	pkt = append(pkt, 0x00, 0x00)             // DataCount
	pkt = append(pkt, 0x4a, 0x00)             // DataOffset
	pkt = append(pkt, 0x02)                   // SetupCount
	pkt = append(pkt, 0x00)                   // Reserved3
	pkt = append(pkt, 0x23, 0x00)             // Setup[0]: TRANS_PEEK_NMPIPE
	pkt = append(pkt, 0x00, 0x00)             // Setup[1]: FID = 0

	name := []byte{'\\', 'P', 'I', 'P', 'E', '\\', 0x00}
	pkt = append(pkt, byte(len(name)), byte(len(name)>>8))
	pkt = append(pkt, name...)
	return nbWrap(pkt)
}

// smbAnonSession выполняет анонимный вход и подключение к IPC$.
// Возвращает UID, TID и успех операции.
func (e *Engine) smbAnonSession(ctx context.Context, svc *model.Service) (uid, tid uint16, ok bool) {
	// NEGOTIATE для получения параметров сессии.
	negResp, err := e.smbExchange(ctx, svc, buildSMB1Negotiate([]string{"NT LM 0.12"}))
	if err != nil || len(negResp) < 36 {
		return 0, 0, false
	}

	// SESSION_SETUP_ANDX.
	ssResp, err := e.smbExchange(ctx, svc, buildSessionSetupAnon(0, 0, 2))
	if err != nil || len(ssResp) < 36 {
		return 0, 0, false
	}
	if binary.LittleEndian.Uint32(ssResp[5:9]) != smbStatusSuccess {
		return 0, 0, false
	}
	uid = binary.LittleEndian.Uint16(ssResp[28:30])

	// TREE_CONNECT_ANDX к IPC$.
	tcResp, err := e.smbExchange(ctx, svc, buildTreeConnectIPC(svc.Host, 0, uid, 3))
	if err != nil || len(tcResp) < 36 {
		return uid, 0, false
	}
	if binary.LittleEndian.Uint32(tcResp[5:9]) == smbStatusSuccess {
		tid = binary.LittleEndian.Uint16(tcResp[24:26])
		return uid, tid, true
	}
	return uid, 0, false
}

// smbPeekNamedPipe выполняет TRANS_PEEK_NMPIPE и возвращает NT-статус ответа.
func (e *Engine) smbPeekNamedPipe(ctx context.Context, svc *model.Service, uid, tid uint16) uint32 {
	resp, err := e.smbExchange(ctx, svc, buildTransPeekNMPipe(tid, uid, 4))
	if err != nil || len(resp) < 13 {
		return 0
	}
	return binary.LittleEndian.Uint32(resp[5:9])
}

// smb1SigningRequired проверяет флаг Security Signatures Required в ответе NEGOTIATE.
func smb1SigningRequired(resp []byte) bool {
	if len(resp) < 36 {
		return false
	}
	securityMode := resp[35]
	return securityMode&0x04 != 0
}

// smb2SigningRequired проверяет SecurityMode в ответе SMB2 NEGOTIATE.
func smb2SigningRequired(resp []byte) bool {
	if len(resp) < 70 {
		return false
	}
	mode := binary.LittleEndian.Uint16(resp[66:68])
	return mode&0x0002 != 0
}

// smb2DialectName возвращает имя выбранного диалекта SMB2/3.
func smb2DialectName(resp []byte) string {
	if len(resp) < 70 {
		return "SMB2+"
	}
	d := binary.LittleEndian.Uint16(resp[68:70])
	switch d {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	default:
		return "SMB2+"
	}
}
