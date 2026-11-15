// Package hostcheck выполняет аудит защищённости локального Windows-хоста:
// антивирус, брандмауэр, RDP, SMBv1, UAC, BitLocker и другие критические параметры.
package hostcheck

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
)

// evalFunc преобразует вывод PowerShell-скрипта в результат проверки.
type evalFunc func(out string) (model.CheckStatus, string)

// checkDef — определение проверки локального хоста.
type checkDef struct {
	id             string
	title          string
	category       model.Category
	severity       model.Severity
	description    string
	recommendation string
	script         string
	eval           evalFunc
}

// evalEquals сравнивает вывод с ожидаемым значением.
func evalEquals(want string) evalFunc {
	return func(out string) (model.CheckStatus, string) {
		v := strings.TrimSpace(out)
		if v == "" {
			return model.CheckError, "нет данных"
		}
		if strings.EqualFold(v, want) {
			return model.CheckPassed, v
		}
		return model.CheckFailed, v
	}
}

// evalEqualsFailIf сравнивает вывод со значением, при котором проверка проваливается.
func evalEqualsFailIf(bad string) evalFunc {
	return func(out string) (model.CheckStatus, string) {
		v := strings.TrimSpace(out)
		if v == "" {
			return model.CheckError, "нет данных"
		}
		if strings.EqualFold(v, bad) {
			return model.CheckFailed, v
		}
		return model.CheckPassed, v
	}
}

// evalMaxDays проверяет, что число дней не превышает предел.
func evalMaxDays(max int) evalFunc {
	return func(out string) (model.CheckStatus, string) {
		v := strings.TrimSpace(out)
		n, err := strconv.Atoi(v)
		if err != nil {
			return model.CheckError, v
		}
		if n > max {
			return model.CheckFailed, fmt.Sprintf("%d дн. (норма ≤ %d)", n, max)
		}
		return model.CheckPassed, fmt.Sprintf("%d дн.", n)
	}
}

// evalContainsFailIf проваливает проверку, если вывод содержит подстроку.
func evalContainsFailIf(bad string) evalFunc {
	return func(out string) (model.CheckStatus, string) {
		v := strings.TrimSpace(out)
		if v == "" {
			return model.CheckError, "нет данных"
		}
		if strings.Contains(strings.ToLower(v), strings.ToLower(bad)) {
			return model.CheckFailed, v
		}
		return model.CheckPassed, v
	}
}

// checks — набор проверок защищённости Windows-хоста.
var checks = []checkDef{
	{
		id: "defender-realtime", title: "Защита в реальном времени Windows Defender",
		category: model.CatMalware, severity: model.SevCritical,
		description:    "Антивирус должен постоянно проверять файлы и блокировать вредоносный код. Без защиты в реальном времени вирусы и шифровальщики проникают на хост беспрепятственно.",
		recommendation: "Включите защиту в реальном времени: Центр безопасности Защитника Windows → Защита от вирусов и угроз → Параметры защиты в реальном времени.",
		script:         `(Get-MpComputerStatus).RealTimeProtectionEnabled`,
		eval:           evalEquals("True"),
	},
	{
		id: "defender-signature", title: "Актуальность сигнатур Windows Defender",
		category: model.CatMalware, severity: model.SevHigh,
		description:    "Устаревшие сигнатуры антивируса не обнаруживают новые вирусы и шифровальщики.",
		recommendation: "Обновите сигнатуры: Центр безопасности Защитника → Обновление защиты → Проверить наличие обновлений.",
		script:         `$s=(Get-MpComputerStatus).AntivirusSignatureLastUpdated; if($s){[int]((Get-Date)-$s).TotalDays}else{-1}`,
		eval:           evalMaxDays(7),
	},
	{
		id: "defender-mode", title: "Антивирус работает (не в пассивном режиме)",
		category: model.CatMalware, severity: model.SevHigh,
		description:    "Если Windows Defender работает в пассивном режиме или остановлен, защита от вирусов отсутствует.",
		recommendation: "Удалите конфликтующий антивирус или включите полноценную работу Защитника Windows.",
		script:         `(Get-MpComputerStatus).AMRunningMode`,
		eval:           evalContainsFailIf("not running"),
	},
	{
		id: "firewall-all", title: "Брандмауэр Windows включён во всех профилях",
		category: model.CatUnauthorized, severity: model.SevHigh,
		description:    "Выключенный брандмауэр открывает хост для сканирования и атак из сети — главный путь проникновения шифровальщиков.",
		recommendation: "Включите брандмауэр Windows для профилей «Домен», «Частный» и «Общедоступный» (панель управления или Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled True).",
		script:         `$p=Get-NetFirewallProfile; if(($p|?{$_.Enabled -ne 'True'}) -eq $null){'True'}else{'False'}`,
		eval:           evalEquals("True"),
	},
	{
		id: "rdp-disabled", title: "Удалённый рабочий стол (RDP) отключён",
		category: model.CatRansomware, severity: model.SevHigh,
		description:    "RDP — главная точка входа для шифровальщиков (Dharma, LockBit, Conti). Если удалённый доступ не нужен, отключите его.",
		recommendation: "Отключите RDP: Параметры → Удалённый рабочий стол → Выкл. (реестр: fDenyTSConnections = 1).",
		script:         `(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections`,
		eval:           evalEquals("1"),
	},
	{
		id: "rdp-nla", title: "RDP требует сетевую аутентификацию (NLA)",
		category: model.CatRansomware, severity: model.SevCritical,
		description:    "Без NLA злоумышленник взаимодействует с экраном входа до аутентификации — это открывает путь к перебору паролей и атакам BlueKeep.",
		recommendation: "Включите NLA: «Требовать сетевую аутентификацию пользователей для подключений к удалённому рабочему столу» (UserAuthentication = 1).",
		script:         `(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication`,
		eval:           evalEquals("1"),
	},
	{
		id: "smb-v1-disabled", title: "Протокол SMBv1 отключён",
		category: model.CatRansomware, severity: model.SevCritical,
		description:    "SMBv1 — протокол, через который распространяются шифровальщики WannaCry и NotPetya (уязвимость EternalBlue/MS17-010).",
		recommendation: "Отключите SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force (или удалите компонент FS-SMB1).",
		script:         `(Get-SmbServerConfiguration).EnableSMB1Protocol`,
		eval:           evalEquals("False"),
	},
	{
		id: "smb-signing-server", title: "Сервер SMB требует подписывание пакетов",
		category: model.CatUnauthorized, severity: model.SevHigh,
		description:    "Без обязательного подписывания SMB-трафик уязвим к relay-атакам и подмене данных аутентификации.",
		recommendation: "Включите политику «Microsoft network server: Digitally sign communications (always)» (RequireSecuritySignature = 1).",
		script:         `(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction SilentlyContinue).RequireSecuritySignature`,
		eval:           evalEquals("1"),
	},
	{
		id: "uac-enabled", title: "Контроль учётных записей (UAC) включён",
		category: model.CatMalware, severity: model.SevHigh,
		description:    "UAC препятствует установке вредоносного ПО с правами администратора без явного подтверждения.",
		recommendation: "Включите UAC (EnableLUA = 1) и перезагрузите компьютер.",
		script:         `(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA`,
		eval:           evalEquals("1"),
	},
	{
		id: "uac-prompt", title: "UAC запрашивает подтверждение администратора",
		category: model.CatMalware, severity: model.SevMedium,
		description:    "Если UAC не запрашивает пароль/согласие (ConsentPromptBehaviorAdmin = 0), любой процесс получает права администратора.",
		recommendation: "Настройте UAC на «Запрашивать пароль на защищённом рабочем столе» (ConsentPromptBehaviorAdmin = 2).",
		script:         `(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').ConsentPromptBehaviorAdmin`,
		eval:           evalEqualsFailIf("0"),
	},
	{
		id: "bitlocker", title: "Шифрование BitLocker включено на системном диске",
		category: model.CatRansomware, severity: model.SevMedium,
		description:    "BitLocker защищает данные при краже оборудования и делает невозможным офлайн-модификацию системы.",
		recommendation: "Включите BitLocker на системном диске: Параметры → Система → Хранилище → BitLocker.",
		script:         `$v=Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue; if($v){$v.ProtectionStatus}else{'NotFound'}`,
		eval:           evalEqualsFailIf("Off"),
	},
	{
		id: "llmnr-disabled", title: "LLMNR отключён (защита от отравления DNS)",
		category: model.CatUnauthorized, severity: model.SevMedium,
		description:    "LLMNR и NBT-NS позволяют злоумышленнику перехватывать учётные данные через отравление локальных запросов (Responder, NTLM relay).",
		recommendation: "Отключите LLMNR групповой политикой: «Turn off Multicast Name Resolution» (EnableMulticast = 0).",
		script:         `(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast`,
		eval:           evalEquals("0"),
	},
	{
		id: "netbios-disabled", title: "NetBIOS через TCP/IP отключён",
		category: model.CatUnauthorized, severity: model.SevMedium,
		description:    "Протокол NetBIOS устарел и используется для отравления и перехвата учётных данных в локальной сети.",
		recommendation: "Отключите NetBIOS в свойствах TCP/IP адаптера (TcpipNetbiosOptions = 2) или групповой политикой.",
		script:         `$v=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*' -ErrorAction SilentlyContinue; $off=($v|?{$_.TcpipNetbiosOptions -eq 2}).Count; $all=($v|?{$null -ne $_.TcpipNetbiosOptions}).Count; if($all -gt 0 -and $off -eq $all){'2'}else{'0'}`,
		eval:           evalEquals("2"),
	},
	{
		id: "wdigest-disabled", title: "Аутентификация WDigest отключена",
		category: model.CatUnauthorized, severity: model.SevHigh,
		description:    "WDigest хранит пароли в памяти в открытом виде — их крадут программы-сборщики (Mimikatz), что ведёт к полной компрометации сети.",
		recommendation: "Установите UseLogonCredential = 0 в HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest.",
		script:         `(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue).UseLogonCredential`,
		eval:           evalEqualsFailIf("1"),
	},
	{
		id: "guest-disabled", title: "Гостевая учётная запись отключена",
		category: model.CatUnauthorized, severity: model.SevHigh,
		description:    "Гостевой доступ позволяет злоумышленнику получить доступ к общим ресурсам без пароля.",
		recommendation: "Отключите гостевую учётную запись: lusrmgr.msc → Учётные записи → Guest → Отключить.",
		script:         `$g=Get-LocalUser -Name Guest -ErrorAction SilentlyContinue; if($g){$g.Enabled}else{'NotFound'}`,
		eval:           evalEqualsFailIf("True"),
	},
	{
		id: "remote-registry", title: "Служба «Удалённый реестр» остановлена",
		category: model.CatUnauthorized, severity: model.SevMedium,
		description:    "Удалённый реестр позволяет злоумышленнику читать и изменять настройки системы по сети.",
		recommendation: "Остановите и отключите службу RemoteRegistry: Set-Service RemoteRegistry -StartupType Disabled.",
		script:         `$s=Get-Service RemoteRegistry -ErrorAction SilentlyContinue; if($s){$s.Status}else{'NotFound'}`,
		eval:           evalEqualsFailIf("Running"),
	},
	{
		id: "telnet-service", title: "Служба Telnet отключена",
		category: model.CatUnauthorized, severity: model.SevHigh,
		description:    "Telnet передаёт пароли в открытом виде и даёт командную строку злоумышленнику.",
		recommendation: "Удалите/отключите службу TlntSvr: Set-Service TlntSvr -StartupType Disabled.",
		script:         `$s=Get-Service TlntSvr -ErrorAction SilentlyContinue; if($s){$s.Status}else{'NotFound'}`,
		eval:           evalEqualsFailIf("Running"),
	},
	{
		id: "ps-v2-disabled", title: "Windows PowerShell 2.0 удалён",
		category: model.CatMalware, severity: model.SevMedium,
		description:    "PowerShell 2.0 не имеет журналирования и AMSI — его используют вредоносные скрипты для обхода защиты.",
		recommendation: "Удалите компонент: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root.",
		script:         `$f=Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue; if($f){$f.State}else{'NotFound'}`,
		eval:           evalEqualsFailIf("Enabled"),
	},
	{
		id: "ps-logging", title: "Журналирование блоков PowerShell включено",
		category: model.CatHardening, severity: model.SevLow,
		description:    "Журналирование Script Block позволяет обнаруживать вредоносные PowerShell-скрипты («fileless»-атаки).",
		recommendation: "Включите групповую политику «Turn on PowerShell Script Block Logging» (EnableScriptBlockLogging = 1).",
		script:         `(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging`,
		eval:           evalEquals("1"),
	},
	{
		id: "windows-update", title: "Обновления Windows установлены недавно",
		category: model.CatHardening, severity: model.SevMedium,
		description:    "Пропущенные обновления безопасности оставляют известные уязвимости открытыми (включая EternalBlue).",
		recommendation: "Установите последние обновления: Параметры → Центр обновления Windows.",
		script:         `$h=Get-HotFix|Sort-Object InstalledOn -Descending|Select-Object -First 1; if($h -and $h.InstalledOn){[int]((Get-Date)-$h.InstalledOn).TotalDays}else{-1}`,
		eval:           evalMaxDays(45),
	},
}

// RunAll выполняет все проверки локального хоста.
func RunAll(ctx context.Context, onProgress func(done, total int, title string)) []model.CheckResult {
	if runtime.GOOS != "windows" {
		res := model.CheckResult{
			ID: "platform", Title: "Аудит локального хоста",
			Category: model.CatInfo, Status: model.CheckSkipped,
			Value:          runtime.GOOS,
			Severity:       model.SevInfo,
			Description:    "Проверки защищённости локального хоста доступны только в Windows.",
			Recommendation: "Запустите приложение на компьютере под управлением Windows.",
		}
		res.Finalize()
		return []model.CheckResult{res}
	}

	results := make([]model.CheckResult, 0, len(checks))
	for i, c := range checks {
		if onProgress != nil {
			onProgress(i, len(checks), c.title)
		}
		out := runPowerShell(ctx, c.script)
		status, value := c.eval(out)
		if ctx.Err() != nil {
			status = model.CheckSkipped
		}
		r := model.CheckResult{
			ID: c.id, Title: c.title, Category: c.category, Status: status,
			Value: value, Severity: c.severity,
			Description: c.description, Recommendation: c.recommendation,
		}
		r.Finalize()
		results = append(results, r)
	}
	return results
}

// runPowerShell выполняет скрипт PowerShell и возвращает обрезанный вывод.
func runPowerShell(ctx context.Context, script string) string {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return ""
	}
	s := strings.TrimSpace(string(out))
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}
