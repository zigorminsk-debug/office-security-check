# Аудит защиты — Office Security Check

**Настольное приложение для Windows** (Go + Fyne) для аудита безопасности сети и локального
компьютера: обнаружение уязвимостей, которые могут привести

- 🦠 **к заражению вирусами** и вредоносным ПО,
- 🔓 **к несанкционированному доступу** злоумышленников,
- 🔐 **к шифрованию серверов и данных** вымогателями (рансомвар).

![Язык](https://img.shields.io/badge/язык-Go%20%2B%20Fyne-00ADD8) ![Платформа](https://img.shields.io/badge/платформа-Windows%20x64-0078D6) ![Сборка](https://img.shields.io/badge/сборка-GitHub%20Actions-2088FF)

---

## Возможности

### 🔍 Сканирование сети (активный аудит)
| Модуль | Что проверяется |
|---|---|
| **Обнаружение хостов** | TCP-ping по ключевым портам, обратный DNS, определение ОС по службам |
| **Сканирование портов** | Параллельный TCP-скан (worker pool + ограничение скорости), профили «Быстрый / Стандартный / Глубокий / Пользовательский» |
| **Определение служб** | Баннер-граббинг, фингерпринтинг HTTP/SSH/FTP/SMTP/MySQL/SMB/RDP и др. |
| **Аудит TLS** | Сертификаты (срок, самоподпись, длина ключа), поддержка TLS 1.0–1.3 (raw ClientHello), слабые шифры (RC4/3DES/NULL/EXPORT/anon), **Heartbleed (CVE-2014-0160)** |
| **Проверки HTTP** | Заголовки безопасности (HSTS, CSP, X-Frame-Options…), опасные пути (`.git`, `.env`, бэкапы), WebDAV, TRACE, открытый прокси, панели администрирования |
| **Проверки SMB** | **SMBv1**, подписывание (SMB signing), анонимный доступ, **MS17-010 / EternalBlue** (только обнаружение) |
| **Проверки RDP** | Обязательная сетевая аутентификация (NLA/CredSSP), режим шифрования |
| **Незащищённые службы** | Redis, MongoDB, Elasticsearch, CouchDB, Memcached, MQTT, AMQP **без аутентификации** — главные цели шифровальщиков |
| **Контейнеры** | Docker API, Kubernetes API, kubelet, etcd без аутентификации |
| **Протоколы** | Анонимный FTP, открытый релей SMTP, SNMP `public`, открытый DNS-резолвер, TFTP, LDAP anonymous bind, VNC без пароля, IPMI, Telnet/rlogin |
| **UDP-проверки** (глубокий профиль) | SNMP, DNS (рекурсия), TFTP, NTP |
| **База знаний CVE** | Сигнатуры версий ПО: Apache, nginx, OpenSSH (включая regreSSHion CVE-2024-6387), vsftpd, ProFTPD, Tomcat (Ghostcat), PHP, IIS, Exim, Elasticsearch (Log4Shell), Jenkins и др. |

### 🛡 Аудит защищённости локального Windows-хоста (21 проверка)
Windows Defender (реальное время, сигнатуры), брандмауэр (все профили), RDP и NLA,
SMBv1, SMB signing, UAC, BitLocker, LLMNR/NBT-NS, WDigest, гостевая учётная запись,
удалённый реестр, Telnet, PowerShell 2.0 и журналирование, обновления Windows.

### 📊 Отчётность
- **Балл защищённости** 0–100 (нелинейный штраф за критические находки);
- находки сгруппированы по **категориям риска**: заражение вирусами / несанкционированный
  доступ / шифрование данных / укрепление защиты;
- экспспорта в **HTML** (красивый отчёт), **JSON** (интеграции), **CSV** (Excel);
- для каждой находки — описание, подтверждение (evidence), CVE, CVSS и **конкретная рекомендация** по устранению.

---

## Установка (Windows)

1. Перейдите в раздел **Actions** репозитория → последняя сборка **build** → **Artifacts**
   → скачайте `OfficeSecurityCheck-windows`.
2. Запустите **`Setup-Audit-Zashchity.exe`** и следуйте мастеру установки.
3. Либо используйте портативные версии: `SecurityAudit.exe` (GUI) и `SecurityAuditCLI.exe` (CLI).

> Приложение не требует прав администратора для работы (аудит хоста может запрашивать
> дополнительные данные в зависимости от политик Windows).

## Использование

### Графический интерфейс
1. Укажите **цель**: `192.168.1.0/24`, `192.168.1.1-50`, `сервер.local` или список через запятую.
2. Выберите **профиль**: Быстрый (критические порты) / Стандартный / Глубокий (все 65535 + UDP) / Пользовательский.
3. Нажмите **«Начать сканирование»**. Результаты появятся во вкладках «Уязвимости», «Хосты и службы».
4. Кнопка **«Аудит хоста»** проверит локальный компьютер (Windows).
5. **«Отчёт HTML / JSON / CSV»** — сохранение отчёта.

### Командная строка
```powershell
# Сканирование подсети, профиль «стандартный», отчёт HTML+JSON
SecurityAuditCLI.exe -cli -targets 192.168.1.0/24 -profile standard -html report.html -json report.json

# Только критические порты, свой набор портов
SecurityAuditCLI.exe -cli -targets 10.0.0.5 -ports 22,80,443,3389 -csv findings.csv

# Аудит локального Windows-хоста
SecurityAuditCLI.exe -cli -host-audit -html host-audit.html

# Глубокое сканирование с UDP-проверками
SecurityAuditCLI.exe -cli -targets 192.168.1.0/24 -profile deep -udp -json deep.json
```

Флаги: `-targets`, `-profile (quick|standard|deep)`, `-ports`, `-timeout (мс)`,
`-workers`, `-skip-discovery`, `-udp`, `-json`, `-html`, `-csv`, `-host-audit`, `-version`.

---

## Сборка и CI/CD

Сборка выполняется **автоматически на GitHub Actions** при каждом push:

| Этап | Что происходит |
|---|---|
| `verify` | gofmt, `go vet`, юнит-тесты (Linux) |
| `build-windows` | Кросс-проверка на Windows: vet, тесты, сборка GUI+CLI (CGO/Fyne + MinGW), ресурсы Windows (иконка, манифест DPI), smoke-тест, **сборка setup.exe** (Inno Setup) |
| `release` | При push тега `v*` — публикация GitHub Release с установщиком |

Локальная сборка (требуется Go 1.21+ и MinGW для Windows):
```bash
go test ./internal/...           # тесты движка
go build -o SecurityAuditCLI.exe .                                  # CLI
go build -ldflags "-H windowsgui" -o SecurityAudit.exe .            # GUI (Windows)
```

Подробнее: [docs/BUILD.md](docs/BUILD.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Архитектура (кратко)

```
main.go                    — точка входа: GUI (по умолчанию) или CLI (-cli)
internal/scanner/          — движок: хосты, порты, баннеры, TLS/HTTP/SMB/RDP/UDP-пробы
internal/vuln/             — база знаний CVE + эвристические правила + скоринг
internal/hostcheck/        — аудит защищённости локального Windows-хоста (PowerShell/API)
internal/report/           — отчёты HTML / JSON / CSV
internal/ui/               — графический интерфейс (Fyne v2)
build/windows/             — ресурсы Windows и скрипт Inno Setup
.github/workflows/         — пайплайн сборки GitHub Actions
```

Все проверки выполняются **только в режиме обнаружения**: приложение не содержит
эксплуатирующих нагрузок и не изменяет проверяемые системы.

## Юридическое уведомление

⚠️ **Сканируйте только сети и системы, на проверку которых у вас есть явное разрешение
владельца.** Несанкционированное сканирование чужих систем может нарушать
законодательство вашей страны. Разработчик не несёт ответственности за неправомерное
использование программы.

## Лицензия

MIT — см. [LICENSE](LICENSE).
