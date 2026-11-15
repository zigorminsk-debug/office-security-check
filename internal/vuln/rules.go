package vuln

import (
	"fmt"
	"strings"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
)

// Rule — эвристическое правило обнаружения опасной экспозиции службы.
type Rule struct {
	ID             string
	Title          string
	Description    string
	Severity       model.Severity
	Category       model.Category
	CVSS           float64
	CVEs           []string
	Recommendation string
	Match          func(s *model.Service) bool
}

// extra читает значение расширения службы.
func extra(s *model.Service, key string) string {
	if s.Extra == nil {
		return ""
	}
	return s.Extra[key]
}

// isTrue проверяет расширение службы на "true".
func isTrue(s *model.Service, key string) bool {
	return extra(s, key) == "true"
}

// isFalse проверяет расширение службы на "false".
func isFalse(s *model.Service, key string) bool {
	return extra(s, key) == "false"
}

// ExposureRules — набор правил обнаружения опасных экспозиций.
// Каждое правило сопоставляется с признаками, собранными сканером (Service.Extra).
var ExposureRules = []Rule{
	// ================= SMB / Windows =================
	{
		ID: "smb-v1-enabled", Title: "Включён протокол SMBv1 (устаревший и опасный)",
		Description: "SMBv1 не поддерживает современные механизмы шифрования и аутентификации. Именно через него распространяются шифровальщики WannaCry, NotPetya и EternalBlue-атаки. SMBv1 должен быть полностью отключён.",
		Severity:    model.SevCritical, Category: model.CatRansomware, CVSS: 9.3,
		CVEs:           []string{"CVE-2017-0144", "CVE-2017-0145"},
		Recommendation: "Отключите SMBv1 на всех серверах и рабочих станциях: Set-SmbServerConfiguration -EnableSMB1Protocol $false (или Remove-WindowsFeature FS-SMB1).",
		Match:          func(s *model.Service) bool { return isTrue(s, "smb_v1") },
	},
	{
		ID: "ms17-010-vulnerable", Title: "Уязвимость EternalBlue / MS17-010 в SMB-сервере",
		Description: "Сервер принимает специальный транзакционный запрос, характерный для уязвимых систем Windows (MS17-010). Это та же уязвимость, которая использована в атаках WannaCry и NotPetya, приводящих к массовому шифрованию серверов.",
		Severity:    model.SevCritical, Category: model.CatRansomware, CVSS: 10.0,
		CVEs:           []string{"CVE-2017-0144"},
		Recommendation: "Немедленно установите обновления безопасности Microsoft (MS17-010) либо временно заблокируйте TCP 445 брандмауэром.",
		Match:          func(s *model.Service) bool { return extra(s, "ms17_010") == "vulnerable" },
	},
	{
		ID: "smb-signing-not-required", Title: "Не требуется подписывание SMB-пакетов (SMB signing)",
		Description: "Без обязательного подписывания SMB-трафик уязвим к атакам relay-типа (NTLM relay) и подмене содержимого, что позволяет злоумышленнику перехватить и модифицировать запросы аутентификации.",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 8.1,
		CVEs:           []string{"CVE-2019-1040", "CVE-2020-1113"},
		Recommendation: "Включите обязательное подписывание SMB: политика «Microsoft network server: Digitally sign communications (always)» = Enabled.",
		Match:          func(s *model.Service) bool { return isFalse(s, "smb_signing_required") },
	},
	{
		ID: "smb-anonymous-access", Title: "Анонимный доступ к SMB-ресурсам",
		Description: "Сервер разрешает подключение к общим папкам без учётных записей. Это позволяет злоумышленнику разведывать данные и распространять шифровальщики по сети.",
		Severity:    model.SevHigh, Category: model.CatRansomware, CVSS: 8.6,
		Recommendation: "Запретите анонимный доступ: политика «Network access: Restrict anonymous access to Named Pipes and Shares», отключите гостевую учётную запись.",
		Match:          func(s *model.Service) bool { return isTrue(s, "smb_anonymous") },
	},

	// ================= RDP =================
	{
		ID: "rdp-no-nla", Title: "RDP без обязательной сетевой аутентификации (NLA)",
		Description: "Служба удалённого рабочего стола принимает подключения до прохождения аутентификации. Это открывает путь к атакам на уязвимости протокола (BlueKeep CVE-2019-0708), перебору паролей и установке шифровальщиков.",
		Severity:    model.SevCritical, Category: model.CatRansomware, CVSS: 9.8,
		CVEs:           []string{"CVE-2019-0708"},
		Recommendation: "Включите обязательную сетевую аутентификацию: «Требовать сетевую аутентификацию пользователей для подключений к удалённому рабочему столу» = Enabled. Открывайте RDP только через VPN/шлюз с MFA.",
		Match:          func(s *model.Service) bool { return isFalse(s, "rdp_nla") },
	},
	{
		ID: "rdp-exposed", Title: "Служба RDP доступна из сети",
		Description: "Удалённый рабочий стол напрямую доступен по сети. RDP — главная точка входа для шифровальщиков (Dharma, LockBit, Conti): перебор паролей или украденные учётные данные позволяют злоумышленнику войти и зашифровать серверы.",
		Severity:    model.SevMedium, Category: model.CatRansomware, CVSS: 6.5,
		Recommendation: "Закройте RDP от прямого доступа (VPN, RDP Gateway), включите MFA, ограничьте список пользователей и включите блокировку после нескольких неудачных попыток.",
		Match:          func(s *model.Service) bool { return s.Name == "rdp" || extra(s, "rdp_nla") != "" },
	},

	// ================= Опасные протоколы =================
	{
		ID: "telnet-plaintext", Title: "Служба Telnet — передача учётных данных в открытом виде",
		Description: "Telnet передаёт логины и пароли без шифрования. Перехват пароля даёт злоумышленнику полный доступ к устройству и возможность развернуть шифровальщик.",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 7.5,
		Recommendation: "Отключите Telnet полностью, используйте SSH. На сетевом оборудовании: no transport input telnet.",
		Match:          func(s *model.Service) bool { return s.Name == "telnet" },
	},
	{
		ID: "ftp-anonymous", Title: "FTP-сервер разрешает анонимный вход",
		Description: "Анонимный доступ к FTP позволяет читать и часто изменять файлы без аутентификации. FTP без шифрования также уязвим к перехвату учётных данных.",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 7.5,
		Recommendation: "Отключите анонимный доступ (anonymous_enable=NO), переведите FTP на FTPS/SFTP и ограничьте права пользователей.",
		Match:          func(s *model.Service) bool { return isTrue(s, "ftp_anon") },
	},
	{
		ID: "ftp-plaintext", Title: "FTP передаёт данные без шифрования",
		Description: "Протокол FTP не шифрует учётные данные и файлы. Используйте FTPS или SFTP.",
		Severity:    model.SevMedium, Category: model.CatUnauthorized, CVSS: 5.3,
		Recommendation: "Включите FTPS (явный TLS) или перейдите на SFTP (SSH).",
		Match:          func(s *model.Service) bool { return s.Name == "ftp" },
	},
	{
		ID: "rlogin-rsh", Title: "Доступны устаревшие службы rlogin/rsh",
		Description: "Службы rlogin/rsh используют доверие между хостами без аутентификации — любой, кто подделает имя хоста, получает shell.",
		Severity:    model.SevCritical, Category: model.CatUnauthorized, CVSS: 9.8,
		Recommendation: "Полностью отключите rlogin/rsh/rexec, используйте SSH.",
		Match:          func(s *model.Service) bool { return s.Name == "rlogin" || s.Name == "rsh" },
	},
	{
		ID: "tftp-open", Title: "Доступен сервер TFTP без аутентификации",
		Description: "TFTP не требует аутентификации и часто используется для кражи конфигураций маршрутизаторов и прошивок, а также для загрузки вредоносного кода на устройства.",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 7.5,
		Recommendation: "Отключите TFTP; если он необходим, ограничьте доступ по IP брандмауэром.",
		Match:          func(s *model.Service) bool { return s.Name == "tftp" },
	},

	// ================= Незащищённые хранилища данных (вектор шифрования) =================
	{
		ID: "redis-unauth", Title: "Redis доступен без аутентификации",
		Description: "Незащищённый Redis — одна из главных целей шифровальщиков и майнеров (атаки Meow, DarthMiner, «RedisWannaMine»). Злоумышленник получает полный контроль над данными и может выполнить код на хосте.",
		Severity:    model.SevCritical, Category: model.CatRansomware, CVSS: 10.0,
		Recommendation: "Включите требование пароля (requirepass / ACL), запретите команду CONFIG и настройте брандмауэр: Redis не должен быть доступен из внешних сетей.",
		Match:          func(s *model.Service) bool { return isTrue(s, "redis_unauth") },
	},
	{
		ID: "mongodb-unauth", Title: "MongoDB доступна без аутентификации",
		Description: "Открытые базы MongoDB массово шифруются и вымогаются: злоумышленник выгружает и стирает данные (атаки «MongoDB ransomware», «Meow»).",
		Severity:    model.SevCritical, Category: model.CatRansomware, CVSS: 10.0,
		Recommendation: "Включите авторизацию (security.authorization: enabled), ограничьте доступ bindIp и брандмауэром.",
		Match:          func(s *model.Service) bool { return isTrue(s, "mongo_unauth") },
	},
	{
		ID: "elasticsearch-unauth", Title: "Elasticsearch доступен без аутентификации",
		Description: "Открытый Elasticsearch позволяет читать и удалять индексы. Массовые атаки шифруют и вымогают данные из поисковых кластеров.",
		Severity:    model.SevCritical, Category: model.CatRansomware, CVSS: 10.0,
		Recommendation: "Включите security-модуль (xpack.security.enabled), настройте аутентификацию и ограничьте сетевой доступ.",
		Match:          func(s *model.Service) bool { return isTrue(s, "elastic_unauth") },
	},
	{
		ID: "couchdb-unauth", Title: "CouchDB доступна без аутентификации",
		Description: "Анонимный доступ к CouchDB позволяет читать, изменять и удалять базы данных.",
		Severity:    model.SevHigh, Category: model.CatRansomware, CVSS: 8.6,
		Recommendation: "Включите аутентификацию CouchDB (require_valid_user) и закройте порт 5984 брандмауэром.",
		Match:          func(s *model.Service) bool { return isTrue(s, "couchdb_unauth") },
	},
	{
		ID: "memcached-unauth", Title: "Memcached доступен без аутентификации",
		Description: "Незащищённый Memcached позволяет читать и изменять кэшированные данные (включая сессии и учётные записи), а также используется для DDoS-амплификации.",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 7.5,
		Recommendation: "Запускайте Memcached с флагом -U 0 (отключить UDP), ограничьте доступ брандмауэром, используйте SASL-аутентификацию.",
		Match:          func(s *model.Service) bool { return isTrue(s, "memcached_unauth") },
	},
	{
		ID: "mqtt-unauth", Title: "MQTT-брокер без аутентификации",
		Description: "Анонимный доступ к MQTT позволяет перехватывать и подменять сообщения устройств, а также использовать брокер как точку распространения вредоносного кода.",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 8.6,
		Recommendation: "Включите обязательную аутентификацию и TLS для MQTT-брокера.",
		Match:          func(s *model.Service) bool { return isTrue(s, "mqtt_unauth") },
	},
	{
		ID: "amqp-unauth", Title: "AMQP (RabbitMQ) доступен с гостевой учётной записью",
		Description: "Учётная запись guest/guest или отсутствие аутентификации позволяет управлять очередями сообщений и выполнять произвольные действия в приложении.",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 8.6,
		Recommendation: "Отключите/замените гостевую учётную запись, требуйте аутентификацию, закройте порт 5672 брандмауэром.",
		Match:          func(s *model.Service) bool { return isTrue(s, "amqp_unauth") },
	},

	// ================= Контейнеры и оркестрация =================
	{
		ID: "docker-api-unauth", Title: "Docker Engine API доступен без аутентификации",
		Description: "Управление демоном Docker без TLS-аутентификации даёт мгновенный root-доступ к хосту: злоумышленник может запустить контейнер с примонтированной файловой системой хоста и развернуть шифровальщик.",
		Severity:    model.SevCritical, Category: model.CatRansomware, CVSS: 10.0,
		Recommendation: "Отключите удалённый доступ к Docker API (tcp://0.0.0.0:2375); используйте TLS-сертификаты (DOCKER_TLS_VERIFY) или локальный socket.",
		Match:          func(s *model.Service) bool { return isTrue(s, "docker_unauth") },
	},
	{
		ID: "k8s-api-unauth", Title: "Kubernetes API доступен без аутентификации",
		Description: "Неаутентифицированный доступ к Kubernetes API позволяет управлять всеми подами и секретами кластера.",
		Severity:    model.SevCritical, Category: model.CatRansomware, CVSS: 10.0,
		Recommendation: "Включите аутентификацию и авторизацию API-сервера (RBAC), отключите анонимный режим (--anonymous-auth=false).",
		Match:          func(s *model.Service) bool { return isTrue(s, "k8s_unauth") },
	},
	{
		ID: "kubelet-unauth", Title: "Kubelet API доступен без аутентификации",
		Description: "Открытый kubelet (порт 10250) позволяет запускать команды в контейнерах и получать доступ к секретам кластера.",
		Severity:    model.SevCritical, Category: model.CatRansomware, CVSS: 10.0,
		Recommendation: "Включите --authentication-token-webhook и --authorization-mode=Webhook на kubelet.",
		Match:          func(s *model.Service) bool { return isTrue(s, "kubelet_unauth") },
	},
	{
		ID: "etcd-unauth", Title: "etcd доступен без аутентификации",
		Description: "etcd хранит все секреты кластера Kubernetes; неаутентифицированный доступ раскрывает пароли и токены.",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 8.6,
		Recommendation: "Включите client-cert-auth для etcd и закройте порт 2379 брандмауэром.",
		Match:          func(s *model.Service) bool { return isTrue(s, "etcd_unauth") },
	},

	// ================= Удалённый доступ / VNC / IPMI =================
	{
		ID: "vnc-no-auth", Title: "VNC-сервер без аутентификации",
		Description: "Сервер удалённого доступа VNC принимает подключения без пароля — любой получает полный контроль над рабочим столом и может запустить шифровальщик.",
		Severity:    model.SevCritical, Category: model.CatRansomware, CVSS: 9.8,
		Recommendation: "Установите пароль VNC (SecurityTypes VncAuth), используйте туннель через SSH/VPN, отключите прямой доступ из сети.",
		Match:          func(s *model.Service) bool { return isTrue(s, "vnc_noauth") },
	},
	{
		ID: "ipmi-exposed", Title: "Доступен интерфейс управления IPMI/BMC",
		Description: "IPMI (порт 623) работает на отдельном процессоре сервера и исторически содержит уязвимости обхода аутентификации (CVE-2013-4786). Компрометация BMC даёт полный контроль над оборудованием.",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 8.3,
		CVEs:           []string{"CVE-2013-4786", "CVE-2013-2286"},
		Recommendation: "Закройте UDP 623 и TCP 623 брандмауэром, обновите прошивку BMC, смените пароли по умолчанию.",
		Match:          func(s *model.Service) bool { return s.Name == "ipmi" },
	},
	{
		ID: "winrm-exposed", Title: "WinRM доступен из сети",
		Description: "Windows Remote Management позволяет выполнять команды на сервере. При слабых паролях это прямой путь к компрометации и размещению шифровальщика.",
		Severity:    model.SevMedium, Category: model.CatRansomware, CVSS: 6.5,
		Recommendation: "Ограничьте WinRM доверенными адресами (WinRM firewall rule scoping), используйте только HTTPS (5986) и групповые политики аутентификации.",
		Match:          func(s *model.Service) bool { return s.Name == "winrm" },
	},

	// ================= Сетевые службы =================
	{
		ID: "snmp-public", Title: "SNMP отвечает на community-строку «public»",
		Description: "Стандартная community-строка по умолчанию позволяет читать конфигурацию устройства, включая пароли и списки доступа. SNMPv1/v2c передаёт данные без шифрования.",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 7.5,
		Recommendation: "Смените community-строки, перейдите на SNMPv3 с аутентификацией и шифрованием, ограничьте доступ по IP.",
		Match:          func(s *model.Service) bool { return isTrue(s, "snmp_public") },
	},
	{
		ID: "dns-open-resolver", Title: "DNS-сервер является открытом рекурсивным резолвером",
		Description: "Открытый рекурсивный DNS используется для DDoS-амплификации и подделки ответов (DNS cache poisoning).",
		Severity:    model.SevMedium, Category: model.CatUnauthorized, CVSS: 5.3,
		Recommendation: "Запретите рекурсию для внешних клиентов (allow-recursion в BIND, disable recursion для public DNS).",
		Match:          func(s *model.Service) bool { return isTrue(s, "dns_open_resolver") },
	},
	{
		ID: "smtp-open-relay", Title: "SMTP-сервер — открытый релей (open relay)",
		Description: "Сервер отправляет почту от чужого имени без аутентификации. Используется для рассылки спама и фишинга, ведёт к попаданию в чёрные списки.",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 7.5,
		Recommendation: "Настройте требование аутентификации для отправки (SASL), запретите релей для внешних получателей.",
		Match:          func(s *model.Service) bool { return isTrue(s, "smtp_open_relay") },
	},
	{
		ID: "ldap-anonymous", Title: "LDAP разрешает анонимное подключение (anonymous bind)",
		Description: "Анонимный доступ к LDAP раскрывает структуру каталога, имена пользователей и группы — всю информацию для подготовки целевой атаки.",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 7.5,
		Recommendation: "Запретите анонимный доступ к LDAP (disallow bind_anon в OpenLDAP, отказ в политике Windows).",
		Match:          func(s *model.Service) bool { return isTrue(s, "ldap_anon") },
	},

	// ================= Базы данных =================
	{
		ID: "db-exposed", Title: "СУБД доступна из сети напрямую",
		Description: "Прямой доступ к серверу базы данных из сети — излюбленная цель перебора паролей и уязвимостей СУБД. Компрометация БД ведёт к краже и шифрованию данных.",
		Severity:    model.SevMedium, Category: model.CatRansomware, CVSS: 6.5,
		Recommendation: "Закройте порты СУБД брандмауэром (доступ только с серверов приложений), используйте сложные пароли и шифрование соединений.",
		Match: func(s *model.Service) bool {
			switch s.Name {
			case "mysql", "mssql", "postgresql", "oracle-tns", "mongodb", "cassandra":
				return true
			}
			return false
		},
	},
	{
		ID: "rdp-mssql-exposed", Title: "MS SQL Server доступен из сети (порт 1433)",
		Description: "Обнаружен сетевой доступ к Microsoft SQL Server. Проверьте, что доступ разрешён только доверенным серверам и используется строгая аутентификация.",
		Severity:    model.SevMedium, Category: model.CatRansomware, CVSS: 6.5,
		Recommendation: "Ограничьте доступ к порту 1433 брандмауэром, отключите sa-учётную запись или задайте ей сложный пароль.",
		Match:          func(s *model.Service) bool { return s.Name == "mssql" },
	},

	// ================= Веб-панели администрирования =================
	{
		ID: "admin-panel", Title: "Доступна панель администрирования через веб",
		Description: "Панели управления (Jenkins, phpMyAdmin, Portainer, Tomcat Manager, WebLogic, NAS-интерфейсы) постоянно атакуются автоматизированными брутфорсерами. Компрометация панели даёт полный контроль над сервером.",
		Severity:    model.SevMedium, Category: model.CatUnauthorized, CVSS: 6.5,
		Recommendation: "Закройте панели от прямого доступа (VPN, IP-фильтр), включите MFA, используйте сложные пароли и fail2ban/блокировку.",
		Match:          func(s *model.Service) bool { return isTrue(s, "admin_panel") },
	},
	{
		ID: "weblogic-exposed", Title: "Oracle WebLogic Server доступен из сети",
		Description: "WebLogic исторически содержит множество критических RCE-уязвимостей (CVE-2017-10271, CVE-2019-2725, CVE-2020-14882), активно эксплуатируемых для установки шифровальщиков и майнеров.",
		Severity:    model.SevHigh, Category: model.CatMalware, CVSS: 9.8,
		CVEs:           []string{"CVE-2017-10271", "CVE-2019-2725", "CVE-2020-14882"},
		Recommendation: "Обновите WebLogic до актуального CPU Oracle, отключите T3/IIOP если не используются.",
		Match:          func(s *model.Service) bool { return extra(s, "weblogic") == "true" || s.Product == "weblogic" },
	},
	{
		ID: "jboss-exposed", Title: "JBoss/WildFly доступен из сети",
		Description: "JBoss содержит уязвимости десериализации (CVE-2017-12149) и небезопасные консоли управления, ведущие к удалённому выполнению кода.",
		Severity:    model.SevHigh, Category: model.CatMalware, CVSS: 9.8,
		CVEs:           []string{"CVE-2017-12149"},
		Recommendation: "Обновите JBoss, закройте консоль управления, отключитеInvoker-сервлеты.",
		Match:          func(s *model.Service) bool { return isTrue(s, "jboss") || s.Product == "jboss" },
	},

	// ================= TLS/HTTPS =================
	{
		ID: "tls-old-versions", Title: "Поддерживается устаревший TLS 1.0/1.1",
		Description: "TLS 1.0 и 1.1 уязвимы к атакам BEAST, POODLE и подобным и запрещены стандартами безопасности (PCI DSS).",
		Severity:    model.SevMedium, Category: model.CatUnauthorized, CVSS: 5.9,
		CVEs:           []string{"CVE-2014-3566", "CVE-2011-3389"},
		Recommendation: "Отключите TLS 1.0/1.1, оставьте только TLS 1.2 и TLS 1.3.",
		Match: func(s *model.Service) bool {
			return s.TLS != nil && (s.TLS.SupportsTLS10 || s.TLS.SupportsTLS11)
		},
	},
	{
		ID: "tls-weak-cipher", Title: "Поддерживаются слабые шифры (RC4/3DES/NULL/EXPORT/anon)",
		Description: "Слабые шифровые наборы позволяют расшифровывать трафик (SWEET32, RC4-биасы, экспортные шифры FREAK/Logjam).",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 7.5,
		CVEs:           []string{"CVE-2016-2183", "CVE-2015-0204"},
		Recommendation: "Настройте сервер на сильные шифры TLS 1.2/1.3 (AES-GCM, ChaCha20), отключите RC4, 3DES, NULL и экспортируемые наборы.",
		Match:          func(s *model.Service) bool { return s.TLS != nil && s.TLS.WeakCipher != "" },
	},
	{
		ID: "tls-heartbleed", Title: "Сервер уязвим к Heartbleed (CVE-2014-0160)",
		Description: "Уязвимость в реализации TLS Heartbeat позволяет читать оперативную память сервера: приватные ключи, пароли и сессии пользователей.",
		Severity:    model.SevCritical, Category: model.CatUnauthorized, CVSS: 7.5,
		CVEs:           []string{"CVE-2014-0160"},
		Recommendation: "Немедленно обновите OpenSSL и перевыпустите сертификаты, так как приватные ключи могли быть скомпрометированы.",
		Match:          func(s *model.Service) bool { return s.TLS != nil && s.TLS.Heartbleed },
	},
	{
		ID: "tls-self-signed", Title: "Самоподписанный сертификат TLS",
		Description: "Самоподписанный сертификат не подтверждается доверенным центром сертификации — пользователи уязвимы к атакам «человек посередине».",
		Severity:    model.SevMedium, Category: model.CatUnauthorized, CVSS: 5.3,
		Recommendation: "Используйте сертификат от доверенного CA (например, Let's Encrypt или корпоративный PKI).",
		Match:          func(s *model.Service) bool { return s.TLS != nil && s.TLS.SelfSigned },
	},
	{
		ID: "tls-expired", Title: "Срок действия сертификата TLS истёк",
		Description: "Просроченный сертификат блокирует клиентов или заставляет их игнорировать предупреждения, открывая путь к MITM-атакам.",
		Severity:    model.SevHigh, Category: model.CatHardening, CVSS: 5.9,
		Recommendation: "Перевыпустите сертификат. Настройте автоматическое продление (ACME).",
		Match:          func(s *model.Service) bool { return s.TLS != nil && s.TLS.DaysLeft < 0 },
	},
	{
		ID: "tls-expiring-soon", Title: "Сертификат TLS истекает в ближайшие 14 дней",
		Description: "Истечение срока действия сертификата приведёт к ошибкам клиентов.",
		Severity:    model.SevLow, Category: model.CatHardening, CVSS: 3.1,
		Recommendation: "Перевыпустите сертификат и включите мониторинг сроков действия.",
		Match:          func(s *model.Service) bool { return s.TLS != nil && s.TLS.DaysLeft >= 0 && s.TLS.DaysLeft <= 14 },
	},
	{
		ID: "tls-weak-key", Title: "Слабый ключ шифрования сертификата (< 2048 бит RSA)",
		Description: "Короткие ключи RSA/DSA могут быть подобраны современными вычислительными ресурсами.",
		Severity:    model.SevMedium, Category: model.CatUnauthorized, CVSS: 5.3,
		Recommendation: "Перевыпустите сертификат с ключом RSA 2048+ бит или ECDSA P-256.",
		Match: func(s *model.Service) bool {
			return s.TLS != nil && s.TLS.PublicKeyBits > 0 && s.TLS.PublicKeyBits < 2048
		},
	},
	{
		ID: "tls-hostname-mismatch", Title: "Имя хоста не соответствует сертификату TLS",
		Description: "Сертификат выдан на другое имя — клиенты не могут проверить подлинность сервера.",
		Severity:    model.SevMedium, Category: model.CatUnauthorized, CVSS: 5.3,
		Recommendation: "Перевыпустите сертификат на корректное имя хоста (CN/SAN).",
		Match:          func(s *model.Service) bool { return s.TLS != nil && s.TLS.HostnameMismatch },
	},

	// ================= HTTP =================
	{
		ID: "http-open-proxy", Title: "Веб-сервер работает как открытый прокси",
		Description: "Открытый прокси используется злоумышленниками для анонимизации атак с вашего сервера, что ведёт к блокировкам и правовым рискам.",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 7.5,
		Recommendation: "Отключите проксирование (CONNECT/forward proxy) для внешних клиентов.",
		Match:          func(s *model.Service) bool { return isTrue(s, "open_proxy") },
	},
	{
		ID: "http-sensitive-files", Title: "Доступны конфиденциальные файлы и резервные копии",
		Description: "Обнаружены открытые файлы конфигурации, резервных копий или служебные данные (например, .git, .env, дампы БД). Они часто содержат пароли и ключи доступа.",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 7.5,
		Recommendation: "Закройте доступ к служебным файлам через конфигурацию веб-сервера и удалите их с публичных серверов.",
		Match:          func(s *model.Service) bool { return isTrue(s, "sensitive_files") },
	},
	{
		ID: "http-directory-listing", Title: "Включён листинг каталогов веб-сервера",
		Description: "Просмотр списка файлов раскрывает структуру приложения и резервные копии, облегчая подготовку атаки.",
		Severity:    model.SevMedium, Category: model.CatUnauthorized, CVSS: 5.3,
		Recommendation: "Отключите autoindex (nginx) / Options Indexes (Apache).",
		Match:          func(s *model.Service) bool { return isTrue(s, "dir_listing") },
	},
	{
		ID: "http-webdav", Title: "Включён модуль WebDAV",
		Description: "WebDAV может позволять загружать и изменять файлы на сервере (включая веб-шеллы). Особенно опасен в сочетании с IIS (CVE-2017-7269).",
		Severity:    model.SevHigh, Category: model.CatMalware, CVSS: 8.6,
		Recommendation: "Отключите WebDAV, если он не требуется; запретите методы PUT/DELETE/MKCOL.",
		Match:          func(s *model.Service) bool { return isTrue(s, "webdav") },
	},
	{
		ID: "http-trace", Title: "Включён HTTP-метод TRACE",
		Description: "Метод TRACE используется в атаках Cross-Site Tracing для кражи cookie.",
		Severity:    model.SevLow, Category: model.CatUnauthorized, CVSS: 3.7,
		Recommendation: "Отключите метод TRACE в конфигурации веб-сервера.",
		Match:          func(s *model.Service) bool { return isTrue(s, "http_trace") },
	},
	{
		ID: "http-server-status", Title: "Доступны служебные страницы статуса (server-status, actuator)",
		Description: "Служебные страницы раскрывают внутреннюю структуру: имена модулей, запросы, переменные окружения и секреты.",
		Severity:    model.SevMedium, Category: model.CatUnauthorized, CVSS: 5.3,
		Recommendation: "Закройте доступ к служебным страницам (server-status, server-info, /actuator) по IP или отключите их.",
		Match:          func(s *model.Service) bool { return isTrue(s, "status_pages") },
	},
	{
		ID: "http-version-disclosure", Title: "Веб-сервер раскрывает версию ПО",
		Description: "Заголовок Server/X-Powered-By сообщает точную версию, помогая злоумышленнику подобрать известные уязвимости.",
		Severity:    model.SevInfo, Category: model.CatHardening, CVSS: 0,
		Recommendation: "Отключите вывод версии: server_tokens off (nginx), ServerTokens Prod (Apache), expose_php=Off (PHP).",
		Match: func(s *model.Service) bool {
			if s.HTTP == nil {
				return false
			}
			return strings.ContainsAny(s.HTTP.Server, "0123456789") || strings.ContainsAny(s.HTTP.PoweredBy, "0123456789")
		},
	},
	{
		ID: "http-missing-headers", Title: "Отсутствуют важные заголовки безопасности HTTP",
		Description: "Без HSTS, CSP, X-Frame-Options и X-Content-Type-Options сайт уязвим к MITM, XSS, clickjacking и MIME-атакам.",
		Severity:    model.SevLow, Category: model.CatHardening, CVSS: 3.7,
		Recommendation: "Добавьте заголовки: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy.",
		Match: func(s *model.Service) bool {
			return s.HTTP != nil && len(s.HTTP.MissingHeaders) > 0
		},
	},
}

// EvaluateService сопоставляет службу с базой знаний и возвращает находки.
func EvaluateService(s *model.Service) []model.Finding {
	var out []model.Finding

	// 1. Сигнатуры версий ПО (CVE-база).
	if s.Product != "" && s.Version != "" {
		for _, sig := range MatchSignatures(s.Product, s.Version) {
			f := model.NewFinding(
				fmt.Sprintf("%s@%s:%d", sig.ID, s.Host, s.Port),
				sig.Title, sig.Description, sig.Severity, sig.Category, sig.Recommendation)
			f.Host, f.Port, f.Protocol, f.Service = s.Host, s.Port, s.Protocol, s.Name
			f.CVEs, f.CVSS = sig.CVEs, sig.CVSS
			f.Evidence = fmt.Sprintf("%s %s", s.Product, s.Version)
			out = append(out, f)
		}
	}

	// 2. Эвристические правила экспозиции.
	for _, rule := range ExposureRules {
		if rule.Match != nil && rule.Match(s) {
			f := model.NewFinding(
				fmt.Sprintf("%s@%s:%d", rule.ID, s.Host, s.Port),
				rule.Title, rule.Description, rule.Severity, rule.Category, rule.Recommendation)
			f.Host, f.Port, f.Protocol, f.Service = s.Host, s.Port, s.Protocol, s.Name
			f.CVEs, f.CVSS = rule.CVEs, rule.CVSS
			f.Evidence = evidenceFor(s, rule.ID)
			out = append(out, f)
		}
	}

	return out
}

// evidenceFor формирует текстовое подтверждение для находки.
func evidenceFor(s *model.Service, ruleID string) string {
	switch {
	case strings.HasPrefix(ruleID, "tls-") && s.TLS != nil:
		return fmt.Sprintf("Сертификат: %s; TLS: %s", s.TLS.Subject, s.TLS.Version)
	case strings.HasPrefix(ruleID, "http-") && s.HTTP != nil:
		return fmt.Sprintf("HTTP %d, Server: %s", s.HTTP.StatusCode, s.HTTP.Server)
	case s.Banner != "":
		return trunc(s.Banner, 120)
	}
	return ""
}

func trunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
