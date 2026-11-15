// Package vuln реализует базу знаний об уязвимостях и движок сопоставления
// (аналог Nmap NSE / Vulners): сигнатуры версий ПО с CVE и эвристические правила.
package vuln

import (
	"strconv"
	"strings"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
)

// Signature — сигнатура уязвимости, зависящей от версии ПО.
type Signature struct {
	ID             string
	Product        string // канонический ключ продукта (apache, openssh, nginx...)
	Min            string // минимальная уязвимая версия (включительно), "" = без ограничения
	Below          string // версии строго меньше Below уязвимы
	Title          string
	Description    string
	Severity       model.Severity
	Category       model.Category
	CVSS           float64
	CVEs           []string
	Recommendation string
}

// NormalizeVersion извлекает числовую часть версии: "2.4.49 (Unix)" -> "2.4.49",
// "8.0p1" -> "8.0".
func NormalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	var b strings.Builder
	for _, r := range v {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
			continue
		}
		if r == '.' && b.Len() > 0 && !strings.HasSuffix(b.String(), ".") {
			b.WriteRune(r)
			continue
		}
		break
	}
	return strings.Trim(b.String(), ".")
}

// CompareVersions сравнивает версии по числовым сегментам.
// Возвращает -1, если a < b; 0, если равны; 1, если a > b.
func CompareVersions(a, b string) int {
	na, nb := NormalizeVersion(a), NormalizeVersion(b)
	if na == "" && nb == "" {
		return 0
	}
	if na == "" {
		return -1
	}
	if nb == "" {
		return 1
	}
	pa := strings.Split(na, ".")
	pb := strings.Split(nb, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		va, vb := 0, 0
		if i < len(pa) {
			va, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			vb, _ = strconv.Atoi(pb[i])
		}
		if va < vb {
			return -1
		}
		if va > vb {
			return 1
		}
	}
	return 0
}

// affected проверяет, попадает ли версия в диапазон действия сигнатуры.
func (s Signature) affected(version string) bool {
	if version == "" {
		return false
	}
	if s.Min != "" && CompareVersions(version, s.Min) < 0 {
		return false
	}
	if s.Below != "" && CompareVersions(version, s.Below) >= 0 {
		return false
	}
	return true
}

// MatchSignatures возвращает сигнатуры, применимые к продукту с версией.
func MatchSignatures(product, version string) []Signature {
	product = strings.ToLower(product)
	version = NormalizeVersion(version)
	var out []Signature
	for _, s := range Signatures {
		if s.Product == product && s.affected(version) {
			out = append(out, s)
		}
	}
	return out
}

// Signatures — база знаний об уязвимостях версий ПО (фрагмент CVE-базы).
// Источники: NVD (nvd.nist.gov), CISA KEV, отчёты вендоров.
var Signatures = []Signature{
	// ---------- Apache HTTP Server ----------
	{
		ID: "apache-cve-2021-41773", Product: "apache", Min: "2.4.49", Below: "2.4.51",
		Title:       "Apache HTTP Server 2.4.49/2.4.50 — удалённое выполнение кода (Path Traversal)",
		Description: "Уязвимости CVE-2021-41773 и CVE-2021-42013 позволяют обходить ограничения пути и выполнять произвольный код на сервере. Активно эксплуатируются в интернете.",
		Severity:    model.SevCritical, Category: model.CatMalware, CVSS: 9.8,
		CVEs:           []string{"CVE-2021-41773", "CVE-2021-42013"},
		Recommendation: "Немедленно обновите Apache HTTP Server до версии 2.4.51 или новее.",
	},
	{
		ID: "apache-cve-2023-25690", Product: "apache", Min: "2.4.0", Below: "2.4.56",
		Title:       "Apache HTTP Server < 2.4.56 — обход аутентификации и RCE через mod_proxy",
		Description: "CVE-2023-25690: некоторые конфигурации mod_proxy позволяют злоумышленнику выполнить запросы к внутренним серверам и выполнить произвольный код.",
		Severity:    model.SevCritical, Category: model.CatUnauthorized, CVSS: 9.8,
		CVEs:           []string{"CVE-2023-25690"},
		Recommendation: "Обновите Apache до версии 2.4.56 или новее и пересмотрите правила RewriteRule/mod_proxy.",
	},
	{
		ID: "apache-cve-2024-38474", Product: "apache", Min: "2.4.0", Below: "2.4.60",
		Title:       "Apache HTTP Server < 2.4.60 — уязвимости подмены кодировки и обхода (множество CVE)",
		Description: "CVE-2024-38474, CVE-2024-38475, CVE-2024-38476, CVE-2024-39573: обход аутентификации, утечка файлов и выполнение кода через mod_rewrite/mod_proxy.",
		Severity:    model.SevCritical, Category: model.CatMalware, CVSS: 9.8,
		CVEs:           []string{"CVE-2024-38474", "CVE-2024-38475", "CVE-2024-38476", "CVE-2024-39573"},
		Recommendation: "Обновите Apache до версии 2.4.60 или новее.",
	},

	// ---------- nginx ----------
	{
		ID: "nginx-eol", Product: "nginx", Below: "1.22.0",
		Title:       "Устаревшая ветка nginx (< 1.22)",
		Description: "Используется старая ветка nginx без регулярных обновлений безопасности. Известны уязвимости (CVE-2019-20372, CVE-2021-23017 и др.).",
		Severity:    model.SevMedium, Category: model.CatHardening, CVSS: 5.3,
		CVEs:           []string{"CVE-2021-23017", "CVE-2019-20372"},
		Recommendation: "Обновите nginx до актуальной стабильной ветки (1.24+).",
	},

	// ---------- OpenSSH ----------
	{
		ID: "openssh-cve-2024-6387", Product: "openssh", Min: "8.5", Below: "9.8",
		Title:       "OpenSSH 8.5–9.7 — удалённое выполнение кода (regreSSHion, CVE-2024-6387)",
		Description: "Гонка обработки сигналов в sshd позволяет выполнить произвольный код с правами root. Уязвимость вернулась в ветку 8.5p1–9.7p1.",
		Severity:    model.SevCritical, Category: model.CatUnauthorized, CVSS: 8.1,
		CVEs:           []string{"CVE-2024-6387"},
		Recommendation: "Обновите OpenSSH до 9.8p1 или новее; временно ограничьте доступ к sshd по IP через брандмауэр.",
	},
	{
		ID: "openssh-cve-2024-6387-old", Product: "openssh", Below: "4.4",
		Title:       "OpenSSH < 4.4p1 — удалённое выполнение кода (regreSSHion, CVE-2024-6387)",
		Description: "Старые ветки OpenSSH также затронуты гонкой обработки сигналов с возможностью удалённого выполнения кода.",
		Severity:    model.SevCritical, Category: model.CatUnauthorized, CVSS: 8.1,
		CVEs:           []string{"CVE-2024-6387"},
		Recommendation: "Обновите OpenSSH до актуальной версии.",
	},
	{
		ID: "openssh-cve-2018-15473", Product: "openssh", Below: "7.8",
		Title:       "OpenSSH < 7.8 — перечисление пользователей (CVE-2018-15473)",
		Description: "Особый запрос раскрывает, существует ли учётная запись на сервере. Используется для подготовки атак подбором паролей.",
		Severity:    model.SevMedium, Category: model.CatUnauthorized, CVSS: 5.3,
		CVEs:           []string{"CVE-2018-15473"},
		Recommendation: "Обновите OpenSSH до версии 7.8 или новее.",
	},
	{
		ID: "openssh-old", Product: "openssh", Below: "7.4",
		Title:       "Устаревший OpenSSH (< 7.4)",
		Description: "Версия содержит известные уязвимости (CVE-2016-0777 «roaming», CVE-2016-10009 и др.).",
		Severity:    model.SevHigh, Category: model.CatUnauthorized, CVSS: 7.5,
		CVEs:           []string{"CVE-2016-0777", "CVE-2016-10009"},
		Recommendation: "Обновите OpenSSH до актуальной версии.",
	},

	// ---------- vsftpd / ProFTPD ----------
	{
		ID: "vsftpd-234-backdoor", Product: "vsftpd", Min: "2.3.4", Below: "2.3.5",
		Title:       "vsftpd 2.3.4 — встроенный бэкдор (CVE-2011-2523)",
		Description: "Официальный дистрибутив vsftpd 2.3.4 содержал бэкдор: при входе с особым именем пользователя открывался shell с правами root.",
		Severity:    model.SevCritical, Category: model.CatUnauthorized, CVSS: 10.0,
		CVEs:           []string{"CVE-2011-2523"},
		Recommendation: "Немедленно замените сервер FTP: переустановите vsftpd из проверенного источника (версия 3.x) и проверьте хост на компрометацию.",
	},
	{
		ID: "proftpd-modcopy", Product: "proftpd", Min: "1.3.5", Below: "1.3.6",
		Title:       "ProFTPD 1.3.5 — копирование файлов без аутентификации (mod_copy, CVE-2015-3306)",
		Description: "Модуль mod_copy позволяет копировать файлы на сервер без аутентификации (используется для загрузки веб-шеллов).",
		Severity:    model.SevCritical, Category: model.CatUnauthorized, CVSS: 10.0,
		CVEs:           []string{"CVE-2015-3306"},
		Recommendation: "Обновите ProFTPD до 1.3.6+ и отключите модуль mod_copy.",
	},

	// ---------- Apache Tomcat ----------
	{
		ID: "tomcat-ghostcat-9", Product: "tomcat", Min: "9.0.0", Below: "9.0.31",
		Title:       "Apache Tomcat 9.0.x < 9.0.31 — чтение файлов и RCE через AJP (Ghostcat)",
		Description: "CVE-2020-1938: уязвимость протокола AJP позволяет читать произвольные файлы web-приложений и загружать вредоносный код.",
		Severity:    model.SevCritical, Category: model.CatMalware, CVSS: 9.8,
		CVEs:           []string{"CVE-2020-1938"},
		Recommendation: "Обновите Tomcat до 9.0.31+; отключите AJP-коннектор, если он не используется.",
	},
	{
		ID: "tomcat-ghostcat-85", Product: "tomcat", Min: "8.5.0", Below: "8.5.51",
		Title:       "Apache Tomcat 8.5.x < 8.5.51 — чтение файлов и RCE через AJP (Ghostcat)",
		Description: "CVE-2020-1938: уязвимость протокола AJP позволяет читать произвольные файлы и выполнять код.",
		Severity:    model.SevCritical, Category: model.CatMalware, CVSS: 9.8,
		CVEs:           []string{"CVE-2020-1938"},
		Recommendation: "Обновите Tomcat до 8.5.51+; отключите AJP-коннектор.",
	},

	// ---------- PHP ----------
	{
		ID: "php-74-eol", Product: "php", Below: "7.4.0",
		Title:       "PHP < 7.4 — не поддерживается, множество критических уязвимостей",
		Description: "Ветки PHP 5.x/7.0–7.3 не получают обновлений безопасности; известны уязвимости удалённого выполнения кода (CVE-2019-11043 и др.).",
		Severity:    model.SevCritical, Category: model.CatMalware, CVSS: 9.8,
		CVEs:           []string{"CVE-2019-11043", "CVE-2018-19518"},
		Recommendation: "Перейдите на поддерживаемую версию PHP (8.2+).",
	},
	{
		ID: "php-80-old", Product: "php", Below: "8.0.30",
		Title:       "PHP 8.0.x < 8.0.30 — уязвимости обхода и выполнения кода",
		Description: "CVE-2023-3823/3824: уязвимости в libxml и phar позволяют обходить ограничения и выполнять код.",
		Severity:    model.SevHigh, Category: model.CatMalware, CVSS: 8.8,
		CVEs:           []string{"CVE-2023-3823", "CVE-2023-3824"},
		Recommendation: "Обновите PHP до последней версии ветки или перейдите на 8.2+.",
	},

	// ---------- Microsoft IIS ----------
	{
		ID: "iis-webdav-cve-2017-7269", Product: "iis", Min: "7.5", Below: "7.5.7601.23677",
		Title:       "Microsoft IIS 7.5 WebDAV — удалённое выполнение кода (CVE-2017-7269)",
		Description: "Уязвимость sc_storage_path_with_backslash в WebDAV позволяет выполнить код с правами SYSTEM. Активно эксплуатируется.",
		Severity:    model.SevCritical, Category: model.CatMalware, CVSS: 10.0,
		CVEs:           []string{"CVE-2017-7269"},
		Recommendation: "Установите обновления безопасности Microsoft и отключите WebDAV, если он не требуется.",
	},

	// ---------- Exim ----------
	{
		ID: "exim-old", Product: "exim", Below: "4.94",
		Title:       "Exim < 4.94 — множество уязвимостей, включая RCE («21Nails»)",
		Description: "Серия уязвимостей CVE-2021-27216 и др. позволяет выполнять произвольный код и обходить ограничения SMTP-сервера.",
		Severity:    model.SevCritical, Category: model.CatMalware, CVSS: 9.8,
		CVEs:           []string{"CVE-2021-27216", "CVE-2020-28018"},
		Recommendation: "Обновите Exim до 4.94 или новее.",
	},

	// ---------- Elasticsearch / Log4Shell ----------
	{
		ID: "es-log4shell", Product: "elasticsearch", Below: "7.16.3",
		Title:       "Elasticsearch < 7.16.3 — Log4Shell (CVE-2021-44228)",
		Description: "Встроенный Apache Log4j 2 уязвим к удалённому выполнению кода через JNDI (Log4Shell).",
		Severity:    model.SevCritical, Category: model.CatMalware, CVSS: 10.0,
		CVEs:           []string{"CVE-2021-44228"},
		Recommendation: "Обновите Elasticsearch до 7.16.3+ (или 6.8.20+) либо примените митигации Log4j.",
	},

	// ---------- Jenkins ----------
	{
		ID: "jenkins-cve-2024-23897", Product: "jenkins", Below: "2.442",
		Title:       "Jenkins < 2.442 — чтение произвольных файлов (CVE-2024-23897)",
		Description: "Уязвимость в библиотеке args4j позволяет читать произвольные файлы с сервера и, как следствие, выполнять код.",
		Severity:    model.SevCritical, Category: model.CatUnauthorized, CVSS: 9.8,
		CVEs:           []string{"CVE-2024-23897"},
		Recommendation: "Обновите Jenkins до 2.442 LTS или новее.",
	},

	// ---------- Apache Struts ----------
	{
		ID: "struts-cve-2017-5638", Product: "struts", Below: "2.3.32",
		Title:       "Apache Struts 2 — удалённое выполнение кода (CVE-2017-5638, Equifax)",
		Description: "Уязвимость Jakarta Multipart parser позволяет выполнить произвольные команды через заголовок Content-Type. Использована в атаке на Equifax.",
		Severity:    model.SevCritical, Category: model.CatMalware, CVSS: 10.0,
		CVEs:           []string{"CVE-2017-5638"},
		Recommendation: "Обновите Apache Struts 2 до 2.3.32/2.5.10.1 или новее.",
	},
}
