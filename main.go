// Приложение «Аудит защиты» (Office Security Check) — аудит безопасности
// сетевых узлов и локального Windows-хоста.
//
// Графический режим запускается по умолчанию. Режим командной строки — с флагом -cli.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zigorminsk-debug/office-security-check/internal/hostcheck"
	"github.com/zigorminsk-debug/office-security-check/internal/model"
	"github.com/zigorminsk-debug/office-security-check/internal/netutil"
	"github.com/zigorminsk-debug/office-security-check/internal/report"
	"github.com/zigorminsk-debug/office-security-check/internal/scanner"
	"github.com/zigorminsk-debug/office-security-check/internal/ui"
	"github.com/zigorminsk-debug/office-security-check/internal/vuln"
)

// version — версия приложения, подставляется при сборке через -ldflags.
var version = "1.0.0"

func main() {
	var (
		cliMode   = flag.Bool("cli", false, "запуск в режиме командной строки (без GUI)")
		targets   = flag.String("targets", "", "цели: IP, CIDR, диапазон, имя хоста (через запятую)")
		profile   = flag.String("profile", "standard", "профиль: quick, standard, deep")
		ports     = flag.String("ports", "", "пользовательский список портов: 22,80,443 или 1-1024")
		jsonOut   = flag.String("json", "", "сохранить отчёт в JSON")
		htmlOut   = flag.String("html", "", "сохранить отчёт в HTML")
		csvOut    = flag.String("csv", "", "сохранить отчёт в CSV")
		hostAudit = flag.Bool("host-audit", false, "выполнить только аудит локального хоста")
		showVer   = flag.Bool("version", false, "показать версию и выйти")
		timeoutMS = flag.Int("timeout", 900, "тайм-аут подключения, мс")
		workers   = flag.Int("workers", 256, "число параллельных проверок")
		skipDisc  = flag.Bool("skip-discovery", false, "пропустить обнаружение хостов (считать все активными)")
		udp       = flag.Bool("udp", false, "выполнить UDP-проверки (SNMP, DNS, TFTP, NTP)")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("Аудит защиты (Office Security Check) версия %s\n", version)
		fmt.Println("Проверка сетевых узлов и локального хоста на уязвимости.")
		return
	}

	if !*cliMode && !*hostAudit && *jsonOut == "" && *htmlOut == "" && *csvOut == "" {
		// Графический режим.
		ui.Run(version)
		return
	}

	os.Exit(runCLI(*targets, model.ScanProfile(*profile), *ports,
		*jsonOut, *htmlOut, *csvOut, *hostAudit, *timeoutMS, *workers, *skipDisc, *udp))
}

// runCLI выполняет сканирование и аудит в режиме командной строки.
func runCLI(targets, profile model.ScanProfile, portSpec,
	jsonOut, htmlOut, csvOut string, hostAuditOnly bool,
	timeoutMS, workers int, skipDisc, udp bool) int {

	ctx := context.Background()
	var (
		hosts      []model.Host
		findings   []model.Finding
		hostChecks []model.CheckResult
		cfg        model.ScanConfig
	)

	// Аудит локального хоста.
	if hostAuditOnly || targets == "" {
		fmt.Println("Выполняется аудит защищённости локального хоста...")
		hostChecks = hostcheck.RunAll(ctx, func(done, total int, title string) {
			fmt.Printf("  [%d/%d] %s\n", done+1, total, title)
		})
		findings = append(findings, vuln.FindingsFromChecks(hostChecks)...)
	}

	// Сканирование сети.
	if targets != "" {
		cfg = scanner.DefaultConfig(profile)
		cfg.Targets = strings.Split(targets, ",")
		cfg.Profile = profile
		cfg.Timeout = time.Duration(timeoutMS) * time.Millisecond
		cfg.Workers = workers
		cfg.SkipDiscovery = skipDisc
		cfg.UDP = udp
		if portSpec != "" {
			var err error
			cfg.Ports, err = netutil.ParsePorts(portSpec)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка в списке портов: %v\n", err)
				return 2
			}
			cfg.Profile = model.ProfileCustom
		}

		fmt.Printf("Сканирование %s (профиль «%s», портов: %d)...\n",
			targets, cfg.Profile.Name(), len(cfg.Ports))
		engine := &scanner.Engine{
			Cfg: cfg,
			Progress: func(p scanner.Progress) {
				if p.Phase == "ports" && p.Total > 0 && p.Current%500 == 0 {
					fmt.Printf("  %s\n", p.Message)
				}
			},
		}
		var err error
		hosts, err = engine.Run(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка сканирования: %v\n", err)
			return 2
		}
		for i := range hosts {
			for j := range hosts[i].Services {
				findings = append(findings, vuln.EvaluateService(&hosts[i].Services[j])...)
			}
		}
		fmt.Printf("Обнаружено хостов: %d\n", len(hosts))
	}

	vuln.SortFindings(findings)
	r := report.Build(version, cfg, hosts, findings, hostChecks)

	// Краткая сводка в консоль.
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════")
	fmt.Printf("  Балл защищённости: %.0f / 100\n", r.Score)
	fmt.Printf("  Критических: %d · Высоких: %d · Средних: %d · Низких: %d · Информация: %d\n",
		r.Counts["CRITICAL"], r.Counts["HIGH"], r.Counts["MEDIUM"], r.Counts["LOW"], r.Counts["INFO"])
	fmt.Println("════════════════════════════════════════════════════════")
	for _, f := range findings {
		if f.Severity >= model.SevHigh {
			target := f.Host
			if f.Port > 0 {
				target = fmt.Sprintf("%s:%d", f.Host, f.Port)
			}
			fmt.Printf("[%s] %s — %s\n", f.Severity, target, f.Title)
		}
	}

	// Сохранение отчётов.
	if jsonOut != "" {
		if err := report.WriteJSON(r, jsonOut); err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка записи JSON: %v\n", err)
			return 2
		}
		fmt.Printf("Отчёт JSON сохранён: %s\n", jsonOut)
	}
	if htmlOut != "" {
		if err := report.WriteHTML(r, htmlOut); err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка записи HTML: %v\n", err)
			return 2
		}
		fmt.Printf("Отчёт HTML сохранён: %s\n", htmlOut)
	}
	if csvOut != "" {
		if err := report.WriteCSV(r, csvOut); err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка записи CSV: %v\n", err)
			return 2
		}
		fmt.Printf("Отчёт CSV сохранён: %s\n", csvOut)
	}
	return 0
}
