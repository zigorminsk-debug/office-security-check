package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"

	"github.com/zigorminsk-debug/office-security-check/internal/hostcheck"
	"github.com/zigorminsk-debug/office-security-check/internal/model"
	"github.com/zigorminsk-debug/office-security-check/internal/netutil"
	"github.com/zigorminsk-debug/office-security-check/internal/report"
	"github.com/zigorminsk-debug/office-security-check/internal/scanner"
	"github.com/zigorminsk-debug/office-security-check/internal/vuln"
)

// profileFromLabel преобразует выбор пользователя в профиль сканирования.
func profileFromLabel(label string) model.ScanProfile {
	switch {
	case strings.HasPrefix(label, "Быстрый"):
		return model.ProfileQuick
	case strings.HasPrefix(label, "Глубокий"):
		return model.ProfileDeep
	case strings.HasPrefix(label, "Пользовательский"):
		return model.ProfileCustom
	default:
		return model.ProfileStandard
	}
}

// startScan запускает сканирование сети в отдельном потоке.
func (u *UI) startScan() {
	target := strings.TrimSpace(u.targetEntry.Text)
	if target == "" {
		dialog.ShowError(fmt.Errorf("укажите цель сканирования (IP, CIDR или имя хоста)"), u.win)
		return
	}

	profile := profileFromLabel(u.profileSelect.Selected)
	cfg := scanner.DefaultConfig(profile)
	cfg.Targets = []string{target}
	cfg.Profile = profile

	if portSpec := strings.TrimSpace(u.portsEntry.Text); portSpec != "" {
		ports, err := netutil.ParsePorts(portSpec)
		if err != nil {
			dialog.ShowError(fmt.Errorf("ошибка в списке портов: %w", err), u.win)
			return
		}
		cfg.Ports = ports
		cfg.Profile = model.ProfileCustom
	}

	u.mu.Lock()
	if u.running {
		u.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	u.cancel = cancel
	u.running = true
	u.findings = nil
	u.hosts = nil
	u.mu.Unlock()

	fyne.Do(func() {
		u.scanBtn.Disable()
		u.stopBtn.Enable()
		u.hostBtn.Disable()
		u.scoreLabel.Text = "Балл защищённости: сканирование..."
		u.scoreLabel.Refresh()
	})
	u.refreshTables()

	go u.runScan(ctx, cfg)
}

// stopScan останавливает текущее сканирование.
func (u *UI) stopScan() {
	u.mu.Lock()
	cancel := u.cancel
	u.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	u.setStatus("Остановка сканирования...")
	u.log("Получен запрос на остановку сканирования")
}

// runScan выполняет сканирование и анализ результатов.
func (u *UI) runScan(ctx context.Context, cfg model.ScanConfig) {
	defer func() {
		u.mu.Lock()
		u.running = false
		u.cancel = nil
		u.mu.Unlock()
		fyne.Do(func() {
			u.scanBtn.Enable()
			u.stopBtn.Disable()
			u.hostBtn.Enable()
		})
	}()

	start := time.Now()
	u.log("=== Начало сканирования: %s (профиль «%s», портов: %d) ===",
		strings.Join(cfg.Targets, ", "), cfg.Profile.Name(), len(cfg.Ports))

	engine := &scanner.Engine{
		Cfg: cfg,
		Progress: func(p scanner.Progress) {
			if p.Total > 0 {
				u.setProgress(float64(p.Current) / float64(p.Total))
			}
			u.setStatus(p.Message)
		},
	}

	hosts, err := engine.Run(ctx)
	if err != nil {
		u.log("Ошибка сканирования: %v", err)
		u.setStatus("Ошибка: " + err.Error())
		return
	}

	// Анализ собранных данных базой знаний.
	u.setStatus("Анализ результатов базой знаний уязвимостей...")
	var findings []model.Finding
	for i := range hosts {
		for j := range hosts[i].Services {
			findings = append(findings, vuln.EvaluateService(&hosts[i].Services[j])...)
		}
	}
	vuln.SortFindings(findings)
	score := vuln.ScoreFindings(findings)

	elapsed := time.Since(start).Round(time.Second)
	open := 0
	for _, h := range hosts {
		open += len(h.Services)
	}
	u.log("=== Сканирование завершено за %s ===", elapsed)
	u.log("Хостов обнаружено: %d; открытых служб: %d; находок: %d", len(hosts), open, len(findings))
	u.log("Балл защищённости: %.0f из 100", score)

	// Все обновления состояния UI — на главном потоке.
	fyne.Do(func() {
		u.hosts = hosts
		u.findings = findings
		u.cfg = cfg
		u.findingsTable.Refresh()
		u.hostsTable.Refresh()
		u.checksTable.Refresh()
		u.progressBar.Value = 1
		u.progressBar.Refresh()
		u.scoreLabel.Text = fmt.Sprintf("Балл защищённости: %.0f / 100   |   находок: %d (критических: %d)",
			score, len(findings), countSeverity(findings, model.SevCritical))
		u.scoreLabel.Refresh()
	})
	u.setStatus(fmt.Sprintf("Готово: %d хостов, %d находок за %s", len(hosts), len(findings), elapsed))

	if ctx.Err() == nil && len(findings) > 0 {
		worst := findings[0]
		u.log("Наиболее опасная находка: [%s] %s", worst.Severity, worst.Title)
	}
}

// countSeverity считает находки указанного уровня.
func countSeverity(findings []model.Finding, sev model.Severity) int {
	n := 0
	for _, f := range findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

// startHostAudit запускает аудит защищённости локального компьютера.
func (u *UI) startHostAudit() {
	u.mu.Lock()
	if u.running {
		u.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	u.cancel = cancel
	u.running = true
	u.mu.Unlock()

	fyne.Do(func() {
		u.scanBtn.Disable()
		u.stopBtn.Enable()
		u.hostBtn.Disable()
	})
	u.log("=== Начало аудита защищённости локального хоста ===")

	go func() {
		defer func() {
			u.mu.Lock()
			u.running = false
			u.cancel = nil
			u.mu.Unlock()
			fyne.Do(func() {
				u.scanBtn.Enable()
				u.stopBtn.Disable()
				u.hostBtn.Enable()
			})
		}()

		checks := hostcheck.RunAll(ctx, func(done, total int, title string) {
			u.setStatus(fmt.Sprintf("Проверка хоста: %s (%d/%d)", title, done+1, total))
			u.setProgress(float64(done+1) / float64(total))
		})

		// Проваленные проверки добавляются в общий список находок.
		hostFindings := vuln.FindingsFromChecks(checks)
		fyne.Do(func() {
			u.checks = checks
			u.findings = append(u.findings, hostFindings...)
			vuln.SortFindings(u.findings)
			u.findingsTable.Refresh()
			u.hostsTable.Refresh()
			u.checksTable.Refresh()
		})

		failed := 0
		for _, c := range checks {
			if c.Status == model.CheckFailed {
				failed++
				u.log("НЕ ПРОЙДЕНА: %s (значение: %s)", c.Title, c.Value)
			}
		}
		u.log("=== Аудит хоста завершён: проверок %d, не пройдено %d ===", len(checks), failed)
		u.setStatus(fmt.Sprintf("Аудит хоста завершён: не пройдено проверок — %d", failed))
		u.refreshTables()
	}()
}

// exportReport сохраняет отчёт в выбранном формате.
func (u *UI) exportReport(format string) {
	u.mu.Lock()
	hosts := u.hosts
	findings := u.findings
	checks := u.checks
	cfg := u.cfg
	u.mu.Unlock()

	if len(findings) == 0 && len(hosts) == 0 && len(checks) == 0 {
		dialog.ShowInformation("Нет данных", "Сначала выполните сканирование или аудит хоста.", u.win)
		return
	}

	r := report.Build(u.version, cfg, hosts, findings, checks)
	d := dialog.NewFileSave(func(w fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, u.win)
			return
		}
		if w == nil {
			return
		}
		defer w.Close()
		var werr error
		switch format {
		case "json":
			werr = report.WriteJSONTo(w, r)
		case "html":
			werr = report.WriteHTMLTo(w, r)
		case "csv":
			werr = report.WriteCSVTo(w, r)
		}
		if werr != nil {
			dialog.ShowError(werr, u.win)
			return
		}
		u.log("Отчёт (%s) сохранён: %s", strings.ToUpper(format), w.URI().Path())
		dialog.ShowInformation("Отчёт сохранён",
			"Файл отчёта успешно сохранён:\n"+w.URI().Path(), u.win)
	}, u.win)
	d.SetFileName("audit-report." + format)
	d.Show()
}
