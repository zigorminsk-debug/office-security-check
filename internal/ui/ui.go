// Package ui реализует графический интерфейс приложения «Аудит защиты» (Fyne).
package ui

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
)

//go:embed icon.png
var iconBytes []byte

// UI — главная структура графического интерфейса.
type UI struct {
	version string
	app     fyne.App
	win     fyne.Window

	targetEntry   *widget.Entry
	portsEntry    *widget.Entry
	profileSelect *widget.Select
	progressBar   *widget.ProgressBar
	statusLabel   *widget.Label
	scoreLabel    *widget.Label
	logLabel      *widget.Label
	logScroll     *container.Scroll

	findingsTable *widget.Table
	hostsTable    *widget.Table
	checksTable   *widget.Table

	scanBtn *widget.Button
	stopBtn *widget.Button
	hostBtn *widget.Button

	mu       sync.Mutex
	findings []model.Finding
	hosts    []model.Host
	checks   []model.CheckResult
	cfg      model.ScanConfig
	cancel   context.CancelFunc
	running  bool
	logLines []string
}

// Run запускает графическое приложение.
func Run(version string) {
	a := app.NewWithID("by.office.security-audit")
	u := &UI{version: version, app: a}
	u.win = a.NewWindow("Аудит защиты — Office Security Check")
	u.win.SetIcon(fyne.NewStaticResource("icon.png", iconBytes))
	u.build()
	u.win.Resize(fyne.NewSize(1280, 840))
	u.win.CenterOnScreen()
	u.win.ShowAndRun()
}

// build создаёт виджеты и раскладку главного окна.
func (u *UI) build() {
	title := widget.NewLabelWithStyle("Аудит защиты сети и серверов",
		fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	subtitle := widget.NewLabel("Поиск уязвимостей, ведущих к заражению вирусами, " +
		"несанкционированному доступу и шифрованию данных вымогателями")

	u.targetEntry = widget.NewEntry()
	u.targetEntry.SetPlaceHolder("Цель: 192.168.1.0/24, 192.168.1.1-50, сервер.local ...")
	u.targetEntry.SetText("127.0.0.1")

	u.portsEntry = widget.NewEntry()
	u.portsEntry.SetPlaceHolder("Порты (для «Пользовательского»): 22,80,443,3389 или 1-1024")

	u.profileSelect = widget.NewSelect([]string{
		"Быстрый (критические порты)",
		"Стандартный (расширенный)",
		"Глубокий (все 65535 портов + UDP)",
		"Пользовательский",
	}, func(string) {})
	u.profileSelect.SetSelected("Стандартный (расширенный)")

	u.scanBtn = widget.NewButton("▶ Начать сканирование", u.startScan)
	u.scanBtn.Importance = widget.HighImportance
	u.stopBtn = widget.NewButton("■ Стоп", u.stopScan)
	u.stopBtn.Disable()
	u.hostBtn = widget.NewButton("🛡 Аудит хоста", u.startHostAudit)

	aboutBtn := widget.NewButton("О программе", u.showAbout)
	exportHTML := widget.NewButton("📄 Отчёт HTML", func() { u.exportReport("html") })
	exportJSON := widget.NewButton("📋 JSON", func() { u.exportReport("json") })
	exportCSV := widget.NewButton("📊 CSV", func() { u.exportReport("csv") })

	settings := container.NewVBox(
		container.NewGridWithColumns(2,
			widget.NewLabel("Цель сканирования:"), u.targetEntry,
		),
		container.NewGridWithColumns(2,
			widget.NewLabel("Профиль проверки:"), u.profileSelect,
		),
		u.portsEntry,
		container.NewHBox(u.scanBtn, u.stopBtn, u.hostBtn, aboutBtn),
		container.NewHBox(widget.NewLabel("Экспорт отчёта:"), exportHTML, exportJSON, exportCSV),
	)

	u.progressBar = widget.NewProgressBar()
	u.statusLabel = widget.NewLabel("Готово к работе. Укажите цель и запустите сканирование.")
	u.scoreLabel = widget.NewLabelWithStyle("Балл защищённости: —",
		fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	u.logLabel = widget.NewLabel("")
	u.logLabel.Wrapping = fyne.TextWrapWord
	u.logScroll = container.NewScroll(u.logLabel)
	u.logScroll.SetMinSize(fyne.NewSize(0, 120))

	u.findingsTable = u.makeFindingsTable()
	u.hostsTable = u.makeHostsTable()
	u.checksTable = u.makeChecksTable()

	findingsTab := container.NewBorder(
		container.NewHBox(u.scoreLabel, widget.NewLabel("")), nil, nil, nil,
		container.NewScroll(u.findingsTable),
	)
	tabs := container.NewAppTabs(
		container.NewTabItem("Уязвимости", findingsTab),
		container.NewTabItem("Хосты и службы", container.NewScroll(u.hostsTable)),
		container.NewTabItem("Аудит хоста", container.NewScroll(u.checksTable)),
		container.NewTabItem("Журнал", u.logScroll),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	top := container.NewVBox(title, subtitle, widget.NewSeparator(), settings,
		widget.NewSeparator(), u.progressBar, u.statusLabel)

	u.win.SetContent(container.NewBorder(top, nil, nil, nil, tabs))
	u.win.SetCloseIntercept(func() {
		u.mu.Lock()
		cancel := u.cancel
		u.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		u.win.Close()
	})
}

// makeFindingsTable создаёт таблицу находок (строка 0 — заголовки).
func (u *UI) makeFindingsTable() *widget.Table {
	headers := []string{"Уровень", "Хост", "Служба", "Уязвимость / отклонение", "Категория"}
	t := widget.NewTable(
		func() (int, int) { return len(u.findings) + 1, len(headers) },
		func() fyne.CanvasObject {
			l := widget.NewLabel("template")
			l.Wrapping = fyne.TextTruncate
			return l
		},
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			l := obj.(*widget.Label)
			l.Importance = widget.MediumImportance
			l.TextStyle = fyne.TextStyle{}
			if id.Row == 0 {
				l.Text = headers[id.Col]
				l.TextStyle = fyne.TextStyle{Bold: true}
				return
			}
			if id.Row > len(u.findings) {
				l.Text = ""
				return
			}
			f := u.findings[id.Row-1]
			switch id.Col {
			case 0:
				l.Text = f.Severity.String()
				l.Importance = severityImportance(f.Severity)
				l.TextStyle = fyne.TextStyle{Bold: true}
			case 1:
				l.Text = f.Host
				if f.Port > 0 {
					l.Text = fmt.Sprintf("%s:%d", f.Host, f.Port)
				}
			case 2:
				l.Text = f.Service
			case 3:
				l.Text = f.Title
			case 4:
				l.Text = f.Category.String()
			}
		},
	)
	t.SetColumnWidth(0, 110)
	t.SetColumnWidth(1, 170)
	t.SetColumnWidth(2, 130)
	t.SetColumnWidth(3, 520)
	t.SetColumnWidth(4, 230)
	return t
}

// makeHostsTable создаёт таблицу хостов.
func (u *UI) makeHostsTable() *widget.Table {
	headers := []string{"IP-адрес", "Имя хоста", "ОС (по службам)", "Открытые службы"}
	t := widget.NewTable(
		func() (int, int) { return len(u.hosts) + 1, len(headers) },
		func() fyne.CanvasObject {
			l := widget.NewLabel("template")
			l.Wrapping = fyne.TextWrapWord
			return l
		},
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			l := obj.(*widget.Label)
			if id.Row == 0 {
				l.Text = headers[id.Col]
				l.TextStyle = fyne.TextStyle{Bold: true}
				return
			}
			l.TextStyle = fyne.TextStyle{}
			if id.Row > len(u.hosts) {
				l.Text = ""
				return
			}
			h := u.hosts[id.Row-1]
			switch id.Col {
			case 0:
				l.Text = h.IP
			case 1:
				l.Text = h.Hostname
			case 2:
				l.Text = h.OSHint
			case 3:
				var parts []string
				for _, s := range h.Services {
					proto := s.Protocol
					if proto == "" {
						proto = "tcp"
					}
					parts = append(parts, fmt.Sprintf("%d/%s %s", s.Port, proto, s.Label()))
				}
				l.Text = strings.Join(parts, "; ")
			}
		},
	)
	t.SetColumnWidth(0, 150)
	t.SetColumnWidth(1, 180)
	t.SetColumnWidth(2, 200)
	t.SetColumnWidth(3, 620)
	return t
}

// makeChecksTable создаёт таблицу проверок локального хоста.
func (u *UI) makeChecksTable() *widget.Table {
	headers := []string{"Проверка", "Результат", "Значение", "Категория"}
	t := widget.NewTable(
		func() (int, int) { return len(u.checks) + 1, len(headers) },
		func() fyne.CanvasObject {
			l := widget.NewLabel("template")
			l.Wrapping = fyne.TextWrapWord
			return l
		},
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			l := obj.(*widget.Label)
			l.Importance = widget.MediumImportance
			l.TextStyle = fyne.TextStyle{}
			if id.Row == 0 {
				l.Text = headers[id.Col]
				l.TextStyle = fyne.TextStyle{Bold: true}
				return
			}
			if id.Row > len(u.checks) {
				l.Text = ""
				return
			}
			c := u.checks[id.Row-1]
			switch id.Col {
			case 0:
				l.Text = c.Title
			case 1:
				switch c.Status {
				case model.CheckPassed:
					l.Text = "✓ Пройдена"
					l.Importance = widget.SuccessImportance
				case model.CheckFailed:
					l.Text = "✗ Не пройдена"
					l.Importance = widget.DangerImportance
					l.TextStyle = fyne.TextStyle{Bold: true}
				case model.CheckSkipped:
					l.Text = "— Пропущена"
					l.Importance = widget.LowImportance
				default:
					l.Text = "? Нет данных"
					l.Importance = widget.LowImportance
				}
			case 2:
				l.Text = c.Value
			case 3:
				l.Text = c.Category.String()
			}
		},
	)
	t.SetColumnWidth(0, 380)
	t.SetColumnWidth(1, 150)
	t.SetColumnWidth(2, 180)
	t.SetColumnWidth(3, 240)
	return t
}

// severityImportance преобразует уровень опасности в важность виджета.
func severityImportance(s model.Severity) widget.Importance {
	switch s {
	case model.SevCritical:
		return widget.DangerImportance
	case model.SevHigh:
		return widget.WarningImportance
	case model.SevMedium:
		return widget.MediumImportance
	default:
		return widget.LowImportance
	}
}

// log добавляет строку в журнал (безопасно из любого потока).
func (u *UI) log(format string, args ...interface{}) {
	line := time.Now().Format("15:04:05") + "  " + fmt.Sprintf(format, args...)
	fyne.Do(func() {
		u.logLines = append(u.logLines, line)
		if len(u.logLines) > 400 {
			u.logLines = u.logLines[len(u.logLines)-400:]
		}
		u.logLabel.Text = strings.Join(u.logLines, "\n")
		u.logLabel.Refresh()
		u.logScroll.ScrollToBottom()
	})
}

// setStatus обновляет строку состояния.
func (u *UI) setStatus(text string) {
	fyne.Do(func() {
		u.statusLabel.Text = text
		u.statusLabel.Refresh()
	})
}

// setProgress обновляет индикатор выполнения.
func (u *UI) setProgress(value float64) {
	fyne.Do(func() {
		u.progressBar.Value = value
		u.progressBar.Refresh()
	})
}

// refreshTables перерисовывает таблицы результатов.
func (u *UI) refreshTables() {
	fyne.Do(func() {
		u.findingsTable.Refresh()
		u.hostsTable.Refresh()
		u.checksTable.Refresh()
	})
}

// showAbout показывает диалог «О программе» с юридическим уведомлением.
func (u *UI) showAbout() {
	msg := fmt.Sprintf(`«Аудит защиты» (Office Security Check), версия %s

Программа выполняет проверку сетевых узлов и локального компьютера
на уязвимости, которые могут привести:
  • к заражению вирусами и вредоносным ПО;
  • к несанкционированному доступу злоумышленников;
  • к шифрованию серверов и данных вымогателями (рансомвар).

Все проверки выполняются только в режиме обнаружения и не содержат
эксплуатирующих нагрузок.

ВАЖНО: сканируйте только те сети и системы, на проверку которых у вас
есть явное разрешение владельца. Несанкционированное сканирование
может нарушать законодательство вашей страны.`, u.version)
	dialog.ShowInformation("О программе", msg, u.win)
}
