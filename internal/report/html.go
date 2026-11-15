package report

import (
	"fmt"
	"html/template"
	"io"
	"os"
	"strings"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
)

// ---------- Модель данных для HTML-отчёта ----------

type htmlFinding struct {
	Severity    string
	SevClass    string
	Category    string
	Target      string
	Service     string
	Title       string
	Description string
	Evidence    string
	CVEs        string
	CVSS        string
	Recommend   string
}

type htmlHost struct {
	IP       string
	Hostname string
	OS       string
	Services string
	Open     int
}

type htmlCheck struct {
	Title    string
	Status   string
	StClass  string
	Value    string
	Category string
}

type htmlData struct {
	Tool       string
	Version    string
	Date       string
	Score      string
	ScoreClass string
	Critical   int
	High       int
	Medium     int
	Low        int
	Info       int
	HostsCount int
	Findings   []htmlFinding
	Hosts      []htmlHost
	Checks     []htmlCheck
	ConfigLine string
	CatSummary []catCount
}

type catCount struct {
	Name  string
	Count int
}

// sevClass возвращает CSS-класс для уровня опасности.
func sevClass(s model.Severity) string {
	switch s {
	case model.SevCritical:
		return "sev-critical"
	case model.SevHigh:
		return "sev-high"
	case model.SevMedium:
		return "sev-medium"
	case model.SevLow:
		return "sev-low"
	default:
		return "sev-info"
	}
}

// WriteHTML сохраняет отчёт в формате HTML.
func WriteHTML(r *model.Report, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return WriteHTMLTo(f, r)
}

// WriteHTMLTo записывает HTML-отчёт в произвольный поток.
func WriteHTMLTo(w io.Writer, r *model.Report) error {
	data := htmlData{
		Tool:    r.Tool,
		Version: r.Version,
		Date:    r.GeneratedAt.Format("02.01.2006 15:04"),
		Score:   fmt.Sprintf("%.0f", r.Score),
	}
	switch {
	case r.Score >= 80:
		data.ScoreClass = "score-good"
	case r.Score >= 50:
		data.ScoreClass = "score-warn"
	default:
		data.ScoreClass = "score-bad"
	}

	// Счётчики и категории.
	catMap := map[model.Category]int{}
	for _, f := range r.Findings {
		switch f.Severity {
		case model.SevCritical:
			data.Critical++
		case model.SevHigh:
			data.High++
		case model.SevMedium:
			data.Medium++
		case model.SevLow:
			data.Low++
		default:
			data.Info++
		}
		catMap[f.Category]++
	}
	for _, c := range []model.Category{model.CatRansomware, model.CatUnauthorized, model.CatMalware, model.CatHardening, model.CatInfo} {
		if catMap[c] > 0 {
			data.CatSummary = append(data.CatSummary, catCount{Name: c.String(), Count: catMap[c]})
		}
	}
	data.HostsCount = len(r.Hosts)

	// Находки.
	for _, f := range r.Findings {
		target := f.Host
		if f.Port > 0 {
			target = fmt.Sprintf("%s:%d", f.Host, f.Port)
		}
		cvss := ""
		if f.CVSS > 0 {
			cvss = fmt.Sprintf("%.1f", f.CVSS)
		}
		data.Findings = append(data.Findings, htmlFinding{
			Severity: f.Severity.String(), SevClass: sevClass(f.Severity),
			Category: f.Category.String(), Target: target, Service: f.Service,
			Title: f.Title, Description: f.Description, Evidence: f.Evidence,
			CVEs: strings.Join(f.CVEs, ", "), CVSS: cvss, Recommend: f.Recommendation,
		})
	}

	// Хосты.
	for _, h := range r.Hosts {
		var svcs []string
		for _, s := range h.Services {
			label := s.Label()
			if s.Port > 0 {
				svcs = append(svcs, fmt.Sprintf("%d/%s (%s)", s.Port, s.Protocol, label))
			}
		}
		data.Hosts = append(data.Hosts, htmlHost{
			IP: h.IP, Hostname: h.Hostname, OS: h.OSHint,
			Services: strings.Join(svcs, ", "), Open: len(h.Services),
		})
	}

	// Проверки локального хоста.
	for _, c := range r.HostAudit {
		stClass, status := "st-pass", "Пройдена"
		switch c.Status {
		case model.CheckFailed:
			stClass, status = "st-fail", "НЕ ПРОЙДЕНА"
		case model.CheckSkipped:
			stClass, status = "st-skip", "Пропущена"
		case model.CheckError:
			stClass, status = "st-skip", "Нет данных"
		}
		data.Checks = append(data.Checks, htmlCheck{
			Title: c.Title, Status: status, StClass: stClass,
			Value: c.Value, Category: c.Category.String(),
		})
	}

	var targets []string
	targets = append(targets, r.Config.Targets...)
	data.ConfigLine = fmt.Sprintf("Профиль: %s; цели: %s", r.Config.Profile.Name(), strings.Join(targets, ", "))

	tpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}
	return tpl.Execute(w, data)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Отчёт аудита защиты</title>
<style>
  :root { --critical:#c0392b; --high:#e67e22; --medium:#f1c40f; --low:#27ae60; --info:#7f8c8d; }
  * { box-sizing: border-box; }
  body { font-family: "Segoe UI", Tahoma, sans-serif; margin: 0; background: #f4f6f9; color: #222; }
  .container { max-width: 1100px; margin: 0 auto; padding: 24px; }
  header { background: linear-gradient(135deg,#16222a,#3a6073); color: #fff; padding: 32px 0; }
  header h1 { margin: 0 0 6px; font-size: 26px; }
  header .meta { opacity: .85; font-size: 14px; }
  .cards { display: flex; gap: 14px; flex-wrap: wrap; margin: -40px 24px 24px; }
  .card { background: #fff; border-radius: 10px; box-shadow: 0 3px 10px rgba(0,0,0,.12); padding: 18px 22px; flex: 1; min-width: 130px; text-align: center; }
  .card .num { font-size: 30px; font-weight: 700; }
  .card .lbl { font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: .5px; }
  .num.critical { color: var(--critical); } .num.high { color: var(--high); }
  .num.medium { color: var(--medium); } .num.low { color: var(--low); }
  .num.info { color: var(--info); } .num.hosts { color: #2c3e50; }
  .score-box { display: flex; align-items: center; gap: 18px; background: #fff; border-radius: 10px; padding: 22px; margin-bottom: 24px; box-shadow: 0 3px 10px rgba(0,0,0,.10); }
  .score { font-size: 52px; font-weight: 800; }
  .score-good { color: var(--low); } .score-warn { color: var(--high); } .score-bad { color: var(--critical); }
  h2 { margin: 34px 0 14px; padding-left: 12px; border-left: 5px solid #3a6073; font-size: 20px; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,.08); }
  th { background: #2c3e50; color: #fff; text-align: left; padding: 10px 12px; font-size: 13px; }
  td { padding: 10px 12px; border-top: 1px solid #eee; font-size: 13px; vertical-align: top; }
  tr:hover td { background: #f7fafc; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; color: #fff; font-size: 11px; font-weight: 600; }
  .sev-critical { background: var(--critical); } .sev-high { background: var(--high); }
  .sev-medium { background: var(--medium); color: #333; } .sev-low { background: var(--low); }
  .sev-info { background: var(--info); }
  .st-pass { color: var(--low); font-weight: 600; } .st-fail { color: var(--critical); font-weight: 600; }
  .st-skip { color: var(--info); }
  .rec { background: #eef7ee; border-left: 4px solid var(--low); padding: 8px 12px; margin-top: 8px; font-size: 12.5px; }
  .evid { color: #555; font-size: 12px; font-family: Consolas, monospace; background: #f4f4f4; padding: 6px 8px; border-radius: 4px; margin-top: 6px; word-break: break-all; }
  .cve { color: #8e44ad; font-weight: 600; }
  footer { text-align: center; color: #999; font-size: 12px; padding: 30px 0; }
  .cat-summary span { display: inline-block; background: #fff; border-radius: 8px; padding: 8px 16px; margin: 0 8px 8px 0; box-shadow: 0 2px 6px rgba(0,0,0,.08); font-size: 13px; }
</style>
</head>
<body>
<header>
  <div class="container">
    <h1>{{.Tool}}</h1>
    <div class="meta">Версия {{.Version}} · {{.Date}}<br>{{.ConfigLine}}</div>
  </div>
</header>

<div class="container">
  <div class="score-box">
    <div class="score {{.ScoreClass}}">{{.Score}}</div>
    <div>
      <div style="font-weight:700;font-size:16px;">Балл защищённости (100 — отлично)</div>
      <div style="color:#666;font-size:13px;">Оценка рассчитана по найденным уязвимостям: чем опаснее находки, тем ниже балл.</div>
    </div>
  </div>

  <div class="cards" style="margin: 0 0 24px;">
    <div class="card"><div class="num critical">{{.Critical}}</div><div class="lbl">Критические</div></div>
    <div class="card"><div class="num high">{{.High}}</div><div class="lbl">Высокие</div></div>
    <div class="card"><div class="num medium">{{.Medium}}</div><div class="lbl">Средние</div></div>
    <div class="card"><div class="num low">{{.Low}}</div><div class="lbl">Низкие</div></div>
    <div class="card"><div class="num info">{{.Info}}</div><div class="lbl">Информация</div></div>
    <div class="card"><div class="num hosts">{{.HostsCount}}</div><div class="lbl">Хостов проверено</div></div>
  </div>

  {{if .CatSummary}}
  <h2>Риски по категориям</h2>
  <div class="cat-summary">
    {{range .CatSummary}}<span><b>{{.Count}}</b> — {{.Name}}</span>{{end}}
  </div>
  {{end}}

  {{if .Findings}}
  <h2>Найденные уязвимости и отклонения ({{len .Findings}})</h2>
  <table>
    <tr><th style="width:110px;">Уровень</th><th>Находка</th><th style="width:170px;">Цель</th></tr>
    {{range .Findings}}
    <tr>
      <td><span class="badge {{.SevClass}}">{{.Severity}}</span></td>
      <td>
        <b>{{.Title}}</b>
        <div style="margin-top:4px;">{{.Description}}</div>
        {{if .Evidence}}<div class="evid">Подтверждение: {{.Evidence}}</div>{{end}}
        {{if .CVEs}}<div style="margin-top:4px;">CVE: <span class="cve">{{.CVEs}}</span>{{if .CVSS}} · CVSS {{.CVSS}}{{end}}</div>{{end}}
        <div class="rec"><b>Рекомендация:</b> {{.Recommend}}</div>
      </td>
      <td>{{.Target}}<br><span style="color:#888;font-size:12px;">{{.Category}}{{if .Service}} · {{.Service}}{{end}}</span></td>
    </tr>
    {{end}}
  </table>
  {{else}}
  <h2>Уязвимости не найдены</h2>
  <p>Проверенные системы не содержат известных уязвимостей и опасных экспозиций.</p>
  {{end}}

  {{if .Checks}}
  <h2>Аудит защищённости локального хоста</h2>
  <table>
    <tr><th>Проверка</th><th style="width:130px;">Результат</th><th style="width:220px;">Значение / категория</th></tr>
    {{range .Checks}}
    <tr>
      <td>{{.Title}}</td>
      <td class="{{.StClass}}">{{.Status}}</td>
      <td>{{.Value}}<br><span style="color:#888;font-size:12px;">{{.Category}}</span></td>
    </tr>
    {{end}}
  </table>
  {{end}}

  {{if .Hosts}}
  <h2>Проверенные хосты</h2>
  <table>
    <tr><th>IP-адрес</th><th>Имя хоста</th><th>ОС (по службам)</th><th style="width:45%;">Открытые службы ({{len .Hosts}} хостов)</th></tr>
    {{range .Hosts}}
    <tr>
      <td>{{.IP}}</td><td>{{.Hostname}}</td><td>{{.OS}}</td>
      <td>{{.Services}} <b style="color:#2c3e50;">[{{.Open}}]</b></td>
    </tr>
    {{end}}
  </table>
  {{end}}
</div>

<footer>Сформировано приложением «Аудит защиты» · {{.Date}} · Проверяйте только собственные сети и системы, на которые у вас есть разрешение.</footer>
</body>
</html>
`
