package vuln

import (
	"sort"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
)

// ScoreFindings вычисляет балл защищённости (100 — отлично, 0 — критическое состояние).
// Критические находки штрафуются сильнее по нелинейной шкале.
func ScoreFindings(findings []model.Finding) float64 {
	penalty := 0.0
	for _, f := range findings {
		w := f.Severity.Weight()
		if f.CVSS > 0 && f.Severity == model.SevCritical {
			w *= f.CVSS / 10.0
		}
		penalty += w
	}
	score := 100.0 - penalty
	if score < 0 {
		score = 0
	}
	return score
}

// ScoreByHost вычисляет балл защищённости для каждого хоста.
func ScoreByHost(findings []model.Finding) map[string]float64 {
	byHost := make(map[string][]model.Finding)
	for _, f := range findings {
		if f.Host != "" {
			byHost[f.Host] = append(byHost[f.Host], f)
		}
	}
	out := make(map[string]float64, len(byHost))
	for host, fs := range byHost {
		out[host] = ScoreFindings(fs)
	}
	return out
}

// SortFindings упорядочивает находки: сначала критические, затем по хосту и порту.
func SortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Port < b.Port
	})
}

// FindingFromCheck преобразует негативный результат проверки хоста в находку.
func FindingFromCheck(c model.CheckResult) model.Finding {
	f := model.NewFinding(
		"hostcheck-"+c.ID,
		c.Title, c.Description, c.Severity, c.Category, c.Recommendation)
	f.Evidence = c.Value
	f.Service = "локальный хост"
	f.Finalize()
	return f
}

// FindingsFromChecks формирует находки из проваленных проверок локального хоста.
func FindingsFromChecks(checks []model.CheckResult) []model.Finding {
	var out []model.Finding
	for _, c := range checks {
		if c.Status == model.CheckFailed {
			out = append(out, FindingFromCheck(c))
		}
	}
	return out
}
