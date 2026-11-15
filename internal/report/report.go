// Package report формирует итоговый отчёт аудита в форматах JSON, HTML и CSV.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
	"github.com/zigorminsk-debug/office-security-check/internal/vuln"
)

// Build собирает отчёт из результатов сканирования и проверок хоста.
func Build(version string, cfg model.ScanConfig, hosts []model.Host,
	findings []model.Finding, hostAudit []model.CheckResult) *model.Report {

	vuln.SortFindings(findings)
	for i := range findings {
		findings[i].Finalize()
	}
	r := &model.Report{
		Tool:        "Аудит защиты (Office Security Check)",
		Version:     version,
		GeneratedAt: time.Now(),
		Config:      cfg,
		Hosts:       hosts,
		Findings:    findings,
		HostAudit:   hostAudit,
		Score:       vuln.ScoreFindings(findings),
	}
	r.FillCounts()
	return r
}

// WriteJSON сохраняет отчёт в формате JSON.
func WriteJSON(r *model.Report, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return WriteJSONTo(f, r)
}

// WriteJSONTo записывает отчёт JSON в произвольный поток.
func WriteJSONTo(w io.Writer, r *model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteCSV сохраняет находки в формате CSV (разделитель «;» для Excel).
func WriteCSV(r *model.Report, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return WriteCSVTo(f, r)
}

// WriteCSVTo записывает находки CSV в произвольный поток.
func WriteCSVTo(w io.Writer, r *model.Report) error {
	// BOM для корректного открытия в Excel.
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
	cw := csv.NewWriter(w)
	cw.Comma = ';'
	_ = cw.Write([]string{
		"Уровень", "Категория", "Хост", "Порт", "Служба", "Уязвимость",
		"Описание", "CVE", "CVSS", "Рекомендация",
	})
	for _, fnd := range r.Findings {
		cves := ""
		for i, c := range fnd.CVEs {
			if i > 0 {
				cves += ", "
			}
			cves += c
		}
		_ = cw.Write([]string{
			fnd.Severity.String(), fnd.Category.String(), fnd.Host,
			strconv.Itoa(fnd.Port), fnd.Service, fnd.Title,
			fnd.Description, cves, fmt.Sprintf("%.1f", fnd.CVSS), fnd.Recommendation,
		})
	}
	cw.Flush()
	return cw.Error()
}
