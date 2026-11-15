package vuln

import (
	"testing"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
)

func TestNormalizeVersion(t *testing.T) {
	cases := map[string]string{
		"2.4.49":        "2.4.49",
		"2.4.49 (Unix)": "2.4.49",
		"8.0p1":         "8.0",
		"1.3.5":         "1.3.5",
		" 7.5 ":         "7.5",
		"nginx/1.18.0":  "",
		"":              "",
	}
	for in, want := range cases {
		if got := NormalizeVersion(in); got != want {
			t.Errorf("NormalizeVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.4.49", "2.4.50", -1},
		{"2.4.50", "2.4.49", 1},
		{"2.4.49", "2.4.49", 0},
		{"8.0", "7.9", 1},
		{"1.3.5", "1.3.6", -1},
		{"9.7", "9.8", -1},
		{"2.4", "2.4.1", -1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestMatchSignaturesApache(t *testing.T) {
	// 2.4.49 затронута CVE-2021-41773.
	found := MatchSignatures("apache", "2.4.49")
	ids := map[string]bool{}
	for _, s := range found {
		ids[s.ID] = true
	}
	if !ids["apache-cve-2021-41773"] {
		t.Error("ожидалась сигнатура apache-cve-2021-41773 для версии 2.4.49")
	}
	// 2.4.62 безопасна.
	for _, s := range MatchSignatures("apache", "2.4.62") {
		if s.ID == "apache-cve-2021-41773" || s.ID == "apache-cve-2024-38474" {
			t.Errorf("версия 2.4.62 не должна попадать под %s", s.ID)
		}
	}
}

func TestMatchSignaturesRegreSSHion(t *testing.T) {
	found := MatchSignatures("openssh", "9.6p1")
	ok := false
	for _, s := range found {
		if s.ID == "openssh-cve-2024-6387" {
			ok = true
		}
	}
	if !ok {
		t.Error("OpenSSH 9.6p1 должна попадать под CVE-2024-6387")
	}
	if len(MatchSignatures("openssh", "9.8p1")) != 0 {
		t.Error("OpenSSH 9.8p1 не должна попадать под сигнатуры")
	}
}

func TestEvaluateServiceRules(t *testing.T) {
	svc := &model.Service{
		Host: "192.168.1.10", Port: 445, Protocol: "tcp", Name: "smb",
		Extra: map[string]string{"smb_v1": "true", "ms17_010": "vulnerable", "smb_signing_required": "false"},
	}
	findings := EvaluateService(svc)
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.CheckID] = true
		if f.Recommendation == "" {
			t.Errorf("у находки %s отсутствует рекомендация", f.CheckID)
		}
	}
	for _, want := range []string{"smb-v1-enabled", "ms17-010-vulnerable", "smb-signing-not-required"} {
		found := false
		for id := range ids {
			if len(id) >= len(want) && id[:len(want)] == want {
				found = true
			}
		}
		if !found {
			t.Errorf("ожидалось правило %s, получено: %v", want, ids)
		}
	}
}

func TestScoreFindings(t *testing.T) {
	clean := ScoreFindings(nil)
	if clean != 100 {
		t.Errorf("пустой список должен давать 100, получено %.0f", clean)
	}
	crit := []model.Finding{model.NewFinding("x", "t", "d", model.SevCritical, model.CatRansomware, "r")}
	if s := ScoreFindings(crit); s >= 100 {
		t.Errorf("критическая находка должна снижать балл, получено %.0f", s)
	}
}
