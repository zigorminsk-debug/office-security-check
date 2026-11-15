package netutil

import "testing"

func TestParseTargetsCIDR(t *testing.T) {
	hosts, err := ParseTargets([]string{"192.168.1.0/29"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 6 {
		t.Errorf("ожидалось 6 адресов (без сети и broadcast), получено %d: %v", len(hosts), hosts)
	}
}

func TestParseTargetsRange(t *testing.T) {
	hosts, err := ParseTargets([]string{"10.0.0.1-3"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 3 || hosts[0] != "10.0.0.1" || hosts[2] != "10.0.0.3" {
		t.Errorf("неожиданный результат: %v", hosts)
	}
}

func TestParseTargetsMixed(t *testing.T) {
	hosts, err := ParseTargets([]string{"192.168.0.5, 192.168.0.5, 10.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Errorf("дубликаты должны удаляться: %v", hosts)
	}
}

func TestParsePorts(t *testing.T) {
	ports, err := ParsePorts("22,80-82,443")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 5 {
		t.Errorf("ожидалось 5 портов, получено %d", len(ports))
	}
	if ports[0] != 22 || ports[4] != 443 {
		t.Errorf("неожиданный порядок: %v", ports)
	}
}

func TestParsePortsInvalid(t *testing.T) {
	if _, err := ParsePorts("70000"); err == nil {
		t.Error("порт 70000 должен отклоняться")
	}
	if _, err := ParsePorts("100-50"); err == nil {
		t.Error("обратный диапазон должен отклоняться")
	}
}
