// Package netutil содержит вспомогательные функции для работы с сетью:
// разбор целей сканирования, параллельные TCP-проверки, ограничение скорости.
package netutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// ParseTargets разбирает список целей: IP, домены, CIDR, диапазоны "a.b.c.d-e.f.g.h".
// Возвращает отсортированный список уникальных IP-адресов и имён хостов.
func ParseTargets(input []string) ([]string, error) {
	seen := make(map[string]bool)
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, item := range input {
		for _, part := range strings.Split(item, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if strings.Contains(part, "/") {
				ips, err := expandCIDR(part)
				if err != nil {
					return nil, err
				}
				for _, ip := range ips {
					add(ip)
				}
				continue
			}
			if strings.Contains(part, "-") && isIPRange(part) {
				ips, err := expandRange(part)
				if err != nil {
					return nil, err
				}
				for _, ip := range ips {
					add(ip)
				}
				continue
			}
			add(part)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("не указаны цели сканирования")
	}
	sort.Strings(out)
	return out, nil
}

// isIPRange определяет, является ли строка диапазоном IP-адресов.
func isIPRange(s string) bool {
	idx := strings.LastIndex(s, "-")
	if idx <= 0 {
		return false
	}
	return net.ParseIP(s[:idx]) != nil
}

// expandCIDR разворачивает CIDR в список адресов (сетевой и широковещательный пропускаются).
func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("некорректный CIDR %q: %w", cidr, err)
	}
	var out []string
	for v := ip.Mask(ipnet.Mask); ipnet.Contains(v); incIP(v) {
		if v.IsLoopback() && !ip.IsLoopback() {
			continue
		}
		out = append(out, v.String())
		if len(out) > 65536 {
			return nil, fmt.Errorf("диапазон %q слишком велик (максимум 65536 адресов)", cidr)
		}
	}
	if len(out) > 2 {
		out = out[1 : len(out)-1] // убираем сеть и broadcast
	}
	return out, nil
}

// expandRange разворачивает диапазон "192.168.0.1-192.168.0.50" или "192.168.0.1-50".
func expandRange(r string) ([]string, error) {
	idx := strings.LastIndex(r, "-")
	start := strings.TrimSpace(r[:idx])
	end := strings.TrimSpace(r[idx+1:])
	startIP := net.ParseIP(start)
	if startIP == nil {
		return nil, fmt.Errorf("некорректный диапазон %q", r)
	}
	startIP = startIP.To4()
	if startIP == nil {
		return nil, fmt.Errorf("поддерживаются только IPv4 диапазоны: %q", r)
	}
	var endIP net.IP
	if e := net.ParseIP(end); e != nil && e.To4() != nil {
		endIP = e.To4()
	} else {
		last := net.ParseIP(startIP.String())
		b := last.To4()
		var n int
		if _, err := fmt.Sscanf(end, "%d", &n); err != nil || n < 1 || n > 255 {
			return nil, fmt.Errorf("некорректный диапазон %q", r)
		}
		b[3] = byte(n)
		endIP = b
	}
	var out []string
	for ip := cloneIP(startIP); !ipAfter(ip, endIP); incIP(ip) {
		out = append(out, ip.String())
		if len(out) > 65536 {
			return nil, fmt.Errorf("диапазон %q слишком велик", r)
		}
	}
	return out, nil
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

func ipAfter(a, b net.IP) bool {
	for i := 0; i < len(a); i++ {
		if a[i] > b[i] {
			return true
		}
		if a[i] < b[i] {
			return false
		}
	}
	return false
}

// ParsePorts разбирает спецификацию портов: "22,80,443", "1-1024", "80,8000-8100".
func ParsePorts(spec string) ([]int, error) {
	seen := make(map[int]bool)
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			var a, b int
			if _, err := fmt.Sscanf(part, "%d-%d", &a, &b); err != nil || a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("некорректный диапазон портов %q", part)
			}
			for p := a; p <= b; p++ {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
			continue
		}
		var p int
		if _, err := fmt.Sscanf(part, "%d", &p); err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("некорректный порт %q", part)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("не указаны порты")
	}
	sort.Ints(out)
	return out, nil
}

// DialTCP устанавливает TCP-соединение с тайм-аутом.
func DialTCP(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", addr)
}

// TCPReachable проверяет, открыт ли TCP-порт.
func TCPReachable(ctx context.Context, host string, port int, timeout time.Duration) bool {
	conn, err := DialTCP(ctx, fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// RateLimiter — простой ограничитель скорости (token bucket).
type RateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	last     time.Time
}

// NewRateLimiter создаёт ограничитель на n операций в секунду (0 = без ограничения).
func NewRateLimiter(perSec int) *RateLimiter {
	if perSec <= 0 {
		return &RateLimiter{interval: 0}
	}
	return &RateLimiter{interval: time.Second / time.Duration(perSec)}
}

// Wait блокируется до разрешения следующей операции.
func (r *RateLimiter) Wait(ctx context.Context) {
	if r.interval <= 0 {
		return
	}
	r.mu.Lock()
	wait := r.interval - time.Since(r.last)
	r.last = time.Now().Add(max0(wait))
	r.mu.Unlock()
	if wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
		}
	}
}

func max0(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	return d
}

// JoinHostPort собирает адрес вида host:port с корректной обработкой IPv6.
func JoinHostPort(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}
