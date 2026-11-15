package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/zigorminsk-debug/office-security-check/internal/model"
	"github.com/zigorminsk-debug/office-security-check/internal/netutil"
)

// Progress — информация о ходе сканирования для интерфейса пользователя.
type Progress struct {
	Phase   string
	Current int
	Total   int
	Message string
}

// ProgressFunc — обратный вызов хода сканирования.
type ProgressFunc func(p Progress)

// Engine — движок сканирования сети.
type Engine struct {
	Cfg      model.ScanConfig
	Progress ProgressFunc
}

// Run выполняет полный цикл сканирования и возвращает обнаруженные хосты.
func (e *Engine) Run(ctx context.Context) ([]model.Host, error) {
	targets, err := netutil.ParseTargets(e.Cfg.Targets)
	if err != nil {
		return nil, err
	}
	ports := e.Cfg.Ports
	if len(ports) == 0 {
		ports = DefaultConfig(e.Cfg.Profile).Ports
	}

	// Фаза 1: обнаружение активных хостов.
	hosts := e.discover(ctx, targets)

	// Фаза 2: сканирование портов.
	e.scanAllPorts(ctx, hosts, ports)

	// Фаза 3: протокольные проверки открытых служб.
	e.probeServices(ctx, hosts)

	// Фаза 4: UDP-проверки (глубокий профиль).
	if e.Cfg.UDP {
		e.probeUDP(ctx, hosts)
	}

	// Косвенное определение ОС по набору открытых служб.
	for i := range hosts {
		hosts[i].OSHint = osHintFromServices(&hosts[i])
	}

	return hosts, nil
}

func (e *Engine) report(p Progress) {
	if e.Progress != nil {
		e.Progress(p)
	}
}

// discover обнаруживает активные хосты (TCP-ping по ключевым портам + обратный DNS).
func (e *Engine) discover(ctx context.Context, targets []string) []model.Host {
	probePorts := []int{445, 443, 80, 135, 22, 139, 3389, 8080, 21, 23}
	timeout := e.Cfg.Timeout
	if timeout > 600*time.Millisecond {
		timeout = 600 * time.Millisecond
	}

	hosts := make([]model.Host, len(targets))
	for i, t := range targets {
		hosts[i] = model.Host{IP: t}
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	found := make([]bool, len(targets))

	for i := range hosts {
		if ctx.Err() != nil {
			break
		}
		if e.Cfg.SkipDiscovery {
			found[i] = true
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			h := &hosts[idx]
			start := time.Now()
			for _, port := range probePorts {
				if ctx.Err() != nil {
					return
				}
				if netutil.TCPReachable(ctx, h.IP, port, timeout) {
					found[idx] = true
					h.LatencyMS = time.Since(start).Milliseconds()
					break
				}
			}
			// Хосты с именами считаем активными (DNS уже разрешил имя).
			if !found[idx] {
				if ip := net.ParseIP(h.IP); ip == nil {
					found[idx] = true
				}
			}
			if found[idx] {
				h.Alive = true
				if addr, err := net.LookupAddr(h.IP); err == nil && len(addr) > 0 {
					h.Hostname = addr[0]
				}
			}
			e.report(Progress{Phase: "discovery", Current: idx + 1, Total: len(targets),
				Message: fmt.Sprintf("Проверка хоста %s", h.IP)})
		}(i)
	}
	wg.Wait()

	var alive []model.Host
	for _, h := range hosts {
		if h.Alive {
			alive = append(alive, h)
		}
	}
	sort.Slice(alive, func(i, j int) bool { return alive[i].IP < alive[j].IP })
	return alive
}

// scanAllPorts сканирует порты всех хостов параллельно.
func (e *Engine) scanAllPorts(ctx context.Context, hosts []model.Host, ports []int) {
	total := len(hosts) * len(ports)
	if total == 0 {
		return
	}
	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		done      int
		lastPct   int
		limiter   = netutil.NewRateLimiter(e.Cfg.RatePerSec)
		sem       = make(chan struct{}, e.Cfg.Workers)
		bannerSem = make(chan struct{}, 64)
	)
	for hi := range hosts {
		for _, port := range ports {
			if ctx.Err() != nil {
				wg.Wait()
				return
			}
			wg.Add(1)
			sem <- struct{}{}
			limiter.Wait(ctx)
			go func(hi, port int) {
				defer wg.Done()
				defer func() { <-sem }()
				host := &hosts[hi]
				addr := netutil.JoinHostPort(host.IP, port)
				conn, err := netutil.DialTCP(ctx, addr, e.Cfg.Timeout)
				mu.Lock()
				done++
				pct := done * 100 / total
				if pct != lastPct || done == total {
					lastPct = pct
					e.report(Progress{Phase: "ports", Current: done, Total: total,
						Message: fmt.Sprintf("Сканирование портов: %d/%d (%d%%)", done, total, pct)})
				}
				mu.Unlock()
				if err != nil {
					return
				}
				svc := model.Service{
					Host: host.IP, Port: port, Protocol: "tcp", State: "open",
					Name: serviceByPort(port),
				}
				if svc.Name == "" {
					svc.Name = "unknown"
				}
				// Сбор баннера и определение службы.
				bannerSem <- struct{}{}
				banner, product, version := grabAndFingerprint(ctx, conn, port)
				<-bannerSem
				svc.Banner, svc.Product, svc.Version = banner, product, version
				if svc.Product != "" && (svc.Name == "unknown" || svc.Name == "http-alt") {
					svc.Name = canonicalService(product)
				}
				mu.Lock()
				host.Services = append(host.Services, svc)
				mu.Unlock()
			}(hi, port)
		}
	}
	wg.Wait()

	// Сортировка служб по порту.
	for hi := range hosts {
		sort.Slice(hosts[hi].Services, func(i, j int) bool {
			return hosts[hi].Services[i].Port < hosts[hi].Services[j].Port
		})
	}
}

// probeServices выполняет протокольные проверки для открытых служб.
func (e *Engine) probeServices(ctx context.Context, hosts []model.Host) {
	type task struct {
		hostIdx, svcIdx int
	}
	var tasks []task
	for hi := range hosts {
		for si := range hosts[hi].Services {
			tasks = append(tasks, task{hi, si})
		}
	}
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		done    int
		lastPct int
	)
	sem := make(chan struct{}, 48)
	for _, t := range tasks {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t task) {
			defer wg.Done()
			defer func() { <-sem }()
			svc := &hosts[t.hostIdx].Services[t.svcIdx]
			e.runProbes(ctx, svc)
			mu.Lock()
			done++
			pct := done * 100 / len(tasks)
			if pct != lastPct || done == len(tasks) {
				lastPct = pct
				e.report(Progress{Phase: "probes", Current: done, Total: len(tasks),
					Message: fmt.Sprintf("Проверка служб: %d/%d", done, len(tasks))})
			}
			mu.Unlock()
		}(t)
	}
	wg.Wait()
}

// osHintFromServices определяет семейство ОС по набору открытых служб (эвристика).
func osHintFromServices(h *model.Host) string {
	win, unix, mac := 0, 0, 0
	for _, s := range h.Services {
		switch s.Port {
		case 135, 139, 445, 3389, 5985, 5986, 1433, 1434:
			win++
		case 548, 631, 5000, 5001:
			mac++
		case 22, 111, 2049, 3306, 5432, 6379, 27017, 9200:
			unix++
		}
	}
	if s := findService(h, 445); s != nil && s.Product == "microsoft-ds" {
		win += 2
	}
	switch {
	case win >= unix && win >= mac && win > 0:
		return "Windows (по службам)"
	case mac > win && mac >= unix:
		return "macOS (по службам)"
	case unix > 0:
		return "Linux/Unix (по службам)"
	default:
		return ""
	}
}

// findService возвращает службу по порту.
func findService(h *model.Host, port int) *model.Service {
	for i := range h.Services {
		if h.Services[i].Port == port {
			return &h.Services[i]
		}
	}
	return nil
}
