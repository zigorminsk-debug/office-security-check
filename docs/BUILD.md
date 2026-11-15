# Сборка и CI/CD

## Автоматическая сборка (GitHub Actions)

Пайплайн: [`.github/workflows/build.yml`](../.github/workflows/build.yml).
Запускается при **каждом push** в любую ветку, при pull request и вручную
(Actions → build → Run workflow).

### Этапы

1. **`verify`** (ubuntu-latest)
   - `gofmt -l` — проверка форматирования всего кода;
   - `go vet` — статический анализ пакетов движка;
   - `go test -v ./internal/vuln ./internal/netutil` — юнит-тесты.

2. **`build-windows`** (windows-latest)
   - `go vet ./...` и `go test ./internal/...` — полная проверка, включая UI;
   - `windres` — сборка ресурсов Windows (иконка `app.ico`, манифест
     `app.manifest` с DPI-awareness PerMonitorV2 и Common Controls v6,
     блок версии файла) в `app.syso`, который подключается к exe автоматически;
   - `go build` — две сборки:
     - `SecurityAuditCLI.exe` — консольная версия;
     - `SecurityAudit.exe` — GUI-версия (`-H windowsgui`, без консольного окна);
   - **Smoke-тест**: запуск `-version`, аудита хоста и сканирования `127.0.0.1`;
   - **Inno Setup** (`choco install innosetup`) → `Setup-Audit-Zashchity.exe`;
   - Публикация артефактов `OfficeSecurityCheck-windows` (установщик + exe + пример отчёта).

3. **`release`** — при push тега `v*` создаётся GitHub Release с установщиком.

### Скачивание результатов сборки

**Actions** → выберите успешный запуск workflow **build** → внизу **Artifacts** →
`OfficeSecurityCheck-windows`.

## Локальная сборка

Требования: Go ≥ 1.21; для Windows-сборки — MinGW-w64 (gcc).

```bash
# Тесты движка (без UI)
go test ./internal/...

# Консольная версия (любая ОС)
go build -o security-audit .

# GUI для Windows (из Linux — через mingw)
CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
  go build -ldflags "-H windowsgui" -o SecurityAudit.exe .
```

## Структура файлов сборки

| Файл | Назначение |
|---|---|
| `build/windows/setup.iss` | Скрипт Inno Setup (установщик, RU/EN) |
| `build/windows/app.rc` | Ресурсы exe: иконка, манифест, версия |
| `build/windows/app.manifest` | Манифест Windows: DPI PerMonitorV2, Common Controls v6 |
| `build/windows/app.ico` | Иконка приложения |

## Версионирование

- Версия приложения зашивается через `-ldflags "-X main.version=..."`;
- в CI используется `1.0.0+build.<номер запуска>`;
- релизы помечаются тегами `v1.0.0`, `v1.1.0` и т.д. — это запускает job `release`.
