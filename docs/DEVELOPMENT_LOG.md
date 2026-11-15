# Журнал разработки

Все действия по созданию приложения «Аудит защиты» (Office Security Check).

## 2026-11-15 — Этап 1. Исследование и проектирование

1. **Исследование темы.** Изучены современные методы обнаружения уязвимостей:
   - параллельное сканирование портов на Go (goroutines + worker pools + rate limiting);
   - баннер-граббинг и сервисный фингерпринтинг (аналог Nmap `-sV`);
   - сигнатурные базы CVE с сопоставлением версий (аналог NSE/Vulners);
   - протокольные детекторы: MS17-010/EternalBlue, Heartbleed, RDP-NLA, SMBv1;
   - атаки шифровальщиков 2023–2025: векторы RDP, SMB, незащищённые Redis/MongoDB/
     Elasticsearch, Docker API — включены в модель категорий риска.
2. **Проектирование архитектуры** (см. docs/ARCHITECTURE.md): разделение на движок,
   базу знаний, аудит хоста, отчёты и UI.
3. **Решения:**
   - Go + Fyne v2.7.4 (кроссплатформенный GUI, go.mod `go 1.21`);
   - проверки только в режиме обнаружения (без эксплуатации);
   - сборка исключительно на GitHub Actions (windows-latest + MinGW + Inno Setup).

## 2026-11-15 — Этап 2. Ядро приложения

4. `internal/model` — типы находок, уровни опасности, категории риска
   (Заражение вирусами / Несанционированный доступ / Шифрование данных).
5. `internal/netutil` — разбор целей (IP/CIDR/диапазоны), портов, RateLimiter.
6. `internal/vuln` — база знаний (18 сигнатур CVE), 40+ правил экспозиции,
   движок сопоставления версий, скоринг. Юнит-тесты.
7. `internal/scanner` — движок: discovery, TCP-скан, баннеры, фингерпринтинг,
   протокольные проверки SMB/RDP/TLS/HTTP/Redis/Mongo/ES/Memcached/MQTT/AMQP/
   FTP/SMTP/LDAP/VNC/Docker/K8s/etcd + UDP (SNMP/DNS/TFTP/NTP).
8. `internal/hostcheck` — 20 проверок Windows-хоста (Defender, Firewall, RDP/NLA,
   SMBv1, UAC, BitLocker, LLMNR, WDigest и др.).
9. `internal/report` — HTML/JSON/CSV отчёты с баллом защищённости.
10. `internal/ui` — GUI Fyne: вкладки «Уязвимости», «Хосты», «Аудит хоста», «Журнал»,
    индикатор прогресса, экспорт отчётов, диалог «О программе» с юридическим уведомлением.
11. `main.go` — режимы GUI и CLI (`-cli`, `-targets`, `-profile`, `-ports`,
    `-json/-html/-csv`, `-host-audit`).

## 2026-11-15 — Этап 3. Система сборки

12. `build/windows/app.rc` + `app.manifest` + `app.ico` — ресурсы Windows
    (иконка, DPI PerMonitorV2, Common Controls v6, версия файла).
13. `build/windows/setup.iss` — установщик Inno Setup (русский + английский языки,
    ярлыки, деинсталлятор).
14. `.github/workflows/build.yml` — пайплайн: проверка кода → сборка Windows →
    smoke-тест → setup.exe → артефакты; релиз по тегам `v*`.
15. Документация: README.md, docs/ARCHITECTURE.md, docs/CHECKS.md, docs/BUILD.md,
    CHANGELOG.md, SECURITY.md, LICENSE.

## Технологии обнаружения уязвимостей (реализовано)

| Технология | Реализация |
|---|---|
| Параллельное сканирование | Worker pool (256–512 потоков) + token-bucket rate limiter |
| Фингерпринтинг служб | Баннер-граббинг + регулярные выражения (20+ продуктов) |
| CVE-сопоставление | База знаний: диапазоны версий → CVE/CVSS/рекомендация |
| Детект EternalBlue | SMB1 NEGOTIATE + SESSION_SETUP + TRANS_PEEK_NMPIPE (статус-код) |
| Детект Heartbleed | ClientHello + heartbeat-запрос с завышенной длиной (raw TLS-записи) |
| Аудит TLS | crypto/tls + raw ClientHello: версии 1.0–1.3, слабые шифры, сертификаты |
| RDP-аудит | X.224/RDP Negotiation: CredSSP/NLA vs Standard Security |
| HTTP-аудит | Заголовки, опасные пути, WebDAV, TRACE, open proxy, админ-панели |
| Рансомвар-векторы | Категория «Шифрование данных»: RDP, SMB, Redis/Mongo/ES, Docker API |
| Аудит защищённости хоста | 20 политик Windows (Defender, Firewall, UAC, BitLocker…) |
| Скоринг | Нелинейная шкала 0–100 с учётом CVSS |
