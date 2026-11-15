# Changelog

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/).

## [1.0.0] — 2026-11-15

### Добавлено
- Сканирование сети: обнаружение хостов, параллельный TCP-скан портов с профилями
  «Быстрый / Стандартный / Глубокий / Пользовательский».
- Определение служб: баннер-граббинг и фингерпринтинг 20+ продуктов.
- Аудит TLS: сертификаты, поддержка TLS 1.0–1.3, слабые шифры, Heartbleed (CVE-2014-0160).
- Проверки HTTP: заголовки безопасности, опасные пути, WebDAV, TRACE, открытый прокси,
  панели администрирования.
- Проверки SMB: SMBv1, подписывание, анонимный доступ, MS17-010/EternalBlue.
- Проверки RDP: обязательная NLA (CredSSP).
- Детекторы незащищённых служб: Redis, MongoDB, Elasticsearch, CouchDB, Memcached,
  MQTT, AMQP, Docker API, Kubernetes, kubelet, etcd, VNC, SNMP, FTP, SMTP, LDAP, TFTP.
- UDP-проверки: SNMP, DNS, TFTP, NTP.
- База знаний CVE: Apache, nginx, OpenSSH (regreSSHion), vsftpd, ProFTPD, Tomcat,
  PHP, IIS, Exim, Elasticsearch (Log4Shell), Jenkins, Struts.
- Аудит защищённости локального Windows-хоста: 20 проверок (Defender, брандмауэр,
  RDP/NLA, SMBv1, UAC, BitLocker, LLMNR/NBT-NS, WDigest и др.).
- Отчёты HTML / JSON / CSV с баллом защищённости и рекомендациями.
- Графический интерфейс (Fyne) и режим командной строки.
- Установщик Windows (setup.exe, Inno Setup) и пайплайн GitHub Actions.
