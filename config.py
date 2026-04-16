# Конфигурация WAF сервиса

# Прокси сервер
PROXY_HOST = "0.0.0.0"
PROXY_PORT = 8080

# Upstream сервер (куда проксируем запросы)
UPSTREAM_HOST = "httpbin.org"  # тестовый сервер
UPSTREAM_PORT = 80
UPSTREAM_SSL = False  # httpbin.org использует http

# Для локального тестирования можно раскомментировать:
# UPSTREAM_HOST = "localhost"
# UPSTREAM_PORT = 8000
# UPSTREAM_SSL = False

# Flask админка
FLASK_HOST = "127.0.0.1"  # только localhost для безопасности
FLASK_PORT = 5000
FLASK_DEBUG = True

# Rate Limiting
RATE_LIMIT = 60  # запросов в минуту

# Логи
LOG_FILE = "waf.log"
LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 3