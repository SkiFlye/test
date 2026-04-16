import logging
from logging.handlers import RotatingFileHandler
import config


def setup_logger():
    """Настройка логгера"""
    logger = logging.getLogger("WAF")
    logger.setLevel(logging.INFO)

    # Формат логов
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Файловый handler с ротацией
    file_handler = RotatingFileHandler(
        config.LOG_FILE,
        maxBytes=config.LOG_MAX_BYTES,
        backupCount=config.LOG_BACKUP_COUNT
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Консольный handler для отладки
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


# Глобальный логгер
waf_logger = setup_logger()


def log_attack(client_ip, method, url, rules_triggered, action="BLOCKED"):
    """Логирование атаки"""
    rules_str = ", ".join([f"{r['name']}({r['severity']})" for r in rules_triggered])
    waf_logger.warning(
        f"{action} - IP: {client_ip} | Method: {method} | URL: {url} | "
        f"Rules: {rules_str}"
    )


def log_request(client_ip, method, url, status_code):
    """Логирование обычного запроса"""
    waf_logger.info(f"PASS - IP: {client_ip} | {method} {url} | Status: {status_code}")


def log_rate_limit(client_ip, method, url):
    """Логирование rate limit"""
    waf_logger.warning(f"RATE_LIMIT - IP: {client_ip} | {method} {url}")