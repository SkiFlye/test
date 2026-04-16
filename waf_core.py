import re
import time
from collections import defaultdict
from datetime import datetime, timedelta
from database import log_statistic, block_ip, is_ip_blocked, get_user_rules_enabled

# Правила безопасности (общие для всех пользователей)
RULES = [
    {"id": 1, "name": "SQL Injection - UNION SELECT", "pattern": re.compile(r"(?i)(union\s+select\s+.+from)"),
     "severity": "high"},
    {"id": 2, "name": "SQL Injection - OR/AND Injection",
     "pattern": re.compile(r"(?i)([\w']+\s+(or|and)\s+[\w']+\s*=\s*[\w']+)"), "severity": "high"},
    {"id": 3, "name": "SQL Injection - Comments", "pattern": re.compile(r"(?i)(--|\#|\/\*|\*\/)"),
     "severity": "medium"},
    {"id": 4, "name": "XSS - Script tag", "pattern": re.compile(r"(?i)(<script[^>]*>.*?</script>)"),
     "severity": "high"},
    {"id": 5, "name": "XSS - Event handlers", "pattern": re.compile(r"(?i)(on\w+\s*=\s*['\"]?[^'\">]*)"),
     "severity": "high"},
    {"id": 6, "name": "XSS - Javascript protocol", "pattern": re.compile(r"(?i)(javascript\s*:\s*)"),
     "severity": "high"},
    {"id": 7, "name": "Path Traversal - Unix", "pattern": re.compile(r"(\.\./|\.\.\\)"), "severity": "high"},
    {"id": 8, "name": "Command Injection", "pattern": re.compile(r"(\||;|\&\&|\$\(|`|\|&)"), "severity": "critical"},
    {"id": 9, "name": "Scanner detection",
     "pattern": re.compile(r"(sqlmap|nikto|nmap|acunetix|nessus|burp)", re.IGNORECASE), "severity": "medium"},
]


class RateLimiter:
    """Rate limiter для каждого пользователя"""

    def __init__(self):
        self.requests = defaultdict(list)  # user_id:ip -> [timestamps]

    def check_and_record(self, user_id, client_ip, limit_per_minute):
        """Проверить и записать запрос"""
        key = f"{user_id}:{client_ip}"
        current_time = time.time()

        # Очищаем старые записи
        self.requests[key] = [ts for ts in self.requests[key] if current_time - ts < 60]

        current_count = len(self.requests[key])
        allowed = current_count < limit_per_minute

        if allowed:
            self.requests[key].append(current_time)
            remaining = limit_per_minute - current_count - 1
        else:
            remaining = 0

        return allowed, remaining


class WAFCore:
    """Ядро WAF для проверки запросов"""

    def __init__(self):
        self.rate_limiter = RateLimiter()

    def check_request(self, user_id, method, path, headers, query_string):
        """Проверить запрос на атаки"""
        user_rules = get_user_rules_enabled(user_id)
        triggered_rules = []

        # Нормализуем данные
        import urllib.parse
        decoded_path = urllib.parse.unquote(path)
        decoded_query = urllib.parse.unquote(query_string or "")

        for rule in RULES:
            # Проверяем, включено ли правило у пользователя
            if str(rule["id"]) in user_rules and not user_rules[str(rule["id"])]:
                continue

            pattern = rule["pattern"]

            if pattern.search(decoded_path) or pattern.search(decoded_query):
                triggered_rules.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"]
                })

        return triggered_rules

    def check_rate_limit(self, user_id, client_ip, rate_limit):
        """Проверить rate limit"""
        return self.rate_limiter.check_and_record(user_id, client_ip, rate_limit)

    def process_request(self, user_id, client_ip, method, path, headers, query_string, rate_limit):
        """Обработать запрос и вернуть решение"""

        # 1. Проверка блокировки IP
        if is_ip_blocked(user_id, client_ip):
            log_statistic(user_id, "rate_limited", method, path, client_ip)
            return {"action": "block", "reason": "rate_limit", "status": 429}

        # 2. Проверка rate limit
        allowed, remaining = self.check_rate_limit(user_id, client_ip, rate_limit)
        if not allowed:
            block_ip(user_id, client_ip, 60, "Rate limit exceeded")
            log_statistic(user_id, "rate_limited", method, path, client_ip)
            return {"action": "block", "reason": "rate_limit", "status": 429}

        # 3. Проверка на атаки
        triggered_rules = self.check_request(user_id, method, path, headers, query_string)

        if triggered_rules:
            # Логируем атаку
            rule_names = [r["name"] for r in triggered_rules]
            log_statistic(user_id, "blocked", method, path, client_ip,
                          rule_names[0] if rule_names else None,
                          triggered_rules[0]["severity"] if triggered_rules else None)

            # При множественных атаках блокируем IP дольше
            # TODO: подсчет атак за последнее время
            return {
                "action": "block",
                "reason": "attack",
                "status": 403,
                "rules": triggered_rules
            }

        # 4. Обычный запрос
        log_statistic(user_id, "normal", method, path, client_ip)
        return {"action": "pass", "status": 200}


# Глобальный экземпляр
waf_core = WAFCore()