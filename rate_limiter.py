import time
from collections import defaultdict
from threading import Lock


class RateLimiter:
    """Rate limiter с скользящим окном"""

    def __init__(self, limit_per_minute=60):
        self.limit_per_minute = limit_per_minute
        self.requests = defaultdict(list)  # ip -> [timestamps]
        self.blocked_ips = {}  # ip -> block_until_timestamp
        self.lock = Lock()

    def is_blocked(self, client_ip):
        """Проверить, заблокирован ли IP"""
        if client_ip in self.blocked_ips:
            if time.time() < self.blocked_ips[client_ip]:
                return True
            else:
                # Снимаем блокировку
                del self.blocked_ips[client_ip]
        return False

    def block_ip(self, client_ip, duration_seconds=300):
        """Заблокировать IP на указанное время"""
        self.blocked_ips[client_ip] = time.time() + duration_seconds

    def unblock_ip(self, client_ip):
        """Разблокировать IP"""
        if client_ip in self.blocked_ips:
            del self.blocked_ips[client_ip]

    def get_blocked_ips(self):
        """Получить список заблокированных IP"""
        current_time = time.time()
        active_blocks = {}
        for ip, until in self.blocked_ips.items():
            if current_time < until:
                active_blocks[ip] = until
        return active_blocks

    def check_and_record(self, client_ip):
        """
        Проверить лимит и записать запрос
        Returns:
            tuple: (allowed, remaining_requests)
        """
        with self.lock:
            current_time = time.time()
            # Очищаем старые записи (старше 1 минуты)
            self.requests[client_ip] = [
                ts for ts in self.requests[client_ip]
                if current_time - ts < 60
            ]

            current_count = len(self.requests[client_ip])
            allowed = current_count < self.limit_per_minute

            if allowed:
                self.requests[client_ip].append(current_time)
                remaining = self.limit_per_minute - current_count - 1
            else:
                remaining = 0

            return allowed, remaining


# Глобальный экземпляр
rate_limiter = RateLimiter()