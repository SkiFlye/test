import asyncio
import aiohttp
from aiohttp import web
import urllib.parse

# Импорты из вашего проекта
from database import get_user_by_api_key, log_statistic, block_ip, is_ip_blocked
from waf_core import waf_core

# Конфигурация
PROXY_HOST = "0.0.0.0"
PROXY_PORT = 8080
UPSTREAM_HOST = "httpbin.org"
UPSTREAM_PORT = 80
UPSTREAM_SSL = False


class WAFProxy:
    """Асинхронный прокси-сервер"""

    def __init__(self):
        self.proxy_host = PROXY_HOST
        self.proxy_port = PROXY_PORT
        self.upstream_host = UPSTREAM_HOST
        self.upstream_port = UPSTREAM_PORT
        self.upstream_ssl = UPSTREAM_SSL
        self.session = None
        self.app = None
        self.runner = None

    async def start(self):
        self.session = aiohttp.ClientSession()
        self.app = web.Application()
        self.app.router.add_route('*', '/{path:.*}', self.handle_request)

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.proxy_host, self.proxy_port)
        await site.start()

        print(f"✅ WAF Proxy запущен на http://{self.proxy_host}:{self.proxy_port}")
        print(f"📡 Проксирует запросы на http://{self.upstream_host}:{self.upstream_port}")

    async def stop(self):
        if self.session:
            await self.session.close()
        if self.runner:
            await self.runner.cleanup()

    async def handle_request(self, request):
        """Обработка входящего запроса"""

        # Получаем API-ключ из заголовка
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return web.Response(status=401, text="Missing API Key")

        # Ищем пользователя (теперь user - это словарь)
        user = get_user_by_api_key(api_key)
        if not user:
            return web.Response(status=401, text="Invalid API Key")

        client_ip = request.remote
        method = request.method
        path = request.path
        query_string = request.query_string

        # Получаем данные из словаря user
        user_id = user['id']  # ← используем словарь, а не объект
        rate_limit = user.get('rate_limit', 60)

        # Проверяем блокировку IP
        if is_ip_blocked(user_id, client_ip):
            log_statistic(user_id, "rate_limited", method, path, client_ip)
            return web.Response(
                status=429,
                text="<h1>429 Too Many Requests</h1><p>IP temporarily blocked.</p>",
                content_type="text/html"
            )

        # Проверяем через WAF core
        result = waf_core.process_request(
            user_id=user_id,
            client_ip=client_ip,
            method=method,
            path=path,
            headers=dict(request.headers),
            query_string=query_string,
            rate_limit=rate_limit
        )

        if result["action"] == "block":
            if result.get("reason") == "attack":
                rules_html = "".join([f"<li>{r['name']}</li>" for r in result.get("rules", [])])
                return web.Response(
                    status=result.get("status", 403),
                    text=f"<h1>403 Forbidden</h1><p>Request blocked by WAF</p><ul>{rules_html}</ul>",
                    content_type="text/html"
                )
            else:
                return web.Response(
                    status=result.get("status", 429),
                    text="<h1>429 Too Many Requests</h1><p>Rate limit exceeded.</p>",
                    content_type="text/html"
                )

        # Проксируем запрос к upstream серверу
        try:
            # Строим URL для upstream
            scheme = "https" if self.upstream_ssl else "http"
            upstream_url = f"{scheme}://{self.upstream_host}:{self.upstream_port}{path}"
            if query_string:
                upstream_url += f"?{query_string}"

            # Подготавливаем заголовки (убираем X-API-Key и Host)
            forward_headers = {k: v for k, v in request.headers.items()
                               if k.lower() not in ['host', 'x-api-key', 'content-length']}
            forward_headers['Host'] = f"{self.upstream_host}:{self.upstream_port}"

            # Читаем тело для POST/PUT запросов
            body = None
            if method in ['POST', 'PUT', 'PATCH']:
                body = await request.read()

            # Отправляем запрос к upstream
            async with self.session.request(
                    method=method,
                    url=upstream_url,
                    headers=forward_headers,
                    data=body,
                    timeout=aiohttp.ClientTimeout(total=30)
            ) as upstream_response:
                response_body = await upstream_response.read()

                # Логируем успешный запрос
                log_statistic(user_id, "normal", method, path, client_ip)

                # Возвращаем ответ
                return web.Response(
                    status=upstream_response.status,
                    headers={k: v for k, v in upstream_response.headers.items()
                             if k.lower() not in ['content-encoding', 'content-length']},
                    body=response_body
                )

        except asyncio.TimeoutError:
            return web.Response(
                status=504,
                text="<h1>504 Gateway Timeout</h1><p>Upstream server did not respond.</p>",
                content_type="text/html"
            )
        except Exception as e:
            print(f"Proxy error: {e}")
            return web.Response(
                status=502,
                text=f"<h1>502 Bad Gateway</h1><p>Error: {str(e)}</p>",
                content_type="text/html"
            )


# Глобальный экземпляр
waf_proxy = WAFProxy()