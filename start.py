#!/usr/bin/env python3
import asyncio
import threading
import os
import sys

# Добавляем текущую директорию в путь
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from waitress import serve
from app import app
from proxy import waf_proxy


def run_proxy():
    """Запуск асинхронного прокси в отдельном потоке"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    print("🔄 Запуск WAF прокси...")
    loop.run_until_complete(waf_proxy.start())
    print("✅ WAF прокси запущен на порту 8080")

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("🛑 Остановка прокси...")
        loop.run_until_complete(waf_proxy.stop())
    finally:
        loop.close()


def main():
    """Главная функция"""
    print("=" * 50)
    print("🛡️ WAF Сервис запущен на Replit")
    print("=" * 50)

    # Получаем URL Replit
    repl_slug = os.environ.get('REPL_SLUG', 'waf-service')
    repl_owner = os.environ.get('REPL_OWNER', 'user')
    public_url = f"https://{repl_slug}.{repl_owner}.repl.co"

    print(f"📊 Админка: {public_url}")
    print(f"🔗 WAF прокси (внутренний): http://0.0.0.0:8080")
    print(f"🔑 API-ключи выдаются после регистрации")
    print("=" * 50)

    # Запускаем прокси в фоновом потоке
    proxy_thread = threading.Thread(target=run_proxy, daemon=True)
    proxy_thread.start()

    # Запускаем Flask через waitress (production-ready)
    print("🚀 Запуск Flask сервера через waitress на порту 5000...")
    serve(app, host='0.0.0.0', port=5000, threads=4)


if __name__ == '__main__':
    main()