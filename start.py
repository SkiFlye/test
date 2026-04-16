#!/usr/bin/env python3
import asyncio
import threading
from proxy import waf_proxy
from app import app


def run_flask():
    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=False)


def run_proxy():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(waf_proxy.start())
    loop.run_forever()


if __name__ == '__main__':
    print("Запуск WAF сервиса...")
    print("Flask сайт: http://127.0.0.1:5000")
    print("WAF прокси: http://0.0.0.0:8080")
    print()

    proxy_thread = threading.Thread(target=run_proxy, daemon=True)
    proxy_thread.start()

    run_flask()