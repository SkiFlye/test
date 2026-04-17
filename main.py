import asyncio
import threading
from waitress import serve
from app import app
from proxy import waf_proxy


def run_flask():
    serve(app, host='0.0.0.0', port=5000)


def run_proxy():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(waf_proxy.start())
    loop.run_forever()  # ← БЛОКИРУЕТ выполнение


if __name__ == '__main__':
    # Запускаем Flask в фоне
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    # Запускаем прокси (блокирует)
    run_proxy()