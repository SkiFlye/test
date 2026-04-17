#!/bin/bash

# Переходим в папку с проектом (корень)
cd /home/runner/${REPL_SLUG}

echo "=========================================="
echo "🛡️ Запуск WAF Сервиса на Replit"
echo "=========================================="

# Создаём виртуальное окружение если нет
if [ ! -d "venv" ]; then
    echo "📦 Создание виртуального окружения..."
    python3 -m venv venv
fi

# Активируем виртуальное окружение
source venv/bin/activate

# Обновляем pip
echo "📦 Обновление pip..."
pip install --upgrade pip

# Устанавливаем зависимости
if [ -f "requirements.txt" ]; then
    echo "📦 Установка зависимостей из requirements.txt..."
    pip install -r requirements.txt
else
    echo "❌ requirements.txt не найден!"
    exit 1
fi

echo "=========================================="
echo "🚀 Запуск приложения..."
echo "📊 Сайт (админка): порт 5000"
echo "🛡️ WAF прокси: порт 8080"
echo "=========================================="

# Запускаем приложение
python main.py