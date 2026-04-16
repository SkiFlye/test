from flask import Flask, render_template_string, jsonify, request
import threading
from logger import waf_logger
from rules import get_rules, get_rule, toggle_rule
from rate_limiter import rate_limiter
import config

app = Flask(__name__)

# HTML шаблоны
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>WAF Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .stats { display: flex; gap: 20px; flex-wrap: wrap; }
        .stat { flex: 1; text-align: center; padding: 20px; background: #e3f2fd; border-radius: 8px; }
        .stat-value { font-size: 36px; font-weight: bold; color: #1976d2; }
        .stat-label { color: #666; margin-top: 10px; }
        .button { background: #1976d2; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; }
        .button:hover { background: #1565c0; }
        .rule-item { padding: 10px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .rule-enabled { color: green; font-weight: bold; }
        .rule-disabled { color: red; }
        .severity-high { color: #d32f2f; }
        .severity-medium { color: #f57c00; }
        .severity-low { color: #388e3c; }
        nav { margin-bottom: 20px; }
        nav a { margin-right: 15px; text-decoration: none; color: #1976d2; }
        pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ WAF Management Console</h1>
        <nav>
            <a href="/">Dashboard</a>
            <a href="/logs">Logs</a>
            <a href="/rules">Rules</a>
            <a href="/blocked_ips">Blocked IPs</a>
        </nav>

        <div class="card">
            <h2>Statistics</h2>
            <div class="stats" id="stats">
                Loading...
            </div>
        </div>

        <div class="card">
            <h2>Recent Alerts</h2>
            <pre id="alerts">Loading...</pre>
        </div>
    </div>

    <script>
        function fetchStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    const statsHtml = `
                        <div class="stat">
                            <div class="stat-value">${data.total_requests}</div>
                            <div class="stat-label">Total Requests</div>
                        </div>
                        <div class="stat">
                            <div class="stat-value">${data.blocked_requests}</div>
                            <div class="stat-label">Blocked Requests</div>
                        </div>
                        <div class="stat">
                            <div class="stat-value">${data.active_rules}</div>
                            <div class="stat-label">Active Rules</div>
                        </div>
                        <div class="stat">
                            <div class="stat-value">${data.blocked_ips}</div>
                            <div class="stat-label">Blocked IPs</div>
                        </div>
                    `;
                    document.getElementById('stats').innerHTML = statsHtml;
                });
        }

        function fetchAlerts() {
            fetch('/api/recent_alerts')
                .then(response => response.json())
                .then(data => {
                    const alertsHtml = data.alerts.map(alert => 
                        `[${alert.time}] ${alert.message}`
                    ).join('\\n') || 'No recent alerts';
                    document.getElementById('alerts').innerText = alertsHtml;
                });
        }

        fetchStats();
        fetchAlerts();
        setInterval(fetchStats, 5000);
        setInterval(fetchAlerts, 5000);
    </script>
</body>
</html>
"""

LOGS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>WAF Logs</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        nav { margin-bottom: 20px; }
        nav a { margin-right: 15px; text-decoration: none; color: #1976d2; }
        pre { background: #1e1e1e; color: #d4d4d4; padding: 15px; overflow-x: auto; border-radius: 4px; font-size: 12px; max-height: 600px; overflow-y: auto; }
        .button { background: #1976d2; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin-right: 10px; }
        .button:hover { background: #1565c0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📋 WAF Logs</h1>
        <nav>
            <a href="/">Dashboard</a>
            <a href="/logs">Logs</a>
            <a href="/rules">Rules</a>
            <a href="/blocked_ips">Blocked IPs</a>
        </nav>

        <div class="card">
            <button class="button" onclick="refreshLogs()">Refresh</button>
            <button class="button" onclick="clearLogs()">Clear Logs</button>
            <pre id="logs">Loading...</pre>
        </div>
    </div>

    <script>
        function fetchLogs() {
            fetch('/api/logs')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('logs').innerText = data.logs || 'No logs available';
                });
        }

        function refreshLogs() {
            fetchLogs();
        }

        function clearLogs() {
            fetch('/api/clear_logs', { method: 'POST' })
                .then(() => fetchLogs());
        }

        fetchLogs();
        setInterval(fetchLogs, 3000);
    </script>
</body>
</html>
"""

RULES_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>WAF Rules</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        nav { margin-bottom: 20px; }
        nav a { margin-right: 15px; text-decoration: none; color: #1976d2; }
        .rule-item { padding: 12px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .rule-item:hover { background: #f9f9f9; }
        .rule-info { flex: 1; }
        .rule-name { font-weight: bold; }
        .rule-details { font-size: 12px; color: #666; margin-top: 4px; }
        .severity-high { color: #d32f2f; font-weight: bold; }
        .severity-medium { color: #f57c00; font-weight: bold; }
        .severity-critical { color: #b71c1c; font-weight: bold; }
        .toggle-btn { padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
        .toggle-enabled { background: #4caf50; color: white; }
        .toggle-disabled { background: #f44336; color: white; }
        .button { background: #1976d2; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin-bottom: 20px; }
        .button:hover { background: #1565c0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚙️ WAF Rules Management</h1>
        <nav>
            <a href="/">Dashboard</a>
            <a href="/logs">Logs</a>
            <a href="/rules">Rules</a>
            <a href="/blocked_ips">Blocked IPs</a>
        </nav>

        <div class="card">
            <button class="button" onclick="refreshRules()">Refresh</button>
            <div id="rules-list">Loading...</div>
        </div>
    </div>

    <script>
        function refreshRules() {
            fetch('/api/rules')
                .then(response => response.json())
                .then(data => {
                    const rulesHtml = data.rules.map(rule => `
                        <div class="rule-item">
                            <div class="rule-info">
                                <div class="rule-name">${rule.name}</div>
                                <div class="rule-details">
                                    Target: ${rule.target} | Severity: <span class="severity-${rule.severity}">${rule.severity}</span> | ID: ${rule.id}
                                </div>
                            </div>
                            <button class="toggle-btn ${rule.enabled ? 'toggle-enabled' : 'toggle-disabled'}" 
                                    onclick="toggleRule(${rule.id}, ${!rule.enabled})">
                                ${rule.enabled ? 'ENABLED' : 'DISABLED'}
                            </button>
                        </div>
                    `).join('');
                    document.getElementById('rules-list').innerHTML = rulesHtml;
                });
        }

        function toggleRule(ruleId, enable) {
            fetch('/api/toggle_rule', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rule_id: ruleId, enabled: enable })
            }).then(() => refreshRules());
        }

        refreshRules();
    </script>
</body>
</html>
"""

BLOCKED_IPS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Blocked IPs</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        nav { margin-bottom: 20px; }
        nav a { margin-right: 15px; text-decoration: none; color: #1976d2; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; }
        .unblock-btn { background: #f44336; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; }
        .unblock-btn:hover { background: #d32f2f; }
        .button { background: #1976d2; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin-bottom: 20px; }
        .button:hover { background: #1565c0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚫 Blocked IPs</h1>
        <nav>
            <a href="/">Dashboard</a>
            <a href="/logs">Logs</a>
            <a href="/rules">Rules</a>
            <a href="/blocked_ips">Blocked IPs</a>
        </nav>

        <div class="card">
            <button class="button" onclick="refreshBlocked()">Refresh</button>
            <table id="blocked-table">
                <thead>
                    <tr><th>IP Address</th><th>Blocked Until</th><th>Action</th></tr>
                </thead>
                <tbody id="blocked-list">
                    <tr><td colspan="3">Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        function refreshBlocked() {
            fetch('/api/blocked_ips')
                .then(response => response.json())
                .then(data => {
                    const rowsHtml = data.ips.map(ip => `
                        <tr>
                            <td>${ip.ip}</td>
                            <td>${new Date(ip.until * 1000).toLocaleString()}</td>
                            <td><button class="unblock-btn" onclick="unblockIP('${ip.ip}')">Unblock</button></td>
                        </tr>
                    `).join('');
                    document.getElementById('blocked-list').innerHTML = rowsHtml || '<tr><td colspan="3">No blocked IPs</td></tr>';
                });
        }

        function unblockIP(ip) {
            fetch('/api/unblock_ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            }).then(() => refreshBlocked());
        }

        refreshBlocked();
        setInterval(refreshBlocked, 5000);
    </script>
</body>
</html>
"""


# API endpoints
@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_TEMPLATE)


@app.route('/logs')
def logs_page():
    return render_template_string(LOGS_TEMPLATE)


@app.route('/rules')
def rules_page():
    return render_template_string(RULES_TEMPLATE)


@app.route('/blocked_ips')
def blocked_ips_page():
    return render_template_string(BLOCKED_IPS_TEMPLATE)


@app.route('/api/stats')
def api_stats():
    """Получить статистику"""
    # Парсим лог файл для подсчета статистики
    total = 0
    blocked = 0

    try:
        with open(config.LOG_FILE, 'r') as f:
            for line in f:
                total += 1
                if 'BLOCKED' in line or 'RATE_LIMIT' in line:
                    blocked += 1
    except:
        pass

    rules = get_rules()
    active_rules = sum(1 for r in rules if r['enabled'])

    return jsonify({
        'total_requests': total,
        'blocked_requests': blocked,
        'active_rules': active_rules,
        'blocked_ips': len(rate_limiter.get_blocked_ips())
    })


@app.route('/api/logs')
def api_logs():
    """Получить последние логи"""
    try:
        with open(config.LOG_FILE, 'r') as f:
            lines = f.readlines()
            # Возвращаем последние 100 строк
            recent = lines[-100:] if len(lines) > 100 else lines
            return jsonify({'logs': ''.join(recent)})
    except:
        return jsonify({'logs': 'No logs available'})


@app.route('/api/recent_alerts')
def api_recent_alerts():
    """Получить последние алерты"""
    alerts = []
    try:
        with open(config.LOG_FILE, 'r') as f:
            lines = f.readlines()
            # Берем последние 20 алертов
            for line in lines[-50:]:
                if 'BLOCKED' in line or 'RATE_LIMIT' in line:
                    # Парсим строку лога
                    parts = line.split(' - ')
                    if len(parts) >= 3:
                        alerts.append({
                            'time': parts[0],
                            'message': parts[2].strip()
                        })
    except:
        pass

    return jsonify({'alerts': alerts[-20:]})


@app.route('/api/rules')
def api_rules():
    """Получить список правил"""
    rules = get_rules()
    return jsonify({
        'rules': [
            {
                'id': r['id'],
                'name': r['name'],
                'enabled': r['enabled'],
                'severity': r['severity'],
                'target': r['target']
            }
            for r in rules
        ]
    })


@app.route('/api/toggle_rule', methods=['POST'])
def api_toggle_rule():
    """Включить/выключить правило"""
    data = request.json
    rule_id = data.get('rule_id')
    enabled = data.get('enabled')

    if toggle_rule(rule_id, enabled):
        waf_logger.info(f"Rule {rule_id} {'enabled' if enabled else 'disabled'} via web UI")
        return jsonify({'success': True})

    return jsonify({'success': False, 'error': 'Rule not found'}), 404


@app.route('/api/blocked_ips')
def api_blocked_ips():
    """Получить список заблокированных IP"""
    blocked = rate_limiter.get_blocked_ips()
    return jsonify({
        'ips': [{'ip': ip, 'until': until} for ip, until in blocked.items()]
    })


@app.route('/api/unblock_ip', methods=['POST'])
def api_unblock_ip():
    """Разблокировать IP"""
    data = request.json
    ip = data.get('ip')
    rate_limiter.unblock_ip(ip)
    waf_logger.info(f"IP {ip} unblocked via web UI")
    return jsonify({'success': True})


@app.route('/api/clear_logs', methods=['POST'])
def api_clear_logs():
    """Очистить логи"""
    try:
        with open(config.LOG_FILE, 'w') as f:
            f.write('')
        waf_logger.info("Logs cleared via web UI")
        return jsonify({'success': True})
    except:
        return jsonify({'success': False}), 500


def run_web_ui():
    """Запуск Flask приложения"""
    print(f"✅ Web UI запущен на http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG, use_reloader=False)