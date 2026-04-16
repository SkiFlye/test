from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from database import *
from waf_core import RULES, waf_core

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Класс для Flask-Login
class LoginUser(UserMixin):
    def __init__(self, user_id, email):
        self.id = user_id
        self.email = email


@login_manager.user_loader
def load_user(user_id):
    user = get_user_by_id(int(user_id))
    if user:
        return LoginUser(user['id'], user['email'])
    return None


# Маршруты
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            flash('Пароли не совпадают')
            return redirect(url_for('register'))

        if get_user_by_email(email):
            flash('Пользователь с таким email уже существует')
            return redirect(url_for('register'))

        api_key = secrets.token_urlsafe(32)
        password_hash = generate_password_hash(password)

        user = create_user(email, password_hash, api_key)
        login_user(LoginUser(user['id'], user['email']))

        flash('Регистрация успешна! Сохраните ваш API-ключ:')
        flash(api_key)
        return redirect(url_for('dashboard'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = get_user_by_email(email)
        if user and check_password_hash(user['password_hash'], password):
            login_user(LoginUser(user['id'], user['email']))
            return redirect(url_for('dashboard'))

        flash('Неверный email или пароль')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    stats = get_user_statistics(current_user.id)
    recent_attacks = get_recent_attacks(current_user.id)
    blocked_ips = get_user_blocked_ips(current_user.id)
    user = get_user_by_id(current_user.id)

    return render_template('dashboard.html',
                           stats=stats,
                           recent_attacks=recent_attacks,
                           blocked_ips=blocked_ips,
                           user=user)


@app.route('/rules')
@login_required
def rules():
    user_rules = get_user_rules_enabled(current_user.id)
    rules_with_status = []
    for rule in RULES:
        enabled = user_rules.get(str(rule["id"]), True)
        rules_with_status.append({
            "id": rule["id"],
            "name": rule["name"],
            "severity": rule["severity"],
            "enabled": enabled
        })
    return render_template('rules.html', rules=rules_with_status)


@app.route('/toggle_rule', methods=['POST'])
@login_required
def toggle_rule():
    data = request.json
    rule_id = data.get('rule_id')
    enabled = data.get('enabled')
    set_user_rule_enabled(current_user.id, rule_id, enabled)
    return jsonify({'success': True})


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = get_user_by_id(current_user.id)

    if request.method == 'POST':
        if 'generate_api_key' in request.form:
            new_api_key = secrets.token_urlsafe(32)
            update_api_key(current_user.id, new_api_key)
            flash(f'Новый API-ключ: {new_api_key}')
            return redirect(url_for('settings'))
        elif 'update_rate_limit' in request.form:
            new_limit = int(request.form['rate_limit'])
            # Обновляем лимит напрямую через базу
            session = Session()
            try:
                db_user = session.query(User).filter(User.id == current_user.id).first()
                if db_user:
                    db_user.rate_limit = new_limit
                    session.commit()
            finally:
                session.close()
            flash('Лимит обновлен')
            return redirect(url_for('settings'))
        elif 'delete_account' in request.form:
            delete_user(current_user.id)
            logout_user()
            flash('Аккаунт удален')
            return redirect(url_for('index'))

    return render_template('settings.html', user=user)


@app.route('/blocked_ips')
@login_required
def blocked_ips():
    blocked = get_user_blocked_ips(current_user.id)
    return render_template('blocked_ips.html', blocked_ips=blocked)


@app.route('/unblock_ip', methods=['POST'])
@login_required
def unblock_ip():
    data = request.json
    ip = data.get('ip')
    unblock_ip(current_user.id, ip)
    return jsonify({'success': True})


@app.route('/api/stats')
@login_required
def api_stats():
    stats = get_user_statistics(current_user.id)
    return jsonify(stats)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)