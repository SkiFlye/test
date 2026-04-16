from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import json

Base = declarative_base()


# Модель пользователя
class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    api_key = Column(String(100), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Настройки пользователя
    rate_limit = Column(Integer, default=60)
    rules_enabled = Column(Text, default='{}')


# Модель для статистики
class Statistic(Base):
    __tablename__ = 'statistics'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    request_type = Column(String(20))
    method = Column(String(10))
    url = Column(Text)
    client_ip = Column(String(50))
    rule_name = Column(String(100), nullable=True)
    severity = Column(String(20), nullable=True)


# Модель для заблокированных IP
class BlockedIP(Base):
    __tablename__ = 'blocked_ips'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    ip = Column(String(50), nullable=False)
    blocked_until = Column(DateTime, nullable=False)
    reason = Column(String(200))


# Модель для истории API-ключей
class APIKeyHistory(Base):
    __tablename__ = 'api_key_history'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    api_key = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    revoked_at = Column(DateTime, nullable=True)


# Инициализация базы данных
engine = create_engine('sqlite:///waf.db', echo=False)
Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)


# Вспомогательные функции
def get_user_by_api_key(api_key):
    """Получить пользователя по API-ключу"""
    session = Session()
    try:
        user = session.query(User).filter(User.api_key == api_key).first()
        # Сохраняем нужные данные в словарь, чтобы закрыть сессию
        if user:
            user_data = {
                'id': user.id,
                'email': user.email,
                'api_key': user.api_key,
                'rate_limit': user.rate_limit,
                'rules_enabled': user.rules_enabled
            }
            return user_data
        return None
    finally:
        session.close()


def get_user_by_email(email):
    """Получить пользователя по email"""
    session = Session()
    try:
        user = session.query(User).filter(User.email == email).first()
        if user:
            user_data = {
                'id': user.id,
                'email': user.email,
                'password_hash': user.password_hash,
                'api_key': user.api_key,
                'rate_limit': user.rate_limit,
                'rules_enabled': user.rules_enabled
            }
            return user_data
        return None
    finally:
        session.close()


def get_user_by_id(user_id):
    """Получить пользователя по ID"""
    session = Session()
    try:
        user = session.query(User).filter(User.id == user_id).first()
        if user:
            user_data = {
                'id': user.id,
                'email': user.email,
                'api_key': user.api_key,
                'rate_limit': user.rate_limit,
                'rules_enabled': user.rules_enabled
            }
            return user_data
        return None
    finally:
        session.close()


def create_user(email, password_hash, api_key):
    """Создать нового пользователя"""
    session = Session()
    try:
        user = User(email=email, password_hash=password_hash, api_key=api_key)
        session.add(user)
        session.commit()

        # Сохраняем историю API-ключа
        history = APIKeyHistory(user_id=user.id, api_key=api_key)
        session.add(history)
        session.commit()

        # Получаем ID до закрытия сессии
        user_id = user.id

        # Возвращаем словарь с данными пользователя
        return {
            'id': user_id,
            'email': email,
            'api_key': api_key,
            'rate_limit': user.rate_limit,
            'rules_enabled': user.rules_enabled
        }
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def update_api_key(user_id, new_api_key):
    """Обновить API-ключ пользователя"""
    session = Session()
    try:
        user = session.query(User).filter(User.id == user_id).first()
        if user:
            # Помечаем старый ключ как отозванный
            old_history = session.query(APIKeyHistory).filter(
                APIKeyHistory.user_id == user_id,
                APIKeyHistory.revoked_at.is_(None)
            ).first()
            if old_history:
                old_history.revoked_at = datetime.utcnow()

            user.api_key = new_api_key
            # Сохраняем новый ключ в историю
            history = APIKeyHistory(user_id=user_id, api_key=new_api_key)
            session.add(history)
            session.commit()
            return True
        return False
    finally:
        session.close()


def get_user_rules_enabled(user_id):
    """Получить настройки правил пользователя"""
    session = Session()
    try:
        user = session.query(User).filter(User.id == user_id).first()
        if user and user.rules_enabled:
            return json.loads(user.rules_enabled)
        return {}
    finally:
        session.close()


def set_user_rule_enabled(user_id, rule_id, enabled):
    """Включить/выключить правило для пользователя"""
    session = Session()
    try:
        user = session.query(User).filter(User.id == user_id).first()
        if user:
            rules = json.loads(user.rules_enabled) if user.rules_enabled else {}
            rules[str(rule_id)] = enabled
            user.rules_enabled = json.dumps(rules)
            session.commit()
            return True
        return False
    finally:
        session.close()


def log_statistic(user_id, request_type, method, url, client_ip, rule_name=None, severity=None):
    """Записать статистику"""
    session = Session()
    try:
        stat = Statistic(
            user_id=user_id,
            request_type=request_type,
            method=method,
            url=url,
            client_ip=client_ip,
            rule_name=rule_name,
            severity=severity
        )
        session.add(stat)
        session.commit()
    finally:
        session.close()


def get_user_statistics(user_id, days=7):
    """Получить статистику пользователя за последние N дней"""
    session = Session()
    try:
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(days=days)

        stats = session.query(Statistic).filter(
            Statistic.user_id == user_id,
            Statistic.timestamp >= cutoff
        ).all()

        total = len(stats)
        blocked = len([s for s in stats if s.request_type == 'blocked'])
        rate_limited = len([s for s in stats if s.request_type == 'rate_limited'])

        # Группировка по дням для графика
        daily = {}
        for stat in stats:
            day = stat.timestamp.strftime('%Y-%m-%d')
            if day not in daily:
                daily[day] = {'total': 0, 'blocked': 0}
            daily[day]['total'] += 1
            if stat.request_type == 'blocked':
                daily[day]['blocked'] += 1

        return {
            'total': total,
            'blocked': blocked,
            'rate_limited': rate_limited,
            'daily': daily
        }
    finally:
        session.close()


def get_recent_attacks(user_id, limit=50):
    """Получить последние атаки пользователя"""
    session = Session()
    try:
        attacks = session.query(Statistic).filter(
            Statistic.user_id == user_id,
            Statistic.request_type == 'blocked'
        ).order_by(Statistic.timestamp.desc()).limit(limit).all()

        # Преобразуем в список словарей
        result = []
        for attack in attacks:
            result.append({
                'timestamp': attack.timestamp,
                'client_ip': attack.client_ip,
                'method': attack.method,
                'url': attack.url,
                'rule_name': attack.rule_name,
                'severity': attack.severity
            })
        return result
    finally:
        session.close()


def get_user_blocked_ips(user_id):
    """Получить активные блокировки IP пользователя"""
    session = Session()
    try:
        now = datetime.utcnow()
        blocked = session.query(BlockedIP).filter(
            BlockedIP.user_id == user_id,
            BlockedIP.blocked_until > now
        ).all()

        result = []
        for b in blocked:
            result.append({
                'id': b.id,
                'ip': b.ip,
                'blocked_until': b.blocked_until,
                'reason': b.reason
            })
        return result
    finally:
        session.close()


def block_ip(user_id, ip, duration_seconds, reason):
    """Заблокировать IP"""
    from datetime import timedelta
    session = Session()
    try:
        blocked_until = datetime.utcnow() + timedelta(seconds=duration_seconds)

        # Удаляем старые блокировки для этого IP
        session.query(BlockedIP).filter(
            BlockedIP.user_id == user_id,
            BlockedIP.ip == ip
        ).delete()

        blocked = BlockedIP(
            user_id=user_id,
            ip=ip,
            blocked_until=blocked_until,
            reason=reason
        )
        session.add(blocked)
        session.commit()
    finally:
        session.close()


def unblock_ip(user_id, ip):
    """Разблокировать IP"""
    session = Session()
    try:
        session.query(BlockedIP).filter(
            BlockedIP.user_id == user_id,
            BlockedIP.ip == ip
        ).delete()
        session.commit()
    finally:
        session.close()


def is_ip_blocked(user_id, ip):
    """Проверить, заблокирован ли IP"""
    session = Session()
    try:
        now = datetime.utcnow()
        blocked = session.query(BlockedIP).filter(
            BlockedIP.user_id == user_id,
            BlockedIP.ip == ip,
            BlockedIP.blocked_until > now
        ).first()
        return blocked is not None
    finally:
        session.close()


def delete_user(user_id):
    """Удалить пользователя и все его данные"""
    session = Session()
    try:
        session.query(Statistic).filter(Statistic.user_id == user_id).delete()
        session.query(BlockedIP).filter(BlockedIP.user_id == user_id).delete()
        session.query(APIKeyHistory).filter(APIKeyHistory.user_id == user_id).delete()
        session.query(User).filter(User.id == user_id).delete()
        session.commit()
    finally:
        session.close()