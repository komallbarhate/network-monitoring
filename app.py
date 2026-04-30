"""
Main Flask Application for NetMon Indigenous Network Monitoring System
"""
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from datetime import datetime
import threading
import time
import logging

from config import Config
from models import db, User, Alert, BlacklistedIP, PacketLog
from capture import PacketCapture
from detector import AnomalyDetector, RuleBasedDetector

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Global components
anomaly_detector = AnomalyDetector()
rule_detector = None
packet_capture = None
alert_cooldown = {}  # prevent alert spam: {(src_ip, type): last_alert_time}
ALERT_COOLDOWN_SECONDS = 10

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ──────────────────────────────────────────────
# Packet / Threat handlers
# ──────────────────────────────────────────────

def handle_packet(pkt_info):
    """Called for every captured/simulated packet."""
    global rule_detector
    # Feed to ML detector
    anomaly_detector.add_packet({
        'packet_size': pkt_info.get('packet_size', 0),
        'src_port': pkt_info.get('src_port', 0),
        'dst_port': pkt_info.get('dst_port', 0),
        'protocol': pkt_info.get('protocol', 'OTHER'),
    })
    ml_result = anomaly_detector.predict({
        'packet_size': pkt_info.get('packet_size', 0),
        'src_port': pkt_info.get('src_port', 0),
        'dst_port': pkt_info.get('dst_port', 0),
        'protocol': pkt_info.get('protocol', 'OTHER'),
    })

    pkt_info['anomaly_score'] = ml_result['anomaly_score']
    pkt_info['is_anomaly'] = ml_result['is_anomaly']

    # Rule-based detection
    threats = rule_detector.analyze(pkt_info) if rule_detector else []

    # ML anomaly alert
    if ml_result['is_anomaly'] and ml_result['anomaly_score'] > 0.65:
        threats.append({
            'type': 'ml_anomaly',
            'severity': 'MEDIUM' if ml_result['anomaly_score'] < 0.8 else 'HIGH',
            'description': f"AI anomaly detected (score={ml_result['anomaly_score']:.2f})",
            'source_ip': pkt_info.get('src_ip', ''),
            'destination_ip': pkt_info.get('dst_ip', ''),
        })

    # Emit packet to dashboard
    socketio.emit('new_packet', pkt_info)

    # Handle threats
    for threat in threats:
        _handle_threat(threat, pkt_info)


def _handle_threat(threat, pkt_info):
    """Persist and emit a detected threat."""
    key = (threat.get('source_ip', ''), threat['type'])
    now = time.time()
    if now - alert_cooldown.get(key, 0) < ALERT_COOLDOWN_SECONDS:
        return
    alert_cooldown[key] = now

    with app.app_context():
        try:
            alert = Alert(
                alert_type=threat['type'],
                severity=threat['severity'],
                source_ip=threat.get('source_ip', ''),
                destination_ip=threat.get('destination_ip', ''),
                description=threat['description'],
                protocol=pkt_info.get('protocol', ''),
                packet_count=1,
            )
            db.session.add(alert)
            db.session.commit()

            socketio.emit('new_alert', {
                **alert.to_dict(),
                'severity': threat['severity'],
            })
            logger.warning(f"[ALERT] {threat['severity']} | {threat['type']} | {threat['description']}")
        except Exception as e:
            logger.error(f"[Alert] DB error: {e}")
            db.session.rollback()


# ──────────────────────────────────────────────
# Auth Routes
# ──────────────────────────────────────────────

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        data = request.get_json() or request.form
        username = data.get('username', '')
        password = data.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password) and user.is_active_flag:
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)
            if request.is_json:
                return jsonify({'success': True, 'role': user.role})
            return redirect(url_for('dashboard'))
        if request.is_json:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    return render_template('admin.html', user=current_user)

# ──────────────────────────────────────────────
# API Routes
# ──────────────────────────────────────────────

@app.route('/api/stats')
@login_required
def api_stats():
    cap_stats = packet_capture.get_stats() if packet_capture else {}
    ml_stats = anomaly_detector.get_stats()
    with app.app_context():
        total_alerts = Alert.query.count()
        unacked = Alert.query.filter_by(is_acknowledged=False).count()
        critical = Alert.query.filter_by(severity='CRITICAL').count()
    return jsonify({
        'capture': cap_stats,
        'ml': ml_stats,
        'alerts': {'total': total_alerts, 'unacknowledged': unacked, 'critical': critical},
        'timestamp': datetime.utcnow().isoformat(),
    })

@app.route('/api/alerts')
@login_required
def api_alerts():
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', '')
    limit = request.args.get('limit', 50, type=int)
    query = Alert.query.order_by(Alert.timestamp.desc())
    if severity:
        query = query.filter_by(severity=severity)
    alerts = query.paginate(page=page, per_page=limit, error_out=False)
    return jsonify({
        'alerts': [a.to_dict() for a in alerts.items],
        'total': alerts.total,
        'pages': alerts.pages,
        'current_page': page,
    })

@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.is_acknowledged = True
    alert.acknowledged_by = current_user.id
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/packets')
@login_required
def api_packets():
    n = request.args.get('n', 50, type=int)
    packets = packet_capture.get_recent_packets(n) if packet_capture else []
    return jsonify({'packets': packets})

@app.route('/api/blacklist', methods=['GET'])
@login_required
def api_blacklist_get():
    ips = BlacklistedIP.query.filter_by(is_active=True).all()
    return jsonify({'blacklist': [ip.to_dict() for ip in ips]})

@app.route('/api/blacklist', methods=['POST'])
@login_required
def api_blacklist_add():
    if not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json()
    ip_address = data.get('ip_address', '').strip()
    reason = data.get('reason', 'Manual block')
    if not ip_address:
        return jsonify({'error': 'IP address required'}), 400
    existing = BlacklistedIP.query.filter_by(ip_address=ip_address).first()
    if existing:
        existing.is_active = True
    else:
        entry = BlacklistedIP(ip_address=ip_address, reason=reason, added_by=current_user.id)
        db.session.add(entry)
    db.session.commit()
    _refresh_blacklist()
    return jsonify({'success': True})

@app.route('/api/blacklist/<int:ip_id>', methods=['DELETE'])
@login_required
def api_blacklist_remove(ip_id):
    if not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    entry = BlacklistedIP.query.get_or_404(ip_id)
    entry.is_active = False
    db.session.commit()
    _refresh_blacklist()
    return jsonify({'success': True})

@app.route('/api/top_talkers')
@login_required
def api_top_talkers():
    talkers = rule_detector.get_top_talkers(10) if rule_detector else []
    return jsonify({'top_talkers': [{'ip': ip, 'count': c} for ip, c in talkers]})

@app.route('/api/ml/train', methods=['POST'])
@login_required
def api_ml_train():
    if not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    result = anomaly_detector.force_train()
    return jsonify({'success': result, 'trained': result})

@app.route('/api/users', methods=['GET'])
@login_required
def api_users():
    if not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    users = User.query.all()
    return jsonify({'users': [u.to_dict() for u in users]})

@app.route('/api/users', methods=['POST'])
@login_required
def api_create_user():
    if not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username exists'}), 409
    user = User(username=data['username'], email=data.get('email', ''), role=data.get('role', 'viewer'))
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'success': True, 'user': user.to_dict()})

@app.route('/api/users/<int:uid>', methods=['DELETE'])
@login_required
def api_delete_user(uid):
    if not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    if uid == current_user.id:
        return jsonify({'error': 'Cannot delete self'}), 400
    user = User.query.get_or_404(uid)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/capture/start', methods=['POST'])
@login_required
def api_capture_start():
    if not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    if packet_capture and not packet_capture.is_running:
        packet_capture.start()
        return jsonify({'success': True, 'message': 'Capture started'})
    return jsonify({'success': False, 'message': 'Already running'})

@app.route('/api/capture/stop', methods=['POST'])
@login_required
def api_capture_stop():
    if not current_user.is_admin():
        return jsonify({'error': 'Forbidden'}), 403
    if packet_capture and packet_capture.is_running:
        packet_capture.stop()
        return jsonify({'success': True, 'message': 'Capture stopped'})
    return jsonify({'success': False, 'message': 'Not running'})

# ──────────────────────────────────────────────
# SocketIO Events
# ──────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    logger.info(f"[WS] Client connected: {request.sid}")

@socketio.on('disconnect')
def on_disconnect():
    logger.info(f"[WS] Client disconnected: {request.sid}")

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _refresh_blacklist():
    """Reload blacklist from DB into rule detector memory."""
    with app.app_context():
        ips = BlacklistedIP.query.filter_by(is_active=True).all()
        ip_set = {ip.ip_address for ip in ips}
        if rule_detector:
            rule_detector.update_blacklist(ip_set)

def _periodic_stats_broadcast():
    """Broadcast stats to all clients every 2 seconds."""
    while True:
        time.sleep(2)
        try:
            with app.app_context():
                cap_stats = packet_capture.get_stats() if packet_capture else {}
                ml_stats = anomaly_detector.get_stats()
                top = rule_detector.get_top_talkers(5) if rule_detector else []
                socketio.emit('stats_update', {
                    'capture': cap_stats,
                    'ml': ml_stats,
                    'top_talkers': [{'ip': ip, 'count': c} for ip, c in top],
                })
        except Exception as e:
            logger.debug(f"[Stats broadcast] {e}")

# ──────────────────────────────────────────────
# App Bootstrap
# ──────────────────────────────────────────────

def create_default_admin():
    """Create default admin user if none exists."""
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@netmon.local', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        logger.info("[Bootstrap] Default admin created: admin / admin123")

    if not User.query.filter_by(username='viewer').first():
        viewer = User(username='viewer', email='viewer@netmon.local', role='viewer')
        viewer.set_password('viewer123')
        db.session.add(viewer)
        db.session.commit()
        logger.info("[Bootstrap] Default viewer created: viewer / viewer123")


def initialize_app():
    global rule_detector, packet_capture
    with app.app_context():
        db.create_all()
        create_default_admin()

        # Seed default blacklist IPs
        for ip_addr in Config.DEFAULT_BLACKLIST:
            if ip_addr and not BlacklistedIP.query.filter_by(ip_address=ip_addr).first():
                entry = BlacklistedIP(ip_address=ip_addr, reason='Default block')
                db.session.add(entry)
        db.session.commit()

        # Initialize detectors
        if rule_detector is None:
            rule_detector = RuleBasedDetector(Config)
            _refresh_blacklist()

        # Start packet capture
        if packet_capture is None:
            packet_capture = PacketCapture(
                config=Config,
                socketio=socketio,
                on_packet=handle_packet,
            )
            packet_capture.start(interface=Config.INTERFACE)

        # Start stats broadcast thread
        threading.Thread(target=_periodic_stats_broadcast, daemon=True).start()

# Initialize everything for WSGI (e.g., Gunicorn on Render)
initialize_app()

if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("  NetMon - Indigenous Network Monitoring System")
    logger.info("  Dashboard: http://127.0.0.1:5000")
    logger.info("  Admin:     admin / admin123")
    logger.info("  Viewer:    viewer / viewer123")
    logger.info("=" * 60)

    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
