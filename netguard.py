"""
╔══════════════════════════════════════════════════════════╗
║         NETGUARD — Network Monitoring System             ║
║         Single file version — paste & run                ║
╚══════════════════════════════════════════════════════════╝

SETUP (run these once in VS Code terminal):
    pip install scapy pandas scikit-learn numpy flask flask-jwt-extended streamlit plotly python-dotenv requests

RUN (open 3 terminals in VS Code):
    Terminal 1:  python netguard.py capture
    Terminal 2:  python netguard.py api
    Terminal 3:  python netguard.py dashboard

Then open:  http://localhost:8501
Login:      admin / admin123
"""

import sys
import os
import sqlite3
import threading
import time
import random
import pickle
import smtplib
from collections  import defaultdict, deque
from datetime     import datetime, timedelta
from email.mime.text      import MIMEText
from email.mime.multipart import MIMEMultipart

# ════════════════════════════════════════════════════════════════════
#  CONFIG  (change these if you want)
# ════════════════════════════════════════════════════════════════════

SECRET_KEY          = "netguard_secret_key_change_me"
JWT_SECRET_KEY      = "netguard_jwt_key_change_me"
ADMIN_USERNAME      = "admin"
ADMIN_PASSWORD      = "admin123"
PORT_SCAN_THRESHOLD = 50       # distinct ports from one IP in TIME_WINDOW seconds
DDOS_PPS_THRESHOLD  = 500      # packets per second
TIME_WINDOW         = 10       # seconds for sliding window
DB_PATH             = "netguard.db"
MODEL_PATH          = "netguard_model.pkl"

# Email alerts (optional — leave blank to disable)
SMTP_HOST  = "smtp.gmail.com"
SMTP_PORT  = 587
SMTP_USER  = ""    # your_email@gmail.com
SMTP_PASS  = ""    # Gmail App Password
ALERT_TO   = ""    # where to send alerts


# ════════════════════════════════════════════════════════════════════
#  DATABASE
# ════════════════════════════════════════════════════════════════════

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            src_ip    TEXT    NOT NULL,
            dst_ip    TEXT,
            src_port  INTEGER,
            dst_port  INTEGER,
            protocol  TEXT,
            threat    TEXT    NOT NULL,
            severity  TEXT    NOT NULL,
            detail    TEXT,
            ml_score  REAL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ip       TEXT    NOT NULL UNIQUE,
            reason   TEXT,
            added_at TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS known_ips (
            ip           TEXT PRIMARY KEY,
            first_seen   TEXT NOT NULL,
            last_seen    TEXT NOT NULL,
            packet_count INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()
    print("[DB] Database ready:", DB_PATH)


def log_event(src_ip, dst_ip, src_port, dst_port, protocol,
              threat, severity, detail='', ml_score=None):
    conn = get_conn()
    conn.execute("""
        INSERT INTO events (timestamp, src_ip, dst_ip, src_port, dst_port,
                            protocol, threat, severity, detail, ml_score)
        VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (src_ip, dst_ip, src_port, dst_port, protocol,
          threat, severity, detail, ml_score))
    conn.commit()
    conn.close()


def add_to_blacklist(ip, reason='auto'):
    conn = get_conn()
    conn.execute("INSERT OR IGNORE INTO blacklist (ip, reason) VALUES (?, ?)", (ip, reason))
    conn.commit()
    conn.close()


def is_blacklisted(ip):
    conn = get_conn()
    row  = conn.execute("SELECT 1 FROM blacklist WHERE ip=?", (ip,)).fetchone()
    conn.close()
    return row is not None


def upsert_known_ip(ip):
    conn = get_conn()
    conn.execute("""
        INSERT INTO known_ips (ip, first_seen, last_seen, packet_count)
        VALUES (?, datetime('now'), datetime('now'), 1)
        ON CONFLICT(ip) DO UPDATE SET
            last_seen    = datetime('now'),
            packet_count = packet_count + 1
    """, (ip,))
    conn.commit()
    conn.close()


def get_recent_events(limit=100):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_blacklist_entries():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM blacklist ORDER BY added_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ════════════════════════════════════════════════════════════════════
#  SNIFFER
# ════════════════════════════════════════════════════════════════════

class Sniffer:
    def __init__(self, interface=None, callback=None, demo=False):
        self.interface = interface
        self.callback  = callback or (lambda p: None)
        self.demo      = demo
        self._stop     = threading.Event()

    def start(self):
        self._stop.clear()
        t = threading.Thread(target=self._run, daemon=True)
        t.start()
        mode = "DEMO" if self.demo else f"LIVE on {self.interface or 'default'}"
        print(f"[Sniffer] Started — {mode}")

    def stop(self):
        self._stop.set()

    def _run(self):
        if self.demo:
            self._demo_mode()
            return
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

            def handle(pkt):
                if not pkt.haslayer(IP):
                    return
                ip  = pkt["IP"]
                feat = {
                    'timestamp':    datetime.now().isoformat(timespec='seconds'),
                    'src_ip':       ip.src,
                    'dst_ip':       ip.dst,
                    'protocol':     'TCP',
                    'length':       len(pkt),
                    'ttl':          ip.ttl,
                    'src_port':     None,
                    'dst_port':     None,
                    'tcp_flags':    None,
                    'payload_size': 0,
                }
                if pkt.haslayer(TCP):
                    feat.update(src_port=pkt["TCP"].sport,
                                dst_port=pkt["TCP"].dport,
                                tcp_flags=str(pkt["TCP"].flags),
                                protocol='TCP')
                elif pkt.haslayer(UDP):
                    feat.update(src_port=pkt["UDP"].sport,
                                dst_port=pkt["UDP"].dport,
                                protocol='UDP')
                elif pkt.haslayer(ICMP):
                    feat['protocol'] = 'ICMP'
                if pkt.haslayer(Raw):
                    feat['payload_size'] = len(pkt["Raw"].load)
                self.callback(feat)

            sniff(iface=self.interface, filter="ip", prn=handle,
                  store=False, stop_filter=lambda _: self._stop.is_set())

        except Exception as e:
            print(f"[Sniffer] Error: {e}")
            print("[Sniffer] Falling back to demo mode.")
            self._demo_mode()

    def _demo_mode(self):
        ips = ['192.168.1.10', '192.168.1.42', '10.0.0.77',
               '203.0.113.88', '172.16.5.9', '192.168.1.100']
        while not self._stop.is_set():
            src = random.choice(ips)
            self.callback({
                'timestamp':    datetime.now().isoformat(timespec='seconds'),
                'src_ip':       src,
                'dst_ip':       '192.168.1.1',
                'protocol':     random.choice(['TCP', 'UDP', 'ICMP']),
                'length':       random.randint(40, 1500),
                'ttl':          random.randint(32, 128),
                'src_port':     random.randint(1024, 65535),
                'dst_port':     random.choice([22, 80, 443, 8080,
                                               random.randint(1, 1024)]),
                'tcp_flags':    random.choice(['S', 'SA', 'A', 'F']),
                'payload_size': random.randint(0, 800),
            })
            time.sleep(random.uniform(0.05, 0.3))


# ════════════════════════════════════════════════════════════════════
#  RULE-BASED DETECTOR
# ════════════════════════════════════════════════════════════════════

def make_alert(src_ip, dst_ip, src_port, dst_port, protocol,
               threat, severity, detail='', ml_score=None):
    return {
        'timestamp': datetime.now().isoformat(timespec='seconds'),
        'src_ip':    src_ip,  'dst_ip':   dst_ip,
        'src_port':  src_port,'dst_port': dst_port,
        'protocol':  protocol,'threat':   threat,
        'severity':  severity,'detail':   detail,
        'ml_score':  ml_score,
    }


class RuleEngine:
    def __init__(self):
        self._known_ips   = set()
        self._port_hist   = defaultdict(deque)  # src → [(time, port)]
        self._pkt_hist    = defaultdict(deque)  # src → [time]

    def process(self, pkt):
        alerts = []
        src = pkt.get('src_ip', '')
        dst = pkt.get('dst_ip', '')
        now = datetime.now()
        self._update_windows(src, pkt.get('dst_port'), now)

        # Rule 1 — blacklisted IP
        if is_blacklisted(src):
            alerts.append(make_alert(src, dst, pkt.get('src_port'), pkt.get('dst_port'),
                pkt.get('protocol'), 'BLACKLISTED_IP', 'CRITICAL',
                f'{src} is on the blacklist.'))

        # Rule 2 — unknown IP
        if src not in self._known_ips:
            self._known_ips.add(src)
            alerts.append(make_alert(src, dst, pkt.get('src_port'), pkt.get('dst_port'),
                pkt.get('protocol'), 'UNKNOWN_IP', 'LOW',
                f'{src} seen for the first time.'))

        # Rule 3 — port scan
        ports = {p for _, p in self._port_hist[src] if p}
        if len(ports) >= PORT_SCAN_THRESHOLD:
            alerts.append(make_alert(src, dst, pkt.get('src_port'), pkt.get('dst_port'),
                pkt.get('protocol'), 'PORT_SCAN', 'CRITICAL',
                f'{src} hit {len(ports)} ports in {TIME_WINDOW}s.'))

        # Rule 4 — DDoS flood
        rate = len(self._pkt_hist[src]) / TIME_WINDOW
        if rate >= DDOS_PPS_THRESHOLD:
            alerts.append(make_alert(src, dst, pkt.get('src_port'), pkt.get('dst_port'),
                pkt.get('protocol'), 'DDOS_FLOOD', 'CRITICAL',
                f'{src} sending {rate:.0f} pkt/s.'))

        return alerts

    def _update_windows(self, src, dst_port, now):
        cutoff = now - timedelta(seconds=TIME_WINDOW)
        dq = self._port_hist[src]
        dq.append((now, dst_port))
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        pdq = self._pkt_hist[src]
        pdq.append(now)
        while pdq and pdq[0] < cutoff:
            pdq.popleft()


# ════════════════════════════════════════════════════════════════════
#  ML ANOMALY DETECTOR
# ════════════════════════════════════════════════════════════════════

class AnomalyDetector:
    def __init__(self):
        self.model    = None
        self._trained = False
        if os.path.exists(MODEL_PATH):
            self.load()

    def train(self, n=5000):
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest
            rng = np.random.default_rng(42)
            X = np.column_stack([
                rng.integers(40, 1500, n),
                rng.integers(32, 128,  n),
                rng.integers(1024, 65535, n),
                rng.choice([80, 443, 22, 53, 8080], n),
                rng.integers(0, 800, n),
                rng.choice([0, 1, 2], n),
            ])
            self.model = IsolationForest(n_estimators=100,
                                         contamination=0.05,
                                         random_state=42)
            self.model.fit(X)
            self._trained = True
            self.save()
            print(f"[ML] Model trained on {n} synthetic samples.")
        except ImportError:
            print("[ML] scikit-learn not installed — ML disabled.")

    def predict(self, pkt):
        if not self._trained:
            return None
        try:
            row = [[
                pkt.get('length', 0),
                pkt.get('ttl', 64),
                pkt.get('src_port', 0) or 0,
                pkt.get('dst_port', 0) or 0,
                pkt.get('payload_size', 0),
                {'TCP': 0, 'UDP': 1, 'ICMP': 2}.get(
                    str(pkt.get('protocol', 'TCP')).upper(), 3),
            ]]
            return round(float(self.model.score_samples(row)[0]), 4)
        except Exception:
            return None

    def is_anomaly(self, pkt, threshold=-0.1):
        s = self.predict(pkt)
        return s is not None and s < threshold

    def save(self):
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(self.model, f)

    def load(self):
        with open(MODEL_PATH, 'rb') as f:
            self.model = pickle.load(f)
        self._trained = True
        print("[ML] Model loaded from disk.")


# ════════════════════════════════════════════════════════════════════
#  EMAIL ALERTER
# ════════════════════════════════════════════════════════════════════

class EmailAlerter:
    def __init__(self):
        self.enabled = bool(SMTP_USER and SMTP_PASS and ALERT_TO)
        if not self.enabled:
            print("[Alerter] Email not configured — alerts logged only.")

    def send(self, alert):
        if not self.enabled or alert.get('severity') != 'CRITICAL':
            return
        threading.Thread(target=self._send_sync, args=(alert,), daemon=True).start()

    def _send_sync(self, alert):
        try:
            msg            = MIMEMultipart()
            msg['Subject'] = f"[NetGuard] CRITICAL: {alert['threat']} from {alert['src_ip']}"
            msg['From']    = SMTP_USER
            msg['To']      = ALERT_TO
            body = (f"Threat:   {alert['threat']}\n"
                    f"Source:   {alert['src_ip']}\n"
                    f"Time:     {alert['timestamp']}\n"
                    f"Detail:   {alert['detail']}")
            msg.attach(MIMEText(body, 'plain'))
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.starttls()
                s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(SMTP_USER, ALERT_TO, msg.as_string())
            print(f"[Alerter] Email sent for {alert['threat']}")
        except Exception as e:
            print(f"[Alerter] Email failed: {e}")


# ════════════════════════════════════════════════════════════════════
#  PIPELINE
# ════════════════════════════════════════════════════════════════════

class Pipeline:
    def __init__(self, interface=None, demo=False):
        init_db()
        self.rules       = RuleEngine()
        self.ml          = AnomalyDetector()
        self.alerter     = EmailAlerter()
        self._alerts     = []
        self._lock       = threading.Lock()
        self.pkt_count   = 0

        if not self.ml._trained:
            self.ml.train()

        self.sniffer = Sniffer(interface=interface,
                               callback=self._on_packet,
                               demo=demo)

    def start(self):
        self.sniffer.start()
        print("[Pipeline] Running — press Ctrl+C to stop.\n")

    def stop(self):
        self.sniffer.stop()

    def get_alerts(self, n=50):
        with self._lock:
            return list(self._alerts[-n:])

    def _on_packet(self, pkt):
        self.pkt_count += 1
        src = pkt.get('src_ip', '')
        upsert_known_ip(src)

        ml_score = self.ml.predict(pkt)

        if self.ml.is_anomaly(pkt):
            self._dispatch({
                **pkt,
                'threat':   'ML_ANOMALY',
                'severity': 'MEDIUM',
                'detail':   f'Isolation Forest score: {ml_score}',
                'ml_score': ml_score,
            })

        for alert in self.rules.process(pkt):
            alert['ml_score'] = ml_score
            self._dispatch(alert)

    def _dispatch(self, alert):
        log_event(alert['src_ip'], alert['dst_ip'],
                  alert.get('src_port'), alert.get('dst_port'),
                  alert.get('protocol'), alert['threat'],
                  alert['severity'], alert.get('detail', ''),
                  alert.get('ml_score'))

        if alert['severity'] == 'CRITICAL':
            add_to_blacklist(alert['src_ip'], reason=alert['threat'])

        self.alerter.send(alert)

        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-500:]

        icon = {'CRITICAL': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(alert['severity'], '⚪')
        print(f"{icon} [{alert['severity']}] {alert['threat']} "
              f"from {alert['src_ip']} — {alert.get('detail', '')}")


# ════════════════════════════════════════════════════════════════════
#  FLASK API  (python netguard.py api)
# ════════════════════════════════════════════════════════════════════

def run_api():
    from flask import Flask, request, jsonify
    from flask_jwt_extended import (JWTManager, create_access_token,
                                    jwt_required)

    app = Flask(__name__)
    app.config['JWT_SECRET_KEY']           = JWT_SECRET_KEY
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False
    JWTManager(app)
    init_db()

    @app.route('/api/login', methods=['POST'])
    def login():
        data = request.get_json(silent=True) or {}
        if (data.get('username') == ADMIN_USERNAME and
                data.get('password') == ADMIN_PASSWORD):
            return jsonify(access_token=create_access_token(identity=ADMIN_USERNAME))
        return jsonify(error='Bad credentials'), 401

    @app.route('/api/events')
    @jwt_required()
    def events():
        limit = min(int(request.args.get('limit', 100)), 500)
        return jsonify(get_recent_events(limit))

    @app.route('/api/stats')
    @jwt_required()
    def stats():
        ev = get_recent_events(500)
        sev = {'LOW': 0, 'MEDIUM': 0, 'CRITICAL': 0}
        thr = {}
        for e in ev:
            sev[e.get('severity', 'LOW')] = sev.get(e.get('severity', 'LOW'), 0) + 1
            t = e.get('threat', 'UNKNOWN')
            thr[t] = thr.get(t, 0) + 1
        return jsonify(total_events=len(ev), severity_counts=sev,
                       threat_counts=thr, blacklist_count=len(get_blacklist_entries()))

    @app.route('/api/blacklist', methods=['GET'])
    @jwt_required()
    def bl_get():
        return jsonify(get_blacklist_entries())

    @app.route('/api/blacklist', methods=['POST'])
    @jwt_required()
    def bl_add():
        data = request.get_json(silent=True) or {}
        ip   = data.get('ip', '').strip()
        if not ip:
            return jsonify(error='ip required'), 400
        add_to_blacklist(ip, reason=data.get('reason', 'manual'))
        return jsonify(success=True, ip=ip)

    print("[API] Starting on http://localhost:5000")
    app.run(port=5000, debug=False)


# ════════════════════════════════════════════════════════════════════
#  STREAMLIT DASHBOARD  (python netguard.py dashboard)
# ════════════════════════════════════════════════════════════════════

def run_dashboard():
    import subprocess
    import sys
    # Re-launch this file under streamlit
    subprocess.run([sys.executable, "-m", "streamlit", "run",
                    __file__, "--", "--streamlit-mode"],
                   check=True)


def streamlit_app():
    """Called when streamlit runs this file."""
    import requests
    import streamlit as st
    import plotly.graph_objects as go
    import pandas as pd

    API = "http://localhost:5000/api"
    st.set_page_config(page_title="NetGuard", page_icon="🛡️", layout="wide")

    if 'token' not in st.session_state:
        st.session_state.token = None

    def api(method, path, **kwargs):
        h = {'Authorization': f'Bearer {st.session_state.token}'}
        try:
            r = getattr(requests, method)(f"{API}{path}", headers=h,
                                          timeout=3, **kwargs)
            if r.status_code == 200:
                return r.json()
        except Exception:
            return None

    # ── Login ──
    if not st.session_state.token:
        st.title("🛡️ NetGuard — Login")
        user = st.text_input("Username")
        pw   = st.text_input("Password", type="password")
        if st.button("Login"):
            try:
                r = requests.post(f"{API}/login",
                                  json={'username': user, 'password': pw}, timeout=3)
                if r.status_code == 200:
                    st.session_state.token = r.json()['access_token']
                    st.rerun()
                else:
                    st.error("Wrong username or password.")
            except Exception:
                st.error("Cannot reach API — make sure Terminal 2 (api) is running.")
        return

    # ── Sidebar ──
    st.sidebar.title("🛡️ NetGuard")
    page = st.sidebar.radio("", ["Live Monitor", "Blacklist", "Help"])
    if st.sidebar.button("Logout"):
        st.session_state.token = None
        st.rerun()

    # ── Live Monitor ──
    if page == "Live Monitor":
        st.title("Live Network Monitor")
        stats  = api('get', '/stats') or {}
        events = api('get', '/events', params={'limit': 200}) or []

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total alerts",  stats.get('total_events', 0))
        c2.metric("🔴 Critical",   stats.get('severity_counts', {}).get('CRITICAL', 0))
        c3.metric("🟡 Medium",     stats.get('severity_counts', {}).get('MEDIUM', 0))
        c4.metric("Blocked IPs",   stats.get('blacklist_count', 0))
        st.divider()

        if events:
            df = pd.DataFrame(events)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            ts = df.set_index('timestamp').resample('1min').size().reset_index(name='n')
            fig = go.Figure(go.Scatter(x=ts['timestamp'], y=ts['n'],
                mode='lines+markers', fill='tozeroy',
                line=dict(color='#378ADD', width=2)))
            fig.update_layout(title='Alerts per minute', height=200,
                              margin=dict(l=0,r=0,t=40,b=0),
                              paper_bgcolor='rgba(0,0,0,0)',
                              plot_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig, use_container_width=True)

            st.subheader("Alert log")
            show = df[['timestamp','severity','threat','src_ip',
                        'dst_ip','protocol','detail']].copy()

            def colour(val):
                return {'CRITICAL':'background-color:#fde8e8;color:#a32d2d',
                        'MEDIUM':'background-color:#fef3c7;color:#854f0b',
                        'LOW':'background-color:#d1fae5;color:#065f46'}.get(val,'')

            st.dataframe(show.style.map(colour, subset=['severity']),
                         use_container_width=True, height=380)
        else:
            st.info("No alerts yet — make sure Terminal 1 (capture) is running.")

        time.sleep(5)
        st.rerun()

    # ── Blacklist ──
    elif page == "Blacklist":
        st.title("IP Blacklist")
        bl = api('get', '/blacklist') or []
        if bl:
            st.dataframe(pd.DataFrame(bl), use_container_width=True)
        else:
            st.info("Blacklist is empty.")
        st.subheader("Block an IP manually")
        ip     = st.text_input("IP address")
        reason = st.text_input("Reason", value="manual")
        if st.button("Block IP"):
            res = api('post', '/blacklist', json={'ip': ip, 'reason': reason})
            if res and res.get('success'):
                st.success(f"Blocked {ip}")
                st.rerun()
            else:
                st.error("Failed — check the IP address.")

    # ── Help ──
    else:
        st.title("Help")
        st.markdown("""
### How to run NetGuard

Open **3 terminals** in VS Code (`Ctrl + backtick`, then click **+**):

| Terminal | Command |
|---|---|
| 1 — Capture | `python netguard.py capture` |
| 2 — API     | `python netguard.py api` |
| 3 — Dashboard | `python netguard.py dashboard` |

Then open **http://localhost:8501** and login with `admin / admin123`.

### Detection rules
| Threat | Trigger | Severity |
|---|---|---|
| Port scan | >50 ports from one IP in 10s | 🔴 CRITICAL |
| DDoS flood | >500 packets/sec | 🔴 CRITICAL |
| Blacklisted IP | Found in blacklist DB | 🔴 CRITICAL |
| Unknown IP | First time seen | 🟢 LOW |
| ML anomaly | Isolation Forest score | 🟡 MEDIUM |

### Change thresholds
Edit the CONFIG section at the top of `netguard.py`.
        """)


# ════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    # Called by streamlit run — show the dashboard UI
    if '--streamlit-mode' in sys.argv:
        streamlit_app()
        sys.exit(0)

    # Check if streamlit is running this file directly
    try:
        import streamlit as _st
        # If we're inside a streamlit context, show the app
        streamlit_app()
        sys.exit(0)
    except Exception:
        pass

    if len(sys.argv) < 2:
        print(__doc__)
        print("\nUsage:")
        print("  python netguard.py capture    ← start packet capture + detection")
        print("  python netguard.py api        ← start REST API")
        print("  python netguard.py dashboard  ← start dashboard (opens browser)")
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == 'capture':
        import signal
        # Check if --live flag passed (requires admin / Npcap)
        live      = '--live' in sys.argv
        interface = None
        for a in sys.argv:
            if a.startswith('--interface='):
                interface = a.split('=', 1)[1]

        pipeline = Pipeline(interface=interface, demo=not live)

        def _exit(sig, frame):
            print("\n[Main] Shutting down...")
            pipeline.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT,  _exit)
        signal.signal(signal.SIGTERM, _exit)
        pipeline.start()

        while True:
            time.sleep(1)

    elif cmd == 'api':
        run_api()

    elif cmd == 'dashboard':
        run_dashboard()

    else:
        print(f"Unknown command: {cmd}")
        print("Use: capture | api | dashboard")
        sys.exit(1)
