/* ================================================
   NetMon Dashboard JavaScript
   Indigenous Network Monitoring System
   ================================================ */

const socket = io({ transports: ['websocket'] });

// ── State ──────────────────────────────────────
const state = {
  packets: [],
  alerts: [],
  alertPage: 1,
  alertFilter: '',
  paused: false,
  trafficHistory: Array(60).fill(0),
  anomalyHistory: Array(60).fill(0),
  pktCountLastSec: 0,
  lastTimestamp: Date.now(),
};

// ── Charts ─────────────────────────────────────
let trafficChart, protocolChart, alertTypeChart, severityChart, spikeChart, anomalyChart;
const CHART_DEFAULTS = {
  plugins: { legend: { labels: { color: '#64748b', font: { size: 12, family: 'Inter' } } } },
  scales: {
    x: { grid: { color: '#f1f5f9' }, ticks: { color: '#94a3b8' } },
    y: { grid: { color: '#f1f5f9' }, ticks: { color: '#94a3b8' } },
  }
};

function initCharts() {
  const labels60 = Array.from({ length: 60 }, (_, i) => i % 10 === 0 ? `-${60 - i}s` : '');

  // Traffic volume chart
  const tc = document.getElementById('trafficChart');
  if (tc) {
    trafficChart = new Chart(tc, {
      type: 'line',
      data: {
        labels: labels60,
        datasets: [{
          label: 'Packets/s',
          data: state.trafficHistory,
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59,130,246,0.07)',
          borderWidth: 2,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
        }]
      },
      options: { ...CHART_DEFAULTS, animation: { duration: 0 }, responsive: true }
    });
  }

  // Protocol pie
  const pc = document.getElementById('protocolChart');
  if (pc) {
    protocolChart = new Chart(pc, {
      type: 'doughnut',
      data: {
        labels: ['TCP', 'UDP', 'ICMP', 'Other'],
        datasets: [{
          data: [0, 0, 0, 0],
          backgroundColor: ['rgba(59,130,246,0.75)', 'rgba(99,102,241,0.7)', 'rgba(245,158,11,0.7)', 'rgba(148,163,184,0.5)'],
          borderColor: ['#3b82f6', '#6366f1', '#f59e0b', '#94a3b8'],
          borderWidth: 1,
        }]
      },
      options: {
        plugins: { legend: { position: 'bottom', labels: { color: '#64748b', padding: 16 } } },
        cutout: '70%', responsive: true
      }
    });
  }

  // Alert type chart
  const atc = document.getElementById('alertTypeChart');
  if (atc) {
    alertTypeChart = new Chart(atc, {
      type: 'bar',
      data: {
        labels: ['Port Scan', 'DDoS', 'Blacklisted', 'Unknown IP', 'AI Anomaly'],
        datasets: [{
          data: [0, 0, 0, 0, 0],
          backgroundColor: ['rgba(239,68,68,0.45)', 'rgba(245,158,11,0.45)', 'rgba(220,38,38,0.5)', 'rgba(59,130,246,0.45)', 'rgba(99,102,241,0.45)'],
          borderRadius: 6, borderWidth: 0,
        }]
      },
      options: { ...CHART_DEFAULTS, plugins: { legend: { display: false } }, responsive: true }
    });
  }

  // Severity chart
  const sc = document.getElementById('severityChart');
  if (sc) {
    severityChart = new Chart(sc, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: [0, 0, 0, 0],
          backgroundColor: ['rgba(239,68,68,0.7)', 'rgba(245,158,11,0.7)', 'rgba(99,102,241,0.65)', 'rgba(34,197,94,0.65)'],
          borderWidth: 1,
        }]
      },
      options: {
        plugins: { legend: { position: 'bottom', labels: { color: '#64748b', padding: 12 } } },
        cutout: '65%', responsive: true
      }
    });
  }

  // Spike chart
  const spk = document.getElementById('spikeChart');
  if (spk) {
    spikeChart = new Chart(spk, {
      type: 'line',
      data: {
        labels: labels60,
        datasets: [{
          label: 'Pkt/s',
          data: state.trafficHistory,
          borderColor: '#6366f1',
          backgroundColor: 'rgba(99,102,241,0.07)',
          borderWidth: 2, fill: true, tension: 0.4, pointRadius: 0,
        }]
      },
      options: { ...CHART_DEFAULTS, animation: { duration: 0 }, responsive: true }
    });
  }

  // Anomaly score chart
  const ac = document.getElementById('anomalyChart');
  if (ac) {
    anomalyChart = new Chart(ac, {
      type: 'line',
      data: {
        labels: labels60,
        datasets: [{
          label: 'Anomaly Score',
          data: state.anomalyHistory,
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239,68,68,0.06)',
          borderWidth: 2, fill: true, tension: 0.4, pointRadius: 0,
        }]
      },
      options: {
        ...CHART_DEFAULTS,
        animation: { duration: 0 }, responsive: true,
        scales: {
          x: { grid: { color: '#f1f5f9' }, ticks: { color: '#94a3b8' } },
          y: { min: 0, max: 1, grid: { color: '#f1f5f9' }, ticks: { color: '#94a3b8' } },
        }
      }
    });
  }
}

// ── Socket Events ──────────────────────────────
socket.on('connect', () => {
  document.getElementById('captureMode').textContent = 'Connected';
  loadAlerts();
});

socket.on('disconnect', () => {
  document.getElementById('captureMode').textContent = 'Disconnected';
});

socket.on('new_packet', (pkt) => {
  if (state.paused) return;
  state.pktCountLastSec++;
  state.packets.unshift(pkt);
  if (state.packets.length > 200) state.packets.pop();

  // Update anomaly history
  if (pkt.anomaly_score !== undefined) {
    state.anomalyHistory.shift();
    state.anomalyHistory.push(pkt.anomaly_score || 0);
    if (anomalyChart) {
      anomalyChart.data.datasets[0].data = [...state.anomalyHistory];
      anomalyChart.update('none');
    }
  }

  renderPacketRow(pkt);
  updateProtocolChart(pkt.protocol);
});

socket.on('new_alert', (alert) => {
  state.alerts.unshift(alert);
  showToast(alert);
  updateAlertBadge();
  if (document.getElementById('section-alerts').classList.contains('active')) {
    prependAlertCard(alert);
  }
});

socket.on('stats_update', (data) => {
  updateStats(data);
});

// ── Stats Update ───────────────────────────────
function updateStats(data) {
  const cap = data.capture || {};
  const ml = data.ml || {};

  animateCounter('totalPackets', fmtNum(cap.total_packets || 0));
  setText('ppsDisplay', `${cap.pps || 0} pkt/s`);
  animateCounter('bandwidth', cap.mbps || '0');
  setText('bytesTotal', `${((cap.bytes_total || 0) / 1e6).toFixed(2)} MB total`);

  // Traffic history
  state.trafficHistory.shift();
  state.trafficHistory.push(cap.pps || 0);
  if (trafficChart) {
    trafficChart.data.datasets[0].data = [...state.trafficHistory];
    trafficChart.update('none');
  }
  if (spikeChart) {
    spikeChart.data.datasets[0].data = [...state.trafficHistory];
    spikeChart.update('none');
  }

  // Capture mode indicator
  const mode = cap.simulation_mode ? '🧪 Simulation Mode' : '📡 Live Capture';
  setText('captureMode', mode);

  // ML stats
  if (ml) {
    const aiRateTxt = ml.is_trained ? (ml.anomaly_rate * 100).toFixed(1) + '%' : 'Training…';
    animateCounter('aiStatus', aiRateTxt);
    setText('aiSamples', `${ml.buffer_size || 0} samples`);
    setText('aiTrained', ml.is_trained ? '✅ Trained' : '⏳ Learning…');
    animateCounter('aiBufferSize', ml.buffer_size || 0);
    animateCounter('aiAvgScore', (ml.avg_anomaly_score || 0).toFixed(3));
    const ratePct = ((ml.anomaly_rate || 0) * 100).toFixed(1) + '%';
    animateCounter('aiAnomalyRate', ratePct);
    setText('aiMinSamples', `Min: ${ml.min_train_samples || 50}`);
  }

  // Top talkers
  if (data.top_talkers) renderTopTalkers(data.top_talkers);
}

function updateProtocolChart(proto) {
  if (!protocolChart) return;
  const idx = { TCP: 0, UDP: 1, ICMP: 2 };
  const i = idx[proto] ?? 3;
  protocolChart.data.datasets[0].data[i]++;
  protocolChart.update('none');
}

// ── Packet Feed ────────────────────────────────
function renderPacketRow(pkt) {
  const feed = document.getElementById('packetFeed');
  if (!feed) return;

  const filter = document.getElementById('filterProtocol')?.value;
  if (filter && pkt.protocol !== filter) return;

  const ts = pkt.timestamp ? pkt.timestamp.split('T')[1].split('.')[0] : '';
  const status = pkt.is_anomaly ? 'status-bad' : (pkt.anomaly_score > 0.4 ? 'status-warn' : 'status-ok');
  const statusText = pkt.is_anomaly ? '⚠ ANOMALY' : (pkt.anomaly_score > 0.4 ? '⚡ WARN' : '✓ OK');

  const row = document.createElement('div');
  row.className = `packet-row ${pkt.is_anomaly ? 'suspicious' : 'new-flash'}`;
  row.innerHTML = `
    <span>${ts}</span>
    <span title="${pkt.src_ip}">${pkt.src_ip || '–'}</span>
    <span title="${pkt.dst_ip}">${pkt.dst_ip || '–'}</span>
    <span>${pkt.src_port || '–'}</span>
    <span>${pkt.dst_port || '–'}</span>
    <span><span class="proto-badge ${pkt.protocol || 'OTHER'}">${pkt.protocol || '?'}</span></span>
    <span>${pkt.packet_size || 0}B</span>
    <span>${pkt.flags || '–'}</span>
    <span class="${status}">${statusText}</span>
  `;

  feed.insertBefore(row, feed.firstChild);
  // Remove flash class after animation
  setTimeout(() => row.classList.remove('new-flash'), 650);
  while (feed.children.length > 200) feed.removeChild(feed.lastChild);
}

function clearPacketFeed() {
  const feed = document.getElementById('packetFeed');
  if (feed) feed.innerHTML = '';
}

// ── Alerts ─────────────────────────────────────
let alertTypeCounts = { port_scan: 0, ddos: 0, blacklisted_ip: 0, unknown_ip: 0, ml_anomaly: 0 };
let severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

async function loadAlerts() {
  const sev = state.alertFilter ? `&severity=${state.alertFilter}` : '';
  const res = await fetch(`/api/alerts?page=${state.alertPage}&limit=20${sev}`);
  const data = await res.json();
  const list = document.getElementById('alertsList');
  if (!list) return;

  // Update alert counts for stats
  const statsRes = await fetch('/api/stats');
  const stats = await statsRes.json();
  setText('totalAlerts', fmtNum(stats.alerts?.unacknowledged || 0));
  setText('criticalAlerts', `${stats.alerts?.critical || 0} critical`);
  updateAlertBadge(stats.alerts?.unacknowledged || 0);

  if (state.alertPage === 1) {
    list.innerHTML = '';
    alertTypeCounts = { port_scan: 0, ddos: 0, blacklisted_ip: 0, unknown_ip: 0, ml_anomaly: 0 };
    severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  }

  data.alerts.forEach(alert => {
    prependAlertCard(alert, true);
    alertTypeCounts[alert.alert_type] = (alertTypeCounts[alert.alert_type] || 0) + 1;
    severityCounts[alert.severity] = (severityCounts[alert.severity] || 0) + 1;
  });

  updateAnalyticsCharts();
}

function prependAlertCard(alert, append = false) {
  const list = document.getElementById('alertsList');
  if (!list) return;

  const div = document.createElement('div');
  div.className = `alert-card ${alert.severity} ${alert.is_acknowledged ? 'acked' : ''}`;
  div.id = `alert-${alert.id}`;
  div.innerHTML = `
    <span class="sev-badge ${alert.severity}">${alert.severity}</span>
    <div class="alert-body">
      <div class="alert-desc">${escHtml(alert.description || '')}</div>
      <div class="alert-meta">
        <span>🕐 ${fmtTime(alert.timestamp)}</span>
        <span>📡 ${alert.source_ip || '?'} → ${alert.destination_ip || '?'}</span>
        <span>🔖 ${alert.alert_type?.replace('_', ' ').toUpperCase()}</span>
        ${alert.protocol ? `<span>📶 ${alert.protocol}</span>` : ''}
      </div>
    </div>
    ${!alert.is_acknowledged ? `<button class="btn-ack" onclick="ackAlert(${alert.id})">✓ Ack</button>` : '<span style="font-size:12px;color:#4ade80">✓ Acked</span>'}
  `;
  if (append) list.appendChild(div);
  else list.insertBefore(div, list.firstChild);
}

async function ackAlert(id) {
  await fetch(`/api/alerts/${id}/acknowledge`, { method: 'POST' });
  const card = document.getElementById(`alert-${id}`);
  if (card) card.classList.add('acked');
  const btn = card?.querySelector('.btn-ack');
  if (btn) btn.outerHTML = '<span style="font-size:12px;color:#4ade80">✓ Acked</span>';
}

function filterAlerts(severity, btn) {
  state.alertFilter = severity;
  state.alertPage = 1;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  loadAlerts();
}

function loadMoreAlerts() {
  state.alertPage++;
  loadAlerts();
}

function updateAlertBadge(count) {
  const badge = document.getElementById('alertBadge');
  if (!badge) return;
  const newVal = count !== undefined ? count : (parseInt(badge.textContent) + 1);
  badge.textContent = newVal;
  badge.classList.remove('bump');
  void badge.offsetWidth; // force reflow
  badge.classList.add('bump');
}

// ── Top Talkers ────────────────────────────────
function renderTopTalkers(talkers) {
  const el = document.getElementById('topTalkersTable');
  if (!el) return;
  if (!talkers?.length) { el.innerHTML = '<p style="color:#64748b;font-size:13px;padding:8px 0">No traffic data yet…</p>'; return; }
  const max = talkers[0]?.count || 1;
  el.innerHTML = talkers.map(t => `
    <div class="talker-row">
      <span class="talker-ip">${t.ip}</span>
      <div class="talker-bar-wrap"><div class="talker-bar" style="width:${(t.count/max*100).toFixed(1)}%"></div></div>
      <span class="talker-count">${t.count}</span>
    </div>
  `).join('');
}

// ── Analytics ──────────────────────────────────
function updateAnalyticsCharts() {
  if (alertTypeChart) {
    alertTypeChart.data.datasets[0].data = [
      alertTypeCounts.port_scan, alertTypeCounts.ddos,
      alertTypeCounts.blacklisted_ip, alertTypeCounts.unknown_ip,
      alertTypeCounts.ml_anomaly
    ];
    alertTypeChart.update();
  }
  if (severityChart) {
    severityChart.data.datasets[0].data = [
      severityCounts.CRITICAL, severityCounts.HIGH, severityCounts.MEDIUM, severityCounts.LOW
    ];
    severityChart.update();
  }
}

// ── Navigation ─────────────────────────────────
function navigate(section) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const el = document.getElementById(`section-${section}`);
  if (el) el.classList.add('active');
  const nav = document.getElementById(`nav-${section}`);
  if (nav) nav.classList.add('active');
  const bc = document.getElementById('breadcrumb');
  if (bc) bc.textContent = { overview: 'Overview', 'live-traffic': 'Live Traffic', alerts: 'Alerts', analytics: 'Analytics', 'ai-engine': 'AI Engine' }[section] || section;

  if (section === 'alerts') loadAlerts();
}

document.querySelectorAll('.nav-item[data-section]').forEach(el => {
  el.addEventListener('click', e => {
    e.preventDefault();
    navigate(el.dataset.section);
  });
});

function toggleSidebar() {
  document.getElementById('sidebar')?.classList.toggle('open');
}

// ── AI Engine ──────────────────────────────────
async function forceTrainAI() {
  const res = await fetch('/api/ml/train', { method: 'POST' });
  const data = await res.json();
  const el = document.getElementById('trainResult');
  if (el) el.textContent = data.trained ? '✅ Model retrained!' : '❌ Training failed (need more samples)';
  setTimeout(() => { if (el) el.textContent = ''; }, 4000);
}

// ── Toast Notifications ────────────────────────
const SEVERITY_ICONS = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' };

function showToast(alert) {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast ${alert.severity}`;
  toast.innerHTML = `
    <div class="toast-title">${SEVERITY_ICONS[alert.severity] || '⚠️'} ${alert.severity} — ${alert.alert_type?.replace('_', ' ').toUpperCase()}</div>
    <div class="toast-body">${escHtml(alert.description || '')}</div>
  `;
  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateX(20px)'; toast.style.transition = 'all 0.4s'; setTimeout(() => toast.remove(), 400); }, 5000);
}

// ── Clock ──────────────────────────────────────
function updateClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString();
}
setInterval(updateClock, 1000);
updateClock();

// ── Pause feed ─────────────────────────────────
document.getElementById('pauseFeed')?.addEventListener('change', e => { state.paused = e.target.checked; });

// ── Helpers ────────────────────────────────────
function setText(id, val) { const el = document.getElementById(id); if (el) el.textContent = val; }
function fmtNum(n) { return n >= 1e6 ? (n/1e6).toFixed(1)+'M' : n >= 1e3 ? (n/1e3).toFixed(1)+'K' : String(n); }
function fmtTime(ts) { try { return new Date(ts).toLocaleTimeString(); } catch { return ts; } }
function escHtml(str) { const d = document.createElement('div'); d.appendChild(document.createTextNode(str)); return d.innerHTML; }

// ── Animated counter ───────────────────────────
const _counterState = {};
function animateCounter(id, targetRaw) {
  const el = document.getElementById(id);
  if (!el) return;
  const isNum = typeof targetRaw === 'number' || /^[\d.]+[KM]?$/.test(String(targetRaw));
  if (!isNum) { setText(id, targetRaw); return; }
  const target = parseFloat(String(targetRaw).replace(/[KM]/, ''));
  const suffix = String(targetRaw).replace(/[\d.]/g, '');
  const prev = _counterState[id] || 0;
  _counterState[id] = target;
  if (Math.abs(target - prev) < 0.01) return;
  const steps = 18; const diff = target - prev;
  let step = 0;
  clearInterval(_counterState[id + '_t']);
  el.classList.add('updated');
  el.addEventListener('animationend', () => el.classList.remove('updated'), { once: true });
  _counterState[id + '_t'] = setInterval(() => {
    step++;
    const ease = 1 - Math.pow(1 - step / steps, 3);
    const val = prev + diff * ease;
    el.textContent = (val >= 1e6 ? (val/1e6).toFixed(1)+'M' : val >= 1e3 ? (val/1e3).toFixed(1)+'K' : val >= 10 ? Math.round(val) : val.toFixed(2)) + (suffix || '');
    if (step >= steps) { clearInterval(_counterState[id + '_t']); el.textContent = targetRaw; }
  }, 30);
}

// ── Init ───────────────────────────────────────
initCharts();
loadAlerts();

// Scroll-based fade-in observer
const observer = new IntersectionObserver(entries => {
  entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('visible'); observer.unobserve(e.target); } });
}, { threshold: 0.1 });
document.querySelectorAll('.card, .chart-card').forEach(el => { el.classList.add('fade-up'); observer.observe(el); });

// Periodic stats refresh fallback (in case socket is slow)
setInterval(async () => {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    const talkers = await fetch('/api/top_talkers').then(r => r.json());
    updateStats({ capture: data.capture, ml: data.ml, top_talkers: talkers.top_talkers });
  } catch {}
}, 5000);
