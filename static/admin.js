/* Admin Panel JavaScript */

function updateClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString();
}
setInterval(updateClock, 1000);
updateClock();

// ── Toast helper ──────────────────────────────
function showToast(msg, type = 'success') {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const t = document.createElement('div');
  t.className = 'toast';
  t.innerHTML = `<div class="toast-title">${type === 'success' ? '✅' : '❌'} ${msg}</div>`;
  container.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

// ── Load Stats ────────────────────────────────
async function loadStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    const cap = data.capture || {};
    const ml = data.ml || {};
    setText('captureStatusTxt', cap.simulation_mode !== undefined ? (cap.simulation_mode ? '🧪 Simulation' : '📡 Live') : '–');
    setText('captureModeTxt', cap.total_packets !== undefined ? 'Running' : 'Stopped');
    setText('adminTotalPkts', fmtNum(cap.total_packets || 0));
    setText('adminUptime', cap.uptime_seconds ? `${Math.floor(cap.uptime_seconds / 60)}m ${(cap.uptime_seconds % 60).toFixed(0)}s` : '–');
    setText('adminAiTrained', ml.is_trained ? '✅ Yes' : '⏳ Training…');
    setText('adminAiSamples', `${ml.buffer_size || 0} / ${ml.min_train_samples || 50}`);
    setText('adminAiRate', `${((ml.anomaly_rate || 0) * 100).toFixed(1)}%`);
    setText('adminAiScore', (ml.avg_anomaly_score || 0).toFixed(4));
  } catch (e) { console.error('Stats load error', e); }
}

// ── Blacklist ─────────────────────────────────
async function loadBlacklist() {
  const res = await fetch('/api/blacklist');
  const data = await res.json();
  const tbody = document.getElementById('blacklistTable');
  const count = document.getElementById('blacklistCount');
  if (count) count.textContent = `${data.blacklist.length} IPs`;
  if (!tbody) return;
  tbody.innerHTML = data.blacklist.map(ip => `
    <tr>
      <td style="font-family:'JetBrains Mono',monospace;color:#38bdf8">${ip.ip_address}</td>
      <td style="color:#94a3b8">${ip.reason || '–'}</td>
      <td style="color:#64748b;font-size:12px">${fmtTime(ip.added_at)}</td>
      <td><button class="btn-danger-sm" onclick="removeFromBlacklist(${ip.id})">🗑 Remove</button></td>
    </tr>
  `).join('');
}

async function addToBlacklist() {
  const ip = document.getElementById('newBlacklistIP').value.trim();
  const reason = document.getElementById('newBlacklistReason').value.trim();
  if (!ip) return showToast('Enter an IP address', 'error');
  const res = await fetch('/api/blacklist', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip_address: ip, reason })
  });
  const data = await res.json();
  if (data.success) {
    showToast(`${ip} added to blacklist`);
    document.getElementById('newBlacklistIP').value = '';
    document.getElementById('newBlacklistReason').value = '';
    loadBlacklist();
  } else {
    showToast(data.error || 'Failed', 'error');
  }
}

async function removeFromBlacklist(id) {
  if (!confirm('Remove this IP from blacklist?')) return;
  await fetch(`/api/blacklist/${id}`, { method: 'DELETE' });
  showToast('IP removed from blacklist');
  loadBlacklist();
}

// ── Users ─────────────────────────────────────
async function loadUsers() {
  const res = await fetch('/api/users');
  const data = await res.json();
  const tbody = document.getElementById('usersTable');
  const count = document.getElementById('userCount');
  if (count) count.textContent = `${data.users.length} users`;
  if (!tbody) return;
  tbody.innerHTML = data.users.map(u => `
    <tr>
      <td style="font-weight:600">${u.username}</td>
      <td style="color:#64748b;font-size:12px">${u.email || '–'}</td>
      <td><span class="role-badge ${u.role}">${u.role}</span></td>
      <td style="color:#64748b;font-size:12px">${u.last_login ? fmtTime(u.last_login) : 'Never'}</td>
      <td><button class="btn-danger-sm" onclick="deleteUser(${u.id}, '${u.username}')">🗑 Delete</button></td>
    </tr>
  `).join('');
}

async function createUser() {
  const username = document.getElementById('newUsername').value.trim();
  const password = document.getElementById('newPassword').value;
  const email = document.getElementById('newEmail').value.trim();
  const role = document.getElementById('newRole').value;
  if (!username || !password) return showToast('Username and password required', 'error');
  const res = await fetch('/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, email, role })
  });
  const data = await res.json();
  if (data.success) {
    showToast(`User ${username} created`);
    ['newUsername', 'newPassword', 'newEmail'].forEach(id => document.getElementById(id).value = '');
    loadUsers();
  } else {
    showToast(data.error || 'Failed', 'error');
  }
}

async function deleteUser(id, name) {
  if (!confirm(`Delete user "${name}"?`)) return;
  const res = await fetch(`/api/users/${id}`, { method: 'DELETE' });
  const data = await res.json();
  if (data.success) { showToast(`User ${name} deleted`); loadUsers(); }
  else showToast(data.error || 'Failed', 'error');
}

// ── Capture Control ───────────────────────────
async function startCapture() {
  const res = await fetch('/api/capture/start', { method: 'POST' });
  const data = await res.json();
  showToast(data.message);
  setTimeout(loadStats, 500);
}

async function stopCapture() {
  const res = await fetch('/api/capture/stop', { method: 'POST' });
  const data = await res.json();
  showToast(data.message);
  setTimeout(loadStats, 500);
}

// ── ML Force Train ────────────────────────────
async function forceTrainAdmin() {
  const res = await fetch('/api/ml/train', { method: 'POST' });
  const data = await res.json();
  const el = document.getElementById('adminTrainMsg');
  if (el) {
    el.textContent = data.trained ? '✅ Model retrained!' : '❌ Need more samples';
    setTimeout(() => { el.textContent = ''; }, 4000);
  }
}

// ── Helpers ───────────────────────────────────
function setText(id, val) { const el = document.getElementById(id); if (el) el.textContent = val; }
function fmtNum(n) { return n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'K' : String(n); }
function fmtTime(ts) { try { return new Date(ts).toLocaleString(); } catch { return ts; } }

// ── Init ──────────────────────────────────────
loadStats();
loadBlacklist();
loadUsers();
setInterval(loadStats, 5000);
