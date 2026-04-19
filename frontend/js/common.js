/* common.js — auth, navigation, shared utilities */
'use strict';

const PAGES = [
  { id:'dashboard',    href:'dashboard.html',   icon:'⊞',  label:'Dashboard',       group:'MAIN' },
  { id:'scan',         href:'scan.html',         icon:'↑',  label:'New Scan',         group:'MAIN' },
  { id:'results',      href:'results.html',      icon:'≡',  label:'Detection Results',group:'ANALYSIS' },
  { id:'risk_summary', href:'risk_summary.html', icon:'◎',  label:'Risk Summary',     group:'ANALYSIS' },
  { id:'reports',      href:'reports.html',      icon:'↓',  label:'Download Reports', group:'ANALYSIS' },
  { id:'whitelist',    href:'whitelist.html',    icon:'✓',  label:'Access Points',    group:'MANAGE' },
  { id:'history',      href:'history.html',      icon:'◷',  label:'Scan History',     group:'MANAGE' },
  { id:'users',        href:'users.html',        icon:'⚙',  label:'Users',            group:'ADMIN', adminOnly: true },
];

/* ── Auth ──────────────────────────────────────────────────────────── */
async function checkAuth() {
  try {
    const res = await fetch('/api/me');
    if (!res.ok) { window.location.href = '/'; return null; }
    return await res.json();
  } catch { window.location.href = '/'; return null; }
}

async function logout() {
  await fetch('/api/logout', { method:'POST' });
  window.location.href = '/';
}

/* ── Render sidebar ────────────────────────────────────────────────── */
function renderNav(currentId, user) {
  const sb = document.getElementById('sidebar');
  if (!sb) return;

  const isAdmin = user?.role === 'admin';
  const visiblePages = PAGES.filter(p => !p.adminOnly || isAdmin);
  const groups = [...new Set(visiblePages.map(p=>p.group))];
  const initial = (user?.username||'A')[0].toUpperCase();

  let html = `
    <div class="sidebar-brand">
      <div class="brand-icon">🛡</div>
      <div>
        <div class="brand-name">RogueShield</div>
      </div>
    </div>
    <nav class="sidebar-nav">`;

  groups.forEach(g => {
    html += `<div class="nav-group"><div class="nav-group-label">${g}</div>`;
    visiblePages.filter(p=>p.group===g).forEach(p => {
      const active = p.id===currentId ? ' active' : '';
      html += `<a class="nav-item${active}" href="${p.href}">
        <span class="nav-icon">${p.icon}</span>
        <span>${p.label}</span>
      </a>`;
    });
    html += `</div>`;
  });

  html += `</nav>
    <div class="sidebar-footer">
      <div class="user-card" onclick="window.location.href='profile.html'">
        <div class="user-avatar">${initial}</div>
        <div class="user-info">
          <div class="user-name">${user?.username||'Admin'}</div>
          <div class="user-role">${user?.role||'Administrator'}</div>
        </div>
        <button class="logout-btn" onclick="event.stopPropagation();logout()" title="Sign out">⏻</button>
      </div>
    </div>`;

  sb.innerHTML = html;
}

/* ── Init page ─────────────────────────────────────────────────────── */
async function initPage(pageId) {
  const user = await checkAuth();
  if (!user) return null;
  renderNav(pageId, user);
  _injectOverlays();
  return user;
}

function _injectOverlays() {
  if (!document.getElementById('loadingOverlay')) {
    document.body.insertAdjacentHTML('beforeend',
      `<div class="loading-overlay" id="loadingOverlay">
         <div class="spinner"></div>
         <div class="loading-text" id="loadingText">Loading…</div>
       </div>`);
  }
  if (!document.getElementById('toast')) {
    document.body.insertAdjacentHTML('beforeend', `<div class="toast" id="toast"></div>`);
  }
}

/* ── Loading & toast ───────────────────────────────────────────────── */
function showLoading(show, msg='Loading…') {
  const el = document.getElementById('loadingOverlay');
  if (!el) return;
  el.classList.toggle('active', show);
  const t = document.getElementById('loadingText');
  if (t) t.textContent = msg;
}

function showToast(msg, type='success') {
  _injectOverlays();
  const t = document.getElementById('toast');
  if (!t) return;
  const icon = type==='error' ? '✕' : type==='warning' ? '⚠' : '✓';
  t.innerHTML = `<span>${icon}</span><span>${msg}</span>`;
  t.className = `toast show ${type}`;
  clearTimeout(t._t);
  t._t = setTimeout(() => t.classList.remove('show'), 3500);
}

/* ── Session storage helpers ───────────────────────────────────────── */
function setCurrentScan(id) { sessionStorage.setItem('currentScanId', id); }
function getCurrentScan()   { return sessionStorage.getItem('currentScanId'); }

/* ── Fetch helper ──────────────────────────────────────────────────── */
async function apiFetch(url, opts={}) {
  const res = await fetch(url, opts);
  if (res.status === 401) { window.location.href = '/'; return null; }
  return res;
}

/* ── Download helper ───────────────────────────────────────────────── */
async function downloadFile(url, fallback) {
  const res = await apiFetch(url);
  if (!res || !res.ok) { showToast('Download failed','error'); return; }
  const blob = await res.blob();
  const href = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = href;
  const cd = res.headers.get('content-disposition')||'';
  const m  = cd.match(/filename="?([^"]+)"?/);
  a.download = m ? m[1] : fallback;
  a.click(); URL.revokeObjectURL(href);
}

/* ── Render helpers ────────────────────────────────────────────────── */
function verdictBadge(v) {
  const k = v==='LOW RISK'?'LOWRISK':v.split(' ')[0];
  return `<span class="badge ${k}">${v}</span>`;
}
function sevBadge(s) { return `<span class="badge ${s}">${s}</span>`; }
function scoreBar(score, max) {
  const pct = Math.round((score/Math.max(max,1))*100);
  const col = score>=5 ? 'var(--red-500)' : score>=3 ? 'var(--orange-500)' : 'var(--green-500)';
  return `<div class="score-wrap">
    <span class="score-num" style="color:${col}">${score}</span>
    <div class="score-track">
      <div class="score-fill" style="width:${pct}%;background:${col}"></div>
    </div></div>`;
}
