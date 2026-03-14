// ============================================================
//  NEXUS SOC — Banking Cyber Defense Dashboard Engine
//  Simulates real-time multi-agent cybersecurity monitoring
// ============================================================
 
// ─── Clock ───────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent =
    now.toTimeString().slice(0, 8);
}
setInterval(updateClock, 1000);
updateClock();
 
// ─── Simulation State ────────────────────────────────────────
const state = {
  running: false,
  transactions: 48291,
  suspicious: 127,
  users: 3847,
  blockedIPs: 34,
  blockedMACs: 19,
  threatScore: 75,
  attackMode: false,
  intervalIds: [],
};
 
// ─── Sample Data ─────────────────────────────────────────────
const AUTH_DATA = [
  { user:'USR_4421', method:'PATTERN', device:'Unknown Android', ip:'192.168.4.22', loc:'Mumbai', time:'09:47', ok:false, anomaly:'HIGH', prevMethod:'FINGERPRINT' },
  { user:'USR_1190', method:'FINGERPRINT', device:'iPhone 15', ip:'10.0.0.88', loc:'Delhi', time:'09:51', ok:true, anomaly:'MED', prevMethod:'FINGERPRINT' },
  { user:'USR_7734', method:'FACIAL', device:'MacBook Pro', ip:'172.16.1.4', loc:'Bangalore', time:'09:53', ok:true, anomaly:'LOW', prevMethod:'FACIAL' },
  { user:'USR_2234', method:'PASSWORD', device:'Windows PC', ip:'172.16.8.44', loc:'Pune', time:'09:54', ok:false, anomaly:'HIGH', prevMethod:'FACIAL' },
  { user:'USR_5512', method:'FINGERPRINT', device:'Samsung S24', ip:'192.168.1.105', loc:'Hyderabad', time:'09:56', ok:true, anomaly:'LOW', prevMethod:'FINGERPRINT' },
  { user:'USR_3391', method:'PATTERN', device:'iPad Air', ip:'10.10.5.22', loc:'Chennai', time:'09:58', ok:true, anomaly:'LOW', prevMethod:'PATTERN' },
  { user:'USR_8812', method:'PASSWORD', device:'Unknown PC', ip:'45.142.212.100', loc:'Unknown', time:'10:01', ok:false, anomaly:'HIGH', prevMethod:'FINGERPRINT' },
];
 
const NETWORK_DATA = [
  { ip:'192.168.4.22',    mac:'A4:B2:C8:D1:E9:F2', device:'Mobile',   freq:'HIGH',   loc:'Mumbai',    status:'SUSPICIOUS' },
  { ip:'45.142.212.100',  mac:'F8:3A:77:C2:11:DE', device:'Unknown',  freq:'EXTREME', loc:'Unknown',   status:'BLOCKED' },
  { ip:'172.16.1.4',      mac:'B8:27:EB:12:34:56', device:'Desktop',  freq:'NORMAL', loc:'Bangalore', status:'TRUSTED' },
  { ip:'10.0.0.88',       mac:'D4:61:9D:AB:CD:EF', device:'Mobile',   freq:'NORMAL', loc:'Delhi',     status:'TRUSTED' },
  { ip:'185.220.101.44',  mac:'C0:FF:EE:BA:AD:01', device:'VPN/Tor',  freq:'HIGH',   loc:'Unknown',   status:'BLOCKED' },
  { ip:'172.16.8.44',     mac:'AC:DE:48:00:11:22', device:'Desktop',  freq:'MEDIUM', loc:'Pune',      status:'FLAGGED' },
  { ip:'192.168.1.105',   mac:'78:4F:43:55:6A:BC', device:'Mobile',   freq:'NORMAL', loc:'Hyderabad', status:'TRUSTED' },
];
 
const FEED_TEMPLATES = [
  { type:'alert',  msgs:['Suspicious login from {ip} — auth change detected for {user}',
                         'Credential stuffing attempt detected — {n} attempts from {ip}',
                         'Anomaly score elevated for {user} — unusual login time 03:{mm}'] },
  { type:'warn',   msgs:['Authentication pattern anomaly — {user} device fingerprint mismatch',
                         'Multiple failed 2FA attempts from {ip} — possible MFA fatigue attack',
                         'Unusual geographic location for {user} — {loc}'] },
  { type:'block',  msgs:['IP {ip} blocked — threat score exceeded threshold ({score})',
                         'MAC {mac} quarantined — device fingerprint in threat database',
                         'Account {user} temporarily frozen — suspicious activity detected'] },
  { type:'info',   msgs:['ML model rescored {n} transactions — {pct}% flagged for review',
                         'LSTM behavior model updated — baseline recalibrated for {n} users',
                         'Network sweep complete — {n} new devices registered'] },
  { type:'ok',     msgs:['Threat resolved — {user} verified via MFA, score reduced to {n}',
                         'False positive cleared — {user} confirmed legitimate login',
                         'IP {ip} removed from blocklist after manual review'] },
];
 
const ATTACK_SCENARIOS = [
  {
    name: 'COSMOS BANK STYLE ATTACK',
    events: [
      { delay:0,    type:'warn',  msg:'⚠ SWIFT message injection detected — malformed MT103 packet from 185.44.12.199' },
      { delay:1500, type:'alert', msg:'🔴 Parallel ATM fraud detected — 15,000+ simultaneous transactions in 2h window' },
      { delay:3000, type:'block', msg:'⊘ IP 185.44.12.199 blocked — SWIFT network anomaly. Isolating banking core.' },
      { delay:4500, type:'alert', msg:'🔴 Fake HSM response detected — fraudulent transaction approval bypass attempted' },
      { delay:6000, type:'block', msg:'⊘ CRITICAL: 3 operator accounts frozen — insider threat indicators detected' },
    ]
  },
  {
    name: 'BRUTE FORCE + CREDENTIAL THEFT',
    events: [
      { delay:0,    type:'warn',  msg:'⚠ Credential stuffing detected — 4,200 login attempts in 90 seconds from botnet' },
      { delay:2000, type:'alert', msg:'🔴 248 accounts compromised — password spray attack successful on weak passwords' },
      { delay:4000, type:'block', msg:'⊘ IP range 45.142.212.0/24 blocked — botnet C2 infrastructure identified' },
      { delay:5500, type:'info',  msg:'ℹ Isolation Forest flagged 248 anomalous sessions — auto-MFA triggered' },
    ]
  },
  {
    name: 'BIOMETRIC FRAUD ATTEMPT',
    events: [
      { delay:0,    type:'alert', msg:'🔴 Deepfake facial scan detected — liveness check failed for 12 accounts' },
      { delay:2000, type:'warn',  msg:'⚠ Biometric template replay attack — encrypted template hash mismatch' },
      { delay:3500, type:'block', msg:'⊘ Facial auth temporarily disabled — AES-256 template re-encryption initiated' },
      { delay:5000, type:'info',  msg:'ℹ LSTM model detected coordinated attack pattern — 12 accounts quarantined' },
    ]
  },
];
 
// ─── Chart.js Configs ────────────────────────────────────────
let txChart, authChart, fraudChart;
 
function initCharts() {
  // Transaction + Anomaly Chart
  const txCtx = document.getElementById('transactionChart').getContext('2d');
  const labels = Array.from({length:24}, (_,i) => `${String(i).padStart(2,'0')}:00`);
  const txData = [1200,900,700,500,400,300,400,800,2100,3400,4100,4500,4300,3900,4200,4600,4100,3800,3500,3200,2900,2400,2100,1800];
  const anomData = [2,1,0,0,0,0,0,1,3,8,15,22,18,12,10,8,30,25,18,12,9,7,4,3];
 
  txChart = new Chart(txCtx, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          type: 'bar',
          label: 'Transactions',
          data: txData,
          backgroundColor: 'rgba(0,200,255,0.18)',
          borderColor: 'rgba(0,200,255,0.5)',
          borderWidth: 1,
          yAxisID: 'y',
        },
        {
          type: 'line',
          label: 'Anomaly Score',
          data: anomData,
          borderColor: '#ff3860',
          backgroundColor: 'rgba(255,56,96,0.1)',
          borderWidth: 2,
          pointRadius: 0,
          fill: true,
          tension: 0.4,
          yAxisID: 'y1',
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { display: false }, tooltip: {
        backgroundColor: 'rgba(7,14,26,0.95)',
        borderColor: 'rgba(0,200,255,0.3)',
        borderWidth: 1,
        titleFont: { family: 'Share Tech Mono', size: 10 },
        bodyFont: { family: 'Share Tech Mono', size: 10 },
        titleColor: '#00c8ff',
        bodyColor: 'rgba(200,230,255,0.8)',
      }},
      scales: {
        x: {
          ticks: { color: 'rgba(200,230,255,0.3)', font: { family: 'Share Tech Mono', size: 9 }, maxRotation: 0 },
          grid: { color: 'rgba(0,200,255,0.05)' },
        },
        y: {
          type: 'linear',
          position: 'left',
          ticks: { color: 'rgba(0,200,255,0.5)', font: { family: 'Share Tech Mono', size: 9 } },
          grid: { color: 'rgba(0,200,255,0.06)' },
        },
        y1: {
          type: 'linear',
          position: 'right',
          ticks: { color: 'rgba(255,56,96,0.5)', font: { family: 'Share Tech Mono', size: 9 } },
          grid: { drawOnChartArea: false },
        },
      }
    }
  });
 
  // Auth Doughnut
  const authCtx = document.getElementById('authChart').getContext('2d');
  authChart = new Chart(authCtx, {
    type: 'doughnut',
    data: {
      labels: ['Fingerprint','Facial','Pattern','Password'],
      datasets: [{
        data: [42,28,18,12],
        backgroundColor: ['rgba(0,200,255,0.7)','rgba(168,85,247,0.7)','rgba(255,179,0,0.7)','rgba(255,56,96,0.7)'],
        borderColor: ['#00c8ff','#a855f7','#ffb300','#ff3860'],
        borderWidth: 1,
        hoverOffset: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '65%',
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(7,14,26,0.95)',
          titleFont: { family: 'Share Tech Mono', size: 10 },
          bodyFont: { family: 'Share Tech Mono', size: 10 },
          titleColor: '#00c8ff',
          bodyColor: 'rgba(200,230,255,0.8)',
        }
      }
    }
  });
 
  // Fraud sparkline
  const fCtx = document.getElementById('fraudChart').getContext('2d');
  const fraudData = [3,5,4,8,6,4,3,5,12,18,8,6,4,3,7,22,15,8,5,4,3,6,4,3];
  fraudChart = new Chart(fCtx, {
    type: 'line',
    data: {
      labels: fraudData.map((_,i) => i),
      datasets: [{
        label: 'Fraud Events',
        data: fraudData,
        borderColor: '#ff3860',
        backgroundColor: 'rgba(255,56,96,0.08)',
        borderWidth: 1.5,
        pointRadius: 0,
        fill: true,
        tension: 0.4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      scales: {
        x: { display: false },
        y: {
          display: true,
          ticks: { color: 'rgba(255,56,96,0.4)', font: { family: 'Share Tech Mono', size: 9 }, maxTicksLimit: 4 },
          grid: { color: 'rgba(255,56,96,0.06)' },
        }
      }
    }
  });
}
 
// ─── Table Rendering ─────────────────────────────────────────
function renderAuthTable(data) {
  const tbody = document.getElementById('auth-tbody');
  tbody.innerHTML = '';
  data.forEach(row => {
    const methodClass = {FINGERPRINT:'auth-fp',FACIAL:'auth-face',PATTERN:'auth-pat',PASSWORD:'auth-pwd'}[row.method] || 'auth-fp';
    const anomalyClass = {HIGH:'anomaly-high',MED:'anomaly-med',LOW:'anomaly-low'}[row.anomaly];
    const statusClass = row.ok ? 'status-ok' : 'status-fail';
    const changed = row.prevMethod !== row.method;
    const tr = document.createElement('tr');
    if (!row.ok || row.anomaly === 'HIGH') tr.style.background = 'rgba(255,56,96,0.03)';
    tr.innerHTML = `
      <td>${row.user}</td>
      <td><span class="auth-method ${methodClass}">${row.method}</span>${changed ? ' <span style="color:var(--amber);font-size:9px;">↓${row.prevMethod}</span>' : ''}</td>
      <td>${row.device}</td>
      <td>${row.ip}</td>
      <td>${row.loc}</td>
      <td>${row.time}</td>
      <td class="${statusClass}">${row.ok ? '✓ OK' : '✗ FAIL'}</td>
      <td><span class="anomaly-badge ${anomalyClass}">${row.anomaly}</span></td>
    `;
    tbody.appendChild(tr);
  });
}
 
function renderNetworkTable(data) {
  const tbody = document.getElementById('network-tbody');
  tbody.innerHTML = '';
  data.forEach(row => {
    const statusColors = {
      TRUSTED: 'status-ok',
      SUSPICIOUS: 'status-warn',
      BLOCKED: 'status-fail',
      FLAGGED: 'status-warn',
    };
    const tr = document.createElement('tr');
    if (row.status === 'SUSPICIOUS' || row.status === 'BLOCKED') {
      tr.className = 'net-row-suspicious';
    }
    tr.innerHTML = `
      <td>${row.ip}</td>
      <td style="font-size:10px;">${row.mac}</td>
      <td>${row.device}</td>
      <td class="${row.freq==='EXTREME'||row.freq==='HIGH'?'status-warn':''}">${row.freq}</td>
      <td>${row.loc}</td>
      <td class="${statusColors[row.status]||''}">${row.status}</td>
    `;
    tbody.appendChild(tr);
  });
}
 
function addGeoDots() {
  const map = document.getElementById('geo-dots');
  const locations = [
    { top:'42%', left:'72%', color:'var(--red)', label:'Suspicious' },
    { top:'38%', left:'68%', color:'var(--amber)', label:'Mumbai' },
    { top:'36%', left:'70%', color:'var(--cyan)', label:'Delhi' },
    { top:'44%', left:'71%', color:'var(--green)', label:'Bangalore' },
    { top:'35%', left:'38%', color:'var(--red)', label:'Unknown' },
    { top:'32%', left:'25%', color:'var(--red)', label:'Attacker' },
  ];
  map.innerHTML = '';
  locations.forEach(l => {
    const dot = document.createElement('div');
    dot.className = 'geo-dot';
    dot.style.cssText = `top:${l.top};left:${l.left};background:${l.color};color:${l.color};`;
    map.appendChild(dot);
  });
}
 
// ─── Threat Score Gauge ──────────────────────────────────────
function updateThreatGauge(score) {
  const circumference = 301.6;
  const pct = Math.min(score / 100, 1);
  const dashOffset = circumference - pct * circumference;
  const ring = document.getElementById('threat-ring');
  const label = document.getElementById('threat-score');
  if (ring) ring.style.strokeDashoffset = dashOffset;
  if (label) label.textContent = score;
  document.getElementById('threat-count').textContent = score > 60 ? '🔴 HIGH THREAT' : '✓ NORMAL';
}
 
// ─── Counter Animation ───────────────────────────────────────
function animateCounter(id, target, prefix='', suffix='') {
  const el = document.getElementById(id);
  if (!el) return;
  const start = parseInt(el.textContent.replace(/[^0-9]/g,'')) || 0;
  const diff = target - start;
  const steps = 20;
  let step = 0;
  const interval = setInterval(() => {
    step++;
    const val = Math.round(start + diff * (step / steps));
    el.textContent = prefix + val.toLocaleString() + suffix;
    if (step >= steps) clearInterval(interval);
  }, 30);
}
 
// ─── Live Feed ───────────────────────────────────────────────
function addFeedItem(type, msg, time) {
  const feed = document.getElementById('feed-list');
  const item = document.createElement('div');
  item.className = `feed-item ${type}`;
  const typeLabels = { alert:'ALERT', warn:'WARNING', block:'BLOCKED', info:'INFO', ok:'RESOLVED' };
  const now = time || new Date().toTimeString().slice(0,5);
  item.innerHTML = `
    <span class="feed-type">${typeLabels[type]||type.toUpperCase()}</span>
    <span class="feed-msg">${msg}</span>
    <span class="feed-time">${now}</span>
  `;
  feed.insertBefore(item, feed.firstChild);
  if (feed.children.length > 20) feed.removeChild(feed.lastChild);
}
 
// ─── Timeline ─────────────────────────────────────────────────
function addTimelineItem(type, agent, text) {
  const timeline = document.getElementById('timeline');
  const item = document.createElement('div');
  item.className = 'timeline-item';
  const icons = { alert:'🔴', warn:'⚠', block:'⊘', info:'ℹ', ok:'✓' };
  const dotClass = { alert:'tl-alert', warn:'tl-warn', block:'tl-block', info:'tl-info', ok:'tl-ok' };
  const now = new Date().toTimeString().slice(0,8);
  item.innerHTML = `
    <div class="timeline-dot ${dotClass[type]||'tl-info'}">${icons[type]||'•'}</div>
    <div class="timeline-content">
      <div class="timeline-time">${now} — ${agent}</div>
      <div class="timeline-text">${text}</div>
    </div>
  `;
  // Insert at top after first item
  const second = timeline.children[1];
  if (second) timeline.insertBefore(item, second);
  else timeline.appendChild(item);
  if (timeline.children.length > 12) timeline.removeChild(timeline.lastChild);
}
 
// ─── Simulation Engine ───────────────────────────────────────
function startSimulation() {
  if (state.running) return;
  state.running = true;
  document.getElementById('sim-status').textContent = '● SIMULATION RUNNING — MONITORING LIVE';
  document.getElementById('sim-status').style.color = 'var(--green)';
 
  // Random feed generator
  const feedId = setInterval(() => {
    if (!state.running) return;
    const tpl = FEED_TEMPLATES[Math.floor(Math.random() * FEED_TEMPLATES.length)];
    const msgs = tpl.msgs;
    let msg = msgs[Math.floor(Math.random() * msgs.length)];
    msg = msg
      .replace('{ip}', `${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}`)
      .replace('{user}', `USR_${Math.floor(Math.random()*9000+1000)}`)
      .replace('{n}', Math.floor(Math.random()*500+10))
      .replace('{pct}', (Math.random()*8+1).toFixed(1))
      .replace('{loc}', ['Mumbai','Delhi','Unknown','Singapore','Unknown Country'][Math.floor(Math.random()*5)])
      .replace('{mac}', `${Math.floor(Math.random()*256).toString(16).padStart(2,'0').toUpperCase()}:${Math.floor(Math.random()*256).toString(16).padStart(2,'0').toUpperCase()}:XX:XX:XX:XX`)
      .replace('{score}', Math.floor(Math.random()*30+60))
      .replace('{mm}', String(Math.floor(Math.random()*60)).padStart(2,'0'));
    addFeedItem(tpl.type, msg);
  }, 3500);
 
  // Metrics updater
  const metricsId = setInterval(() => {
    if (!state.running) return;
    state.transactions += Math.floor(Math.random() * 40 + 10);
    state.users = Math.max(3000, state.users + Math.floor(Math.random() * 20 - 8));
    if (Math.random() < 0.15) { state.suspicious++; animateCounter('m-suspicious', state.suspicious); }
    animateCounter('m-transactions', state.transactions);
    animateCounter('m-users', state.users);
 
    // Update agent values
    document.getElementById('agent-net-val').textContent = (Math.floor(Math.random()*800+2200)).toLocaleString();
  }, 2000);
 
  // Threat score drift
  const threatId = setInterval(() => {
    if (!state.running) return;
    const drift = (Math.random() - 0.45) * 5;
    state.threatScore = Math.max(10, Math.min(98, Math.round(state.threatScore + drift)));
    updateThreatGauge(state.threatScore);
    if (state.threatScore > 80) {
      addFeedItem('alert', `⚠ Threat score critical: ${state.threatScore}/100 — auto-response triggered`);
    }
  }, 4000);
 
  // Chart live data update
  const chartId = setInterval(() => {
    if (!state.running || !txChart) return;
    const data = txChart.data.datasets[0].data;
    data.push(Math.floor(Math.random()*2000+3000));
    data.shift();
    const anom = txChart.data.datasets[1].data;
    anom.push(Math.floor(Math.random() * (state.attackMode ? 60 : 20)));
    anom.shift();
    txChart.update('none');
 
    if (fraudChart) {
      const fd = fraudChart.data.datasets[0].data;
      fd.push(Math.floor(Math.random() * (state.attackMode ? 35 : 8)));
      fd.shift();
      fraudChart.update('none');
    }
  }, 2500);
 
  state.intervalIds = [feedId, metricsId, threatId, chartId];
}
 
// ─── Attack Simulation ────────────────────────────────────────
function triggerAttack() {
  const scenario = ATTACK_SCENARIOS[Math.floor(Math.random() * ATTACK_SCENARIOS.length)];
  state.attackMode = true;
 
  document.getElementById('sim-status').textContent = `⚡ ATTACK SIMULATED: ${scenario.name}`;
  document.getElementById('sim-status').style.color = 'var(--red)';
 
  addTimelineItem('alert', 'THREAT AGENT', `<strong>ATTACK SCENARIO: ${scenario.name}</strong> — Simulation initiated`);
 
  scenario.events.forEach(evt => {
    setTimeout(() => {
      addFeedItem(evt.type, evt.msg);
      addTimelineItem(evt.type, 'MULTI-AGENT', evt.msg);
 
      // Update metrics dramatically
      if (evt.type === 'alert') {
        state.suspicious += Math.floor(Math.random() * 15 + 5);
        animateCounter('m-suspicious', state.suspicious);
        state.threatScore = Math.min(98, state.threatScore + 12);
        updateThreatGauge(state.threatScore);
      }
      if (evt.type === 'block') {
        state.blockedIPs += 1;
        animateCounter('m-blocked-ip', state.blockedIPs);
        addBlockedIP(`${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`);
 
        // Update agent response counter
        const agentEl = document.getElementById('agent-threat-val');
        if (agentEl) agentEl.textContent = state.blockedIPs;
      }
      if (evt.type === 'alert' || evt.type === 'warn') {
        const authAgent = document.getElementById('agent-auth-val');
        if (authAgent) authAgent.textContent = parseInt(authAgent.textContent) + 1;
      }
    }, evt.delay);
  });
 
  // Auto-resolve after scenario
  setTimeout(() => {
    state.attackMode = false;
    state.threatScore = Math.max(40, state.threatScore - 25);
    updateThreatGauge(state.threatScore);
    addFeedItem('ok', `✓ Attack scenario resolved — ${scenario.name} contained`);
    addTimelineItem('ok', 'ALL AGENTS', `<strong>Scenario resolved.</strong> Systems stabilizing. Incident report filed.`);
    document.getElementById('sim-status').textContent = '● SIMULATION RUNNING — MONITORING LIVE';
    document.getElementById('sim-status').style.color = 'var(--green)';
  }, scenario.events[scenario.events.length-1].delay + 3000);
 
  if (!state.running) startSimulation();
}
 
function addBlockedIP(ip) {
  const list = document.getElementById('blocked-list');
  const item = document.createElement('div');
  item.className = 'blocked-item';
  const reasons = ['ANOMALY SCORE','RAPID FRAUD','BRUTE FORCE','SWIFT ATTACK','VELOCITY SPIKE'];
  const now = new Date().toTimeString().slice(0,5);
  item.innerHTML = `
    <span class="blocked-ip">${ip}</span>
    <span class="blocked-reason">${reasons[Math.floor(Math.random()*reasons.length)]}</span>
    <span class="blocked-time">${now}</span>
  `;
  list.insertBefore(item, list.firstChild);
  if (list.children.length > 6) list.removeChild(list.lastChild);
}
 
// ─── Reset ────────────────────────────────────────────────────
function resetSystem() {
  state.intervalIds.forEach(clearInterval);
  state.intervalIds = [];
  state.running = false;
  state.transactions = 48291;
  state.suspicious = 127;
  state.users = 3847;
  state.blockedIPs = 34;
  state.blockedMACs = 19;
  state.threatScore = 75;
  state.attackMode = false;
 
  document.getElementById('m-transactions').textContent = '48,291';
  document.getElementById('m-suspicious').textContent = '127';
  document.getElementById('m-users').textContent = '3,847';
  document.getElementById('m-blocked-ip').textContent = '34';
  document.getElementById('m-blocked-mac').textContent = '19';
  updateThreatGauge(75);
  document.getElementById('sim-status').textContent = '● SIMULATION READY — CLICK START TO BEGIN';
  document.getElementById('sim-status').style.color = '';
}
 
// ─── Init ─────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  renderAuthTable(AUTH_DATA);
  renderNetworkTable(NETWORK_DATA);
  addGeoDots();
  updateThreatGauge(state.threatScore);
 
  // Staggered mount animations
  document.querySelectorAll('.metric-card, .panel').forEach((el, i) => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(12px)';
    el.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
    setTimeout(() => {
      el.style.opacity = '1';
      el.style.transform = 'translateY(0)';
    }, 80 + i * 40);
  });
});
