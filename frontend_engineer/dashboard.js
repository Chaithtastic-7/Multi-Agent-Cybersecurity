// ============================================================
// NEXUS SOC — Banking Cyber Defense Dashboard Engine
// ============================================================

const BACKEND_URL = "http://localhost:8000";

// --- Global Chart Variables ---
let txChart, authChart, fraudChart;

// ---------------- API CALL ----------------
async function loadDashboard() {
  try {
    const res = await fetch(`${BACKEND_URL}/api/dashboard/overview`);
    const data = await res.json();

    // 1. Update Numeric Metrics
    updateMetric("m-transactions", data.total_transactions.toLocaleString());
    updateMetric("m-suspicious", data.suspicious_activities);
    updateMetric("m-users", data.active_users.toLocaleString());
    updateMetric("m-blocked-ip", data.blocked_ips);
    updateMetric("m-blocked-mac", data.blocked_macs);

    // 2. Update the Threat Gauge
    updateThreatGauge(data.threat_score);

    // 3. Update the Live Charts
    updateCharts(data);

  } catch (err) {
    console.log("Backend sync error. Check if FastAPI is running.");
  }
}

// Helper to safely update text
function updateMetric(id, value) {
  const el = document.getElementById(id);
  if (el) el.innerText = value;
}

// ---------------- CHART LOGIC ----------------
function initCharts() {
  // Transaction Chart
  const txCtx = document.getElementById('transactionChart').getContext('2d');
  txChart = new Chart(txCtx, {
    type: 'line',
    data: {
      labels: Array(20).fill(''),
      datasets: [{
        label: 'Live Transactions',
        data: Array(20).fill(0),
        borderColor: '#00c8ff',
        backgroundColor: 'rgba(0, 200, 255, 0.1)',
        fill: true,
        tension: 0.4
      }]
    },
    options: { 
        responsive: true, 
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { display: false }, x: { display: false } }
    }
  });

  // Fraud Sparkline
  const fCtx = document.getElementById('fraudChart').getContext('2d');
  fraudChart = new Chart(fCtx, {
    type: 'bar',
    data: {
      labels: Array(15).fill(''),
      datasets: [{
        data: Array(15).fill(0),
        backgroundColor: '#ff3860'
      }]
    },
    options: { 
        responsive: true, 
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { display: false }, x: { display: false } }
    }
  });
}

function updateCharts(data) {
  if (txChart) {
    // We simulate a trend using the live total_transactions
    const newVal = data.total_transactions % 1000; 
    txChart.data.datasets[0].data.push(newVal);
    txChart.data.datasets[0].data.shift();
    txChart.update('none');
  }

  if (fraudChart) {
    fraudChart.data.datasets[0].data.push(data.suspicious_activities % 50);
    fraudChart.data.datasets[0].data.shift();
    fraudChart.update('none');
  }
}

// ---------------- THREAT GAUGE ----------------
function updateThreatGauge(score) {
  const circumference = 301.6;
  const pct = Math.min(score / 100, 1);
  const dashOffset = circumference - pct * circumference;

  const ring = document.getElementById("threat-ring");
  const scoreLabel = document.getElementById("threat-score");
  const statusLabel = document.getElementById("threat-count");

  if (ring) ring.style.strokeDashoffset = dashOffset;
  if (scoreLabel) scoreLabel.innerText = score;

  if (statusLabel) {
    statusLabel.innerText = score > 60 ? "🔴 HIGH THREAT" : "✓ NORMAL";
    statusLabel.style.color = score > 60 ? "#ff3860" : "#00ff88";
  }
}

// ---------------- CLOCK ----------------
function updateClock() {
  const el = document.getElementById("clock");
  if (el) el.innerText = new Date().toTimeString().slice(0, 8);
}

// ---------------- WEBSOCKET LIVE FEED ----------------
let ws;

function initWebSocket() {
  // 1. Convert the HTTP backend URL to a WS URL and append the security token
  // This must match the token we set in main_sqlite.py!
  const wsUrl = BACKEND_URL.replace("http", "ws") + "/ws/live-feed?token=super_secret_admin_token";
  
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    console.log("✅ WebSocket Connected to NEXUS SOC Live Feed");
  };

  ws.onmessage = (event) => {
    const alertData = JSON.parse(event.data);
    console.log("🚨 Real-time Event Received:", alertData);
    
    // Future integration: You can use alertData to update your UI immediately 
    // instead of waiting for the 3-second loadDashboard() polling cycle!
  };

  ws.onclose = (event) => {
    console.warn(`⚠️ WebSocket Disconnected (Code: ${event.code}). Reconnecting in 5s...`);
    // If the server goes down, automatically try to reconnect
    setTimeout(initWebSocket, 5000);
  };

  ws.onerror = (err) => {
    console.error("❌ WebSocket Error:", err);
  };
}

// ---------------- INIT ----------------
document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  updateClock();
  loadDashboard();
  
  // Initialize the secure WebSocket connection
  initWebSocket(); 
  
  // Set intervals
  setInterval(updateClock, 1000);
  setInterval(loadDashboard, 3000); // Faster updates for SOC feel
});