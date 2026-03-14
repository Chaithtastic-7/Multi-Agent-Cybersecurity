// ============================================================
//  NEXUS SOC — Banking Cyber Defense Dashboard Engine
// ============================================================

// ─── Backend Connection ──────────────────────────────────────
// Use the base URL of your FastAPI server
const BACKEND_URL = "http://localhost:8000"; // DO NOT include /docs here

async function loadDashboard() {
    try {
        // This matches the 2nd blue box in your image
        const response = await fetch(`${BACKEND_URL}/api/dashboard/overview`);
        
        if (!response.ok) throw new Error("Network response was not ok");
        
        const data = await response.json();

        // Map your backend keys to your frontend IDs
        // Note: Check your Python Pydantic models to ensure these keys (total_users) match!
        if(document.getElementById("totalUsers")) {
            document.getElementById("totalUsers").innerText = data.total_users;
        }
        if(document.getElementById("activeDevices")) {
            document.getElementById("activeDevices").innerText = data.active_devices;
        }
        
    } catch (error) {
        console.error("Connection failed:", error);
        // Fallback to simulation mode if backend is down
    }
}

// Call it when the page loads
document.addEventListener('DOMContentLoaded', loadDashboard);

// ─── Chart.js Configs ────────────────────────────────────────
let txChart, authChart, fraudChart;

function initCharts() {
    const txCtx = document.getElementById('transactionChart')?.getContext('2d');
    if (!txCtx) return;

    const labels = Array.from({length:24}, (_,i) => `${String(i).padStart(2,'0')}:00`);
    
    txChart = new Chart(txCtx, {
        type: 'bar',
        data: {
            labels,
            datasets: [
                {
                    label: 'Transactions',
                    data: [1200,900,700,500,400,300,400,800,2100,3400,4100,4500,4300,3900,4200,4600,4100,3800,3500,3200,2900,2400,2100,1800],
                    backgroundColor: 'rgba(0,200,255,0.18)',
                    borderColor: 'rgba(0,200,255,0.5)',
                    borderWidth: 1,
                    yAxisID: 'y',
                },
                {
                    type: 'line',
                    label: 'Anomaly Score',
                    data: [2,1,0,0,0,0,0,1,3,8,15,22,18,12,10,8,30,25,18,12,9,7,4,3],
                    borderColor: '#ff3860',
                    backgroundColor: 'rgba(255,56,96,0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    yAxisID: 'y1',
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { type: 'linear', position: 'left' },
                y1: { type: 'linear', position: 'right', grid: { drawOnChartArea: false } }
            }
        }
    });

    // Auth Doughnut
    const authCtx = document.getElementById('authChart')?.getContext('2d');
    if (authCtx) {
        authChart = new Chart(authCtx, {
            type: 'doughnut',
            data: {
                labels: ['Fingerprint','Facial','Pattern','Password'],
                datasets: [{
                    data: [42,28,18,12],
                    backgroundColor: ['#00c8ff','#a855f7','#ffb300','#ff3860'],
                }]
            },
            options: { responsive: true, maintainAspectRatio: false, cutout: '65%' }
        });
    }
}

// ─── Live Feed Logic ─────────────────────────────────────────
function connectWebSocket() {
    const wsUrl = BACKEND_URL.replace('http', 'ws') + '/ws/live-feed';
    try {
        const ws = new WebSocket(wsUrl);
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'ANOMALY' || data.type === 'FRAUD_ALERT') {
                addFeedItem('alert', data.description || `Fraud detected: Score ${data.fraud_score}`);
            } else if (data.type === 'BLOCKED') {
                addFeedItem('block', `IP ${data.ip || 'Unknown'} blocked: ${data.reason || 'Security Policy'}`);
            }
        };
    } catch(e) {
        console.warn("WebSocket connection failed. Falling back to simulation.");
    }
}

// ─── Core Sync Function ──────────────────────────────────────
async function syncWithBackend() {
    const data = await fetchFromBackend('/api/dashboard/overview');
    if (!data) return; // Silent return, simulation handles the UI

    if (data.total_transactions) animateCounter('m-transactions', data.total_transactions);
    if (data.suspicious_activities) animateCounter('m-suspicious', data.suspicious_activities);
    if (data.active_users) animateCounter('m-users', data.active_users);
    if (data.threat_score !== undefined) updateThreatGauge(data.threat_score);
    
    // Update raw DOM elements if they exist (from your loadDashboard logic)
    if(document.getElementById("totalUsers")) document.getElementById("totalUsers").innerText = data.total_users || data.active_users;
}

// ─── Threat Score Gauge ──────────────────────────────────────
function updateThreatGauge(score) {
    const ring = document.getElementById('threat-ring');
    const label = document.getElementById('threat-score');
    if (label) label.textContent = score;

    if (ring) {
        const circumference = 301.6;
        const pct = Math.min(score / 100, 1);
        ring.style.strokeDashoffset = circumference - (pct * circumference);
    }
    
    const countEl = document.getElementById('threat-count');
    if (countEl) countEl.textContent = score > 60 ? '🔴 HIGH THREAT' : '✓ NORMAL';
}

// ─── Simulation Engine ───────────────────────────────────────
const state = {
    running: false,
    transactions: 48291,
    suspicious: 127,
    users: 3847,
    threatScore: 75,
    intervalIds: []
};

function startSimulation() {
    if (state.running) return;
    state.running = true;
    
    const status = document.getElementById('sim-status');
    if (status) {
        status.textContent = '● SIMULATION RUNNING — MONITORING LIVE';
        status.style.color = '#23d160';
    }

    const metricsId = setInterval(() => {
        state.transactions += Math.floor(Math.random() * 10);
        animateCounter('m-transactions', state.transactions);
    }, 3000);

    state.intervalIds.push(metricsId);
}

// ─── Initialization ──────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    updateThreatGauge(state.threatScore);
    
    // Start Backend Communications
    connectWebSocket();
    syncWithBackend();
    setInterval(syncWithBackend, 5000);

    // Initial Table Render (Sample Data)
    // renderAuthTable(AUTH_DATA); // Assuming AUTH_DATA is defined globally
    
    // Auto-start simulation if no backend detected after 2 seconds
    setTimeout(() => {
        if (!state.running) startSimulation();
    }, 2000);
});

// Helper for animations
function animateCounter(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = target.toLocaleString();
}