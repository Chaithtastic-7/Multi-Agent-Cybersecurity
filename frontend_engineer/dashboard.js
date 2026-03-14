// ============================================================
// NEXUS SOC — Banking Cyber Defense Dashboard Engine
// ============================================================


const BACKEND_URL = "http://127.0.0.1:8000";

// ---------------- API CALL ----------------
async function loadDashboard() {
  try {
    const res = await fetch(`${BACKEND_URL}/api/dashboard/overview`);
    const data = await res.json();

    document.getElementById("m-transactions").innerText =
      data.total_transactions;

    document.getElementById("m-suspicious").innerText =
      data.suspicious_activities;

    document.getElementById("m-users").innerText =
      data.active_users;

    document.getElementById("m-blocked-ip").innerText =
      data.blocked_ips;

    document.getElementById("m-blocked-mac").innerText =
      data.blocked_macs;

    updateThreatGauge(data.threat_score);

  } catch (err) {
    console.log("Backend not connected, simulation mode running");
  }
}

// auto refresh
setInterval(loadDashboard, 5000);

// ---------------- CLOCK ----------------
function updateClock() {
  const now = new Date();
  document.getElementById("clock").innerText =
    now.toTimeString().slice(0, 8);
}

setInterval(updateClock, 1000);

// ---------------- THREAT GAUGE ----------------
function updateThreatGauge(score) {

  const circumference = 301.6;
  const pct = Math.min(score / 100, 1);

  const dashOffset = circumference - pct * circumference;

  const ring = document.getElementById("threat-ring");

  if (ring) ring.style.strokeDashoffset = dashOffset;

  document.getElementById("threat-score").innerText = score;

  if (score > 60) {
    document.getElementById("threat-count").innerText =
      "🔴 HIGH THREAT";
  } else {
    document.getElementById("threat-count").innerText =
      "✓ NORMAL";
  }
}

// ---------------- FEED ----------------
function addFeedItem(type, message) {

  const feed = document.getElementById("feed-list");

  const item = document.createElement("div");

  item.className = "feed-item";

  const time = new Date().toTimeString().slice(0,5);

  item.innerHTML = `
  <span class="feed-type">${type}</span>
  <span class="feed-msg">${message}</span>
  <span class="feed-time">${time}</span>
  `;

  feed.prepend(item);
}

// ---------------- INIT ----------------
document.addEventListener("DOMContentLoaded", () => {

  updateClock();

  loadDashboard();

});