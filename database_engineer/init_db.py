"""
init_db.py — SQLite3 Database Setup
Run this once:  python3 init_db.py
Creates nexus_soc.db in the same folder. No install needed — SQLite is built into Mac/Python.
"""

import sqlite3
import os

DB_PATH = "nexus_soc.db"

def init():
    # Remove old DB if re-running
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"Removed old {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ── Users ──────────────────────────────────────────────────
    c.execute("""
    CREATE TABLE users (
        user_id        TEXT PRIMARY KEY,
        name           TEXT NOT NULL,
        email          TEXT UNIQUE NOT NULL,
        password_hash  TEXT NOT NULL,
        account_status TEXT DEFAULT 'ACTIVE',
        risk_level     TEXT DEFAULT 'LOW',
        created_at     TEXT DEFAULT (datetime('now')),
        last_login_at  TEXT,
        mfa_enabled    INTEGER DEFAULT 0
    )""")

    # ── Authentication History ─────────────────────────────────
    c.execute("""
    CREATE TABLE authentication_history (
        auth_id        TEXT PRIMARY KEY,
        user_id        TEXT REFERENCES users(user_id),
        auth_method    TEXT NOT NULL,
        device_id      TEXT,
        ip_address     TEXT NOT NULL,
        mac_address    TEXT,
        location_city  TEXT,
        success        INTEGER NOT NULL,
        anomaly_score  REAL DEFAULT 0.0,
        threat_flags   TEXT,
        timestamp      TEXT DEFAULT (datetime('now'))
    )""")

    # ── Devices ────────────────────────────────────────────────
    c.execute("""
    CREATE TABLE devices (
        device_id      TEXT PRIMARY KEY,
        user_id        TEXT REFERENCES users(user_id),
        mac_address    TEXT,
        ip_address     TEXT,
        device_type    TEXT,
        trusted        INTEGER DEFAULT 0,
        last_seen      TEXT DEFAULT (datetime('now')),
        location_city  TEXT,
        login_count    INTEGER DEFAULT 0,
        is_blocked     INTEGER DEFAULT 0
    )""")

    # ── Threat Logs ────────────────────────────────────────────
    c.execute("""
    CREATE TABLE threat_logs (
        threat_id      TEXT PRIMARY KEY,
        threat_type    TEXT NOT NULL,
        severity       TEXT NOT NULL,
        ip_address     TEXT,
        mac_address    TEXT,
        user_id        TEXT,
        description    TEXT NOT NULL,
        ml_score       REAL,
        status         TEXT DEFAULT 'OPEN',
        timestamp      TEXT DEFAULT (datetime('now'))
    )""")

    # ── Blocked Addresses ──────────────────────────────────────
    c.execute("""
    CREATE TABLE blocked_addresses (
        block_id       TEXT PRIMARY KEY,
        address_type   TEXT NOT NULL,
        address_value  TEXT NOT NULL,
        reason         TEXT NOT NULL,
        severity       TEXT DEFAULT 'HIGH',
        permanent      INTEGER DEFAULT 0,
        blocked_at     TEXT DEFAULT (datetime('now')),
        expires_at     TEXT,
        is_active      INTEGER DEFAULT 1
    )""")

    # ── Transactions ───────────────────────────────────────────
    c.execute("""
    CREATE TABLE transactions (
        tx_id          TEXT PRIMARY KEY,
        user_id        TEXT REFERENCES users(user_id),
        account_from   TEXT NOT NULL,
        account_to     TEXT NOT NULL,
        amount         REAL NOT NULL,
        currency       TEXT DEFAULT 'INR',
        tx_type        TEXT,
        ip_address     TEXT,
        location       TEXT,
        fraud_score    REAL DEFAULT 0.0,
        fraud_flags    TEXT,
        status         TEXT DEFAULT 'PENDING',
        timestamp      TEXT DEFAULT (datetime('now'))
    )""")

    # ── Indexes ────────────────────────────────────────────────
    c.execute("CREATE INDEX idx_auth_user    ON authentication_history(user_id)")
    c.execute("CREATE INDEX idx_auth_ip      ON authentication_history(ip_address)")
    c.execute("CREATE INDEX idx_auth_time    ON authentication_history(timestamp)")
    c.execute("CREATE INDEX idx_threats_sev  ON threat_logs(severity)")
    c.execute("CREATE INDEX idx_threats_time ON threat_logs(timestamp)")
    c.execute("CREATE INDEX idx_blocked_val  ON blocked_addresses(address_value)")
    c.execute("CREATE INDEX idx_txn_user     ON transactions(user_id)")
    c.execute("CREATE INDEX idx_txn_fraud    ON transactions(fraud_score)")

    # ── Seed Sample Data ───────────────────────────────────────
    users = [
        # Original test users
        ("USR_4421", "Arjun Sharma",  "arjun@nexusbank.in",  "hash_arjun",  "FROZEN", "CRITICAL"),
        ("USR_1190", "Priya Mehta",   "priya@nexusbank.in",  "hash_priya",  "ACTIVE", "MEDIUM"),
        
        # New 20 Employee Pool for strict database testing
        ("USR_1001", "Aarav Patel",   "aarav.p@nexusbank.in",  "hash_aarav",  "ACTIVE", "LOW"),
        ("USR_1002", "Rohan Gupta",   "rohan.g@nexusbank.in",  "hash_rohan",  "ACTIVE", "MEDIUM"),
        ("USR_1003", "Ananya Singh",  "ananya.s@nexusbank.in", "hash_ananya", "ACTIVE", "LOW"),
        ("USR_1004", "Vikram Reddy",  "vikram.r@nexusbank.in", "hash_vikram", "ACTIVE", "HIGH"),
        ("USR_1005", "Neha Desai",    "neha.d@nexusbank.in",   "hash_neha",   "ACTIVE", "LOW"),
        ("USR_1006", "Rahul Verma",   "rahul.v@nexusbank.in",  "hash_rahul",  "ACTIVE", "LOW"),
        ("USR_1007", "Sneha Kapoor",  "sneha.k@nexusbank.in",  "hash_sneha",  "ACTIVE", "MEDIUM"),
        ("USR_1008", "Amit Kumar",    "amit.k@nexusbank.in",   "hash_amit",   "ACTIVE", "LOW"),
        ("USR_1009", "Pooja Joshi",   "pooja.j@nexusbank.in",  "hash_pooja",  "ACTIVE", "LOW"),
        ("USR_1010", "Karan Malhotra","karan.m@nexusbank.in",  "hash_karan",  "ACTIVE", "MEDIUM"),
        ("USR_1011", "Riya Jain",     "riya.j@nexusbank.in",   "hash_riya",   "ACTIVE", "LOW"),
        ("USR_1012", "Sanjay Das",    "sanjay.d@nexusbank.in", "hash_sanjay", "ACTIVE", "LOW"),
        ("USR_1013", "Meera Reddy",   "meera.r@nexusbank.in",  "hash_meera",  "ACTIVE", "HIGH"),
        ("USR_1014", "Arjun Nair",    "arjun.n@nexusbank.in",  "hash_arjun",  "ACTIVE", "LOW"),
        ("USR_1015", "Kavya Iyer",    "kavya.i@nexusbank.in",  "hash_kavya",  "ACTIVE", "LOW"),
        ("USR_1016", "Aditya Rao",    "aditya.r@nexusbank.in", "hash_aditya", "ACTIVE", "MEDIUM"),
        ("USR_1017", "Nidhi Menon",   "nidhi.m@nexusbank.in",  "hash_nidhi",  "ACTIVE", "LOW"),
        ("USR_1018", "Varun Bhatia",  "varun.b@nexusbank.in",  "hash_varun",  "ACTIVE", "LOW"),
        ("USR_1019", "Swati Pillai",  "swati.p@nexusbank.in",  "hash_swati",  "ACTIVE", "LOW"),
        ("USR_1020", "Kabir Khan",    "kabir.k@nexusbank.in",  "hash_kabir",  "ACTIVE", "LOW"),
    ]
    c.executemany(
        "INSERT INTO users (user_id,name,email,password_hash,account_status,risk_level) VALUES (?,?,?,?,?,?)",
        users
    )

    devices = [
        ("DEV_A1B2", "USR_4421", "78:4F:43:55:6A:BC", "192.168.1.100", "Mobile",  1, "Mumbai"),
        ("DEV_E5F6", "USR_1190", "D4:61:9D:AB:CD:EF", "10.0.0.88",     "Mobile",  1, "Delhi"),
        ("DEV_G7H8", "USR_7734", "AC:DE:48:00:11:22", "172.16.1.4",    "Desktop", 1, "Bangalore"),
        ("DEV_I9J0", "USR_2234", "F8:3A:77:C2:11:DE", "172.16.8.44",   "Mobile",  1, "Pune"),
    ]
    c.executemany(
        "INSERT INTO devices (device_id,user_id,mac_address,ip_address,device_type,trusted,location_city) VALUES (?,?,?,?,?,?,?)",
        devices
    )

    threats = [
        ("THR_001", "AUTH_ANOMALY",  "HIGH",     "192.168.4.22",   "USR_4421", "Auth method changed FINGERPRINT→PATTERN from unknown device"),
        ("THR_002", "FRAUD_BURST",   "CRITICAL", "192.168.4.22",   "USR_4421", "7 rapid transfers in 12s — ₹8,40,000 total"),
        ("THR_003", "BRUTE_FORCE",   "HIGH",     "45.142.212.100", None,       "247 failed login attempts in 60 seconds"),
        ("THR_004", "SWIFT_FRAUD",   "CRITICAL", "185.220.101.44", "USR_2234", "Offshore SWIFT transfer ₹52,00,000 — unknown recipient"),
    ]
    c.executemany(
        "INSERT INTO threat_logs (threat_id,threat_type,severity,ip_address,user_id,description) VALUES (?,?,?,?,?,?)",
        threats
    )

    blocked = [
        ("BLK_001", "IP",  "185.220.101.44", "Tor exit node — rapid fraud",    "CRITICAL", 1),
        ("BLK_002", "IP",  "45.142.212.100", "Brute force 247 attempts",        "HIGH",     0),
        ("BLK_003", "IP",  "192.168.4.22",   "Anomaly score 94",               "HIGH",     0),
        ("BLK_004", "MAC", "A4:B2:C8:D1:E9:F2", "Unknown device fraud",        "HIGH",     0),
    ]
    c.executemany(
        "INSERT INTO blocked_addresses (block_id,address_type,address_value,reason,severity,permanent) VALUES (?,?,?,?,?,?)",
        blocked
    )

    conn.commit()
    conn.close()

    size = os.path.getsize(DB_PATH)
    print("=" * 50)
    print(f"  nexus_soc.db created ({size} bytes)")
    print("=" * 50)
    print("  Tables:  users, devices, threat_logs,")
    print("           blocked_addresses, transactions,")
    print("           authentication_history")
    print()
    print("  Sample data loaded:")
    print("    22 users  |  4 devices  |  4 threats")
    print("    4 blocked addresses")
    print()
    print("  Next step: run your FastAPI server!")
    print("=" * 50)

if __name__ == "__main__":
    init()