import sqlite3
from datetime import datetime

class SecurityDatabase:
    def __init__(self, db_name="cyber_vault.db"):
        self.conn = sqlite3.connect(db_name)
        self.create_tables()

    def create_tables(self):
        # Table to store every "Alert" your threat_analyzer finds
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                threat_type TEXT,
                action_taken TEXT
            )
        ''')
        self.conn.commit()

    def log_incident(self, ip, threat, action):
        time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.conn.execute(
            "INSERT INTO alerts (timestamp, source_ip, threat_type, action_taken) VALUES (?, ?, ?, ?)",
            (time_now, ip, threat, action)
        )
        self.conn.commit()
        print(f"Locked into DB: {ip} for {threat}")

# Simple test to see if it works
if __name__ == "__main__":
    db = SecurityDatabase()
    db.log_incident("1.2.3.4", "DDoS Attempt", "Blocked")