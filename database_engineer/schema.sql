-- ============================================================
--  NEXUS SOC — Banking Cyber Defense System
--  PostgreSQL Database Schema v4.2.1
-- ============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ─── Users Table ──────────────────────────────────────────────
CREATE TABLE users (
    user_id         VARCHAR(20) PRIMARY KEY,
    name            VARCHAR(100) NOT NULL,
    email           VARCHAR(150) UNIQUE NOT NULL,
    password_hash   BYTEA NOT NULL,          -- bcrypt hash
    phone           VARCHAR(20),
    role            VARCHAR(20) DEFAULT 'CUSTOMER'
                    CHECK (role IN ('CUSTOMER', 'ADMIN', 'OPERATOR')),
    account_status  VARCHAR(20) DEFAULT 'ACTIVE'
                    CHECK (account_status IN ('ACTIVE', 'FROZEN', 'SUSPENDED', 'CLOSED')),
    risk_level      VARCHAR(10) DEFAULT 'LOW'
                    CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ,
    mfa_enabled     BOOLEAN DEFAULT FALSE,
    biometric_enrolled BOOLEAN DEFAULT FALSE,

    CONSTRAINT email_format CHECK (email ~* '^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$')
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_status ON users(account_status);
CREATE INDEX idx_users_risk ON users(risk_level);

-- ─── Authentication History ───────────────────────────────────
CREATE TABLE authentication_history (
    auth_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         VARCHAR(20) REFERENCES users(user_id) ON DELETE CASCADE,
    auth_method     VARCHAR(20) NOT NULL
                    CHECK (auth_method IN ('FINGERPRINT', 'FACIAL', 'PATTERN', 'PASSWORD', 'MFA_OTP', 'MFA_TOTP')),
    device_id       VARCHAR(50),
    ip_address      INET NOT NULL,
    mac_address     MACADDR,
    location_city   VARCHAR(100),
    location_country VARCHAR(50),
    location_lat    DECIMAL(9,6),
    location_lng    DECIMAL(9,6),
    user_agent      TEXT,
    success         BOOLEAN NOT NULL,
    failure_reason  VARCHAR(100),
    anomaly_score   DECIMAL(5,2) DEFAULT 0.0,
    threat_flags    TEXT[],                  -- Array of flag strings
    session_id      UUID,
    timestamp       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_auth_user_id   ON authentication_history(user_id);
CREATE INDEX idx_auth_ip        ON authentication_history(ip_address);
CREATE INDEX idx_auth_timestamp ON authentication_history(timestamp DESC);
CREATE INDEX idx_auth_anomaly   ON authentication_history(anomaly_score DESC)
                                WHERE anomaly_score > 50;
CREATE INDEX idx_auth_method    ON authentication_history(auth_method);

-- Partitioning hint (for production: partition by month)
-- PARTITION BY RANGE (timestamp);

-- ─── Devices ─────────────────────────────────────────────────
CREATE TABLE devices (
    device_id       VARCHAR(50) PRIMARY KEY,
    user_id         VARCHAR(20) REFERENCES users(user_id) ON DELETE CASCADE,
    mac_address     MACADDR,
    ip_address      INET,
    device_type     VARCHAR(30)
                    CHECK (device_type IN ('Mobile', 'Desktop', 'Tablet', 'ATM', 'POS', 'Unknown')),
    device_os       VARCHAR(50),
    device_name     VARCHAR(100),
    browser         VARCHAR(100),
    fingerprint_hash VARCHAR(64),            -- SHA-256 of device fingerprint
    trusted         BOOLEAN DEFAULT FALSE,
    registered_at   TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    location_city   VARCHAR(100),
    login_count     INTEGER DEFAULT 0,
    is_blocked      BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_devices_user   ON devices(user_id);
CREATE INDEX idx_devices_mac    ON devices(mac_address);
CREATE INDEX idx_devices_ip     ON devices(ip_address);
CREATE INDEX idx_devices_trusted ON devices(trusted) WHERE trusted = TRUE;

-- ─── Threat Logs ──────────────────────────────────────────────
CREATE TABLE threat_logs (
    threat_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    threat_type     VARCHAR(50) NOT NULL,
    severity        VARCHAR(10) NOT NULL
                    CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    ip_address      INET,
    mac_address     MACADDR,
    user_id         VARCHAR(20),
    description     TEXT NOT NULL,
    raw_data        JSONB,                   -- Full event payload
    ml_score        DECIMAL(5,4),            -- ML model output (0.0-1.0)
    status          VARCHAR(20) DEFAULT 'OPEN'
                    CHECK (status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE')),
    resolved_at     TIMESTAMPTZ,
    resolved_by     VARCHAR(20),
    timestamp       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_threats_severity  ON threat_logs(severity);
CREATE INDEX idx_threats_type      ON threat_logs(threat_type);
CREATE INDEX idx_threats_timestamp ON threat_logs(timestamp DESC);
CREATE INDEX idx_threats_ip        ON threat_logs(ip_address);
CREATE INDEX idx_threats_status    ON threat_logs(status) WHERE status = 'OPEN';
CREATE INDEX idx_threats_user      ON threat_logs(user_id);

-- GIN index for JSONB full-text search on raw_data
CREATE INDEX idx_threats_raw ON threat_logs USING GIN(raw_data);

-- ─── Blocked Devices / IPs ───────────────────────────────────
CREATE TABLE blocked_addresses (
    block_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    address_type    VARCHAR(5) NOT NULL CHECK (address_type IN ('IP', 'MAC', 'CIDR')),
    address_value   TEXT NOT NULL,
    reason          TEXT NOT NULL,
    severity        VARCHAR(10) DEFAULT 'HIGH',
    auto_blocked    BOOLEAN DEFAULT TRUE,
    blocked_by      VARCHAR(20) DEFAULT 'SYSTEM',
    block_count     INTEGER DEFAULT 1,
    permanent       BOOLEAN DEFAULT FALSE,
    blocked_at      TIMESTAMPTZ DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    unblocked_at    TIMESTAMPTZ,
    is_active       BOOLEAN DEFAULT TRUE,
    
    UNIQUE (address_value, is_active) -- Only one active block per address
);

CREATE INDEX idx_blocked_value   ON blocked_addresses(address_value) WHERE is_active = TRUE;
CREATE INDEX idx_blocked_active  ON blocked_addresses(is_active, expires_at);
CREATE INDEX idx_blocked_type    ON blocked_addresses(address_type);

-- ─── Transactions (for fraud monitoring) ─────────────────────
CREATE TABLE transactions (
    tx_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         VARCHAR(20) REFERENCES users(user_id),
    account_from    VARCHAR(30) NOT NULL,
    account_to      VARCHAR(30) NOT NULL,
    amount          DECIMAL(15,2) NOT NULL,
    currency        VARCHAR(3) DEFAULT 'INR',
    tx_type         VARCHAR(30)
                    CHECK (tx_type IN ('TRANSFER', 'WITHDRAWAL', 'DEPOSIT', 'SWIFT', 'RTGS', 'NEFT', 'UPI', 'ATM')),
    ip_address      INET,
    device_id       VARCHAR(50),
    location        VARCHAR(100),
    fraud_score     DECIMAL(5,4) DEFAULT 0.0,
    fraud_flags     TEXT[],
    status          VARCHAR(20) DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'APPROVED', 'BLOCKED', 'FLAGGED', 'REVERSED')),
    swift_ref       VARCHAR(50),
    timestamp       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_txn_user     ON transactions(user_id);
CREATE INDEX idx_txn_time     ON transactions(timestamp DESC);
CREATE INDEX idx_txn_fraud    ON transactions(fraud_score DESC) WHERE fraud_score > 0.5;
CREATE INDEX idx_txn_status   ON transactions(status);
CREATE INDEX idx_txn_amount   ON transactions(amount DESC);

-- ─── Biometric Templates (encrypted) ─────────────────────────
CREATE TABLE biometric_templates (
    template_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         VARCHAR(20) REFERENCES users(user_id) ON DELETE CASCADE,
    template_type   VARCHAR(20) NOT NULL
                    CHECK (template_type IN ('FINGERPRINT', 'FACIAL', 'PATTERN')),
    encrypted_data  BYTEA NOT NULL,          -- AES-256-GCM encrypted template
    template_hash   VARCHAR(64) NOT NULL,    -- HMAC-SHA256 for fast comparison
    device_id       VARCHAR(50),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    last_used       TIMESTAMPTZ,
    is_active       BOOLEAN DEFAULT TRUE,

    UNIQUE (user_id, template_type, device_id)
);

CREATE INDEX idx_bio_user ON biometric_templates(user_id, template_type) WHERE is_active = TRUE;

-- ─── Audit Trail ─────────────────────────────────────────────
CREATE TABLE audit_trail (
    audit_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action          VARCHAR(100) NOT NULL,
    performed_by    VARCHAR(20),
    target_entity   VARCHAR(50),
    target_id       VARCHAR(50),
    old_value       JSONB,
    new_value       JSONB,
    ip_address      INET,
    timestamp       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_time     ON audit_trail(timestamp DESC);
CREATE INDEX idx_audit_actor    ON audit_trail(performed_by);
CREATE INDEX idx_audit_target   ON audit_trail(target_entity, target_id);

-- ─── Views ───────────────────────────────────────────────────

-- Real-time dashboard overview
CREATE VIEW v_dashboard_overview AS
SELECT
    (SELECT COUNT(*) FROM transactions WHERE timestamp > NOW() - INTERVAL '24h') AS transactions_24h,
    (SELECT COUNT(*) FROM threat_logs WHERE severity IN ('HIGH','CRITICAL') AND timestamp > NOW() - INTERVAL '24h') AS threats_24h,
    (SELECT COUNT(*) FROM authentication_history WHERE timestamp > NOW() - INTERVAL '1h') AS auth_attempts_1h,
    (SELECT COUNT(*) FROM blocked_addresses WHERE is_active = TRUE) AS active_blocks,
    (SELECT COUNT(*) FROM users WHERE account_status = 'FROZEN') AS frozen_accounts,
    (SELECT COUNT(*) FROM threat_logs WHERE status = 'OPEN') AS open_threats;

-- User risk summary
CREATE VIEW v_user_risk_summary AS
SELECT
    u.user_id,
    u.name,
    u.risk_level,
    u.account_status,
    COUNT(DISTINCT ah.auth_id) FILTER (WHERE NOT ah.success) AS failed_logins_7d,
    MAX(ah.anomaly_score) AS max_anomaly_score,
    COUNT(DISTINCT t.tx_id) FILTER (WHERE t.fraud_score > 0.5) AS flagged_transactions,
    MAX(t.fraud_score) AS max_fraud_score
FROM users u
LEFT JOIN authentication_history ah ON u.user_id = ah.user_id
    AND ah.timestamp > NOW() - INTERVAL '7 days'
LEFT JOIN transactions t ON u.user_id = t.user_id
    AND t.timestamp > NOW() - INTERVAL '7 days'
GROUP BY u.user_id, u.name, u.risk_level, u.account_status;

-- Threat feed for dashboard
CREATE VIEW v_threat_feed AS
SELECT
    threat_id,
    threat_type,
    severity,
    ip_address::TEXT,
    user_id,
    description,
    ml_score,
    status,
    timestamp
FROM threat_logs
WHERE timestamp > NOW() - INTERVAL '24h'
ORDER BY timestamp DESC
LIMIT 200;

-- ─── Functions ───────────────────────────────────────────────

-- Auto-update user risk level based on anomaly scores
CREATE OR REPLACE FUNCTION update_user_risk_level()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.anomaly_score >= 85 THEN
        UPDATE users SET risk_level = 'CRITICAL' WHERE user_id = NEW.user_id;
    ELSIF NEW.anomaly_score >= 70 THEN
        UPDATE users SET risk_level = 'HIGH' WHERE user_id = NEW.user_id;
    ELSIF NEW.anomaly_score >= 50 THEN
        UPDATE users SET risk_level = 'MEDIUM' WHERE user_id = NEW.user_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_risk
    AFTER INSERT ON authentication_history
    FOR EACH ROW
    WHEN (NEW.anomaly_score > 50)
    EXECUTE FUNCTION update_user_risk_level();

-- Cleanup expired blocks
CREATE OR REPLACE FUNCTION cleanup_expired_blocks()
RETURNS void AS $$
BEGIN
    UPDATE blocked_addresses
    SET is_active = FALSE
    WHERE expires_at < NOW()
    AND permanent = FALSE
    AND is_active = TRUE;
END;
$$ LANGUAGE plpgsql;

-- ─── Sample Data ─────────────────────────────────────────────
INSERT INTO users (user_id, name, email, password_hash, account_status, risk_level) VALUES
    ('USR_4421', 'Arjun Sharma',  'arjun.sharma@nexusbank.in',  '$2b$12$demo_hash_arjun',  'FROZEN',  'CRITICAL'),
    ('USR_1190', 'Priya Mehta',   'priya.mehta@nexusbank.in',   '$2b$12$demo_hash_priya',  'ACTIVE',  'MEDIUM'),
    ('USR_7734', 'Rahul Verma',   'rahul.verma@nexusbank.in',   '$2b$12$demo_hash_rahul',  'ACTIVE',  'LOW'),
    ('USR_2234', 'Sneha Kapoor',  'sneha.kapoor@nexusbank.in',  '$2b$12$demo_hash_sneha',  'ACTIVE',  'HIGH'),
    ('USR_5512', 'Vikram Singh',  'vikram.singh@nexusbank.in',  '$2b$12$demo_hash_vikram', 'ACTIVE',  'LOW'),
    ('USR_3391', 'Anita Nair',    'anita.nair@nexusbank.in',    '$2b$12$demo_hash_anita',  'ACTIVE',  'LOW')
ON CONFLICT DO NOTHING;
