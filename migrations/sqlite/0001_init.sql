-- SQLite schema for Dispa traffic logging
-- Tables mirror the structures created programmatically in TrafficLogger

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS traffic_logs (
    id TEXT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    client_ip TEXT NOT NULL,
    host TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    target TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    request_size INTEGER,
    response_size INTEGER,
    user_agent TEXT,
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_traffic_logs_timestamp ON traffic_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_host ON traffic_logs(host);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_target ON traffic_logs(target);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_status_code ON traffic_logs(status_code);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_created_at ON traffic_logs(created_at);

CREATE TABLE IF NOT EXISTS traffic_summary (
    date TEXT PRIMARY KEY,
    total_requests INTEGER DEFAULT 0,
    total_errors INTEGER DEFAULT 0,
    avg_duration_ms REAL DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    unique_ips INTEGER DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

COMMIT;

