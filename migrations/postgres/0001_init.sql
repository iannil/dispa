-- PostgreSQL schema for Dispa traffic logging

BEGIN;

CREATE TABLE IF NOT EXISTS traffic_logs (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    client_ip TEXT NOT NULL,
    host TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    target TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    duration_ms BIGINT NOT NULL,
    request_size BIGINT,
    response_size BIGINT,
    user_agent TEXT,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_traffic_logs_timestamp ON traffic_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_host ON traffic_logs(host);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_target ON traffic_logs(target);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_status_code ON traffic_logs(status_code);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_created_at ON traffic_logs(created_at);

CREATE TABLE IF NOT EXISTS traffic_summary (
    date DATE PRIMARY KEY,
    total_requests BIGINT DEFAULT 0,
    total_errors BIGINT DEFAULT 0,
    avg_duration_ms DOUBLE PRECISION DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    unique_ips BIGINT DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

COMMIT;

