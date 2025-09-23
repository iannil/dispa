#![allow(dead_code)]
use crate::error::DispaResult;
use sqlx::{Row, SqlitePool};
use std::path::Path;
use tracing::{debug, info};

use super::models::{TargetTrafficStats, TrafficLog, TrafficStats};

/// Database operations for traffic logging
pub struct DatabaseManager {
    pool: SqlitePool,
}

impl DatabaseManager {
    /// Create database connection and setup tables
    pub async fn new(db_url: &str) -> DispaResult<Self> {
        // Create data directory if it doesn't exist
        if db_url.starts_with("sqlite://") {
            let db_path = db_url.strip_prefix("sqlite://").unwrap();
            if let Some(parent) = Path::new(db_path).parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        let pool = SqlitePool::connect(db_url).await?;

        // Create tables
        Self::create_tables(&pool).await?;
        Self::create_indexes(&pool).await?;

        info!("Database initialized successfully");
        Ok(Self { pool })
    }

    /// Create necessary database tables
    async fn create_tables(pool: &SqlitePool) -> DispaResult<()> {
        // Main traffic logs table
        sqlx::query(
            r#"
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
            )
            "#,
        )
        .execute(pool)
        .await?;

        // Summary table for analytics
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS traffic_summary (
                date TEXT PRIMARY KEY,
                total_requests INTEGER DEFAULT 0,
                total_errors INTEGER DEFAULT 0,
                avg_duration_ms REAL DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                unique_ips INTEGER DEFAULT 0,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Create database indexes for better query performance
    async fn create_indexes(pool: &SqlitePool) -> DispaResult<()> {
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_traffic_logs_timestamp ON traffic_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_traffic_logs_host ON traffic_logs(host);
            CREATE INDEX IF NOT EXISTS idx_traffic_logs_target ON traffic_logs(target);
            CREATE INDEX IF NOT EXISTS idx_traffic_logs_status_code ON traffic_logs(status_code);
            CREATE INDEX IF NOT EXISTS idx_traffic_logs_created_at ON traffic_logs(created_at);
            "#,
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Insert a traffic log entry into the database
    pub async fn insert_log(&self, log_entry: &TrafficLog) -> DispaResult<()> {
        sqlx::query(
            r#"
            INSERT INTO traffic_logs (
                id, timestamp, client_ip, host, method, path, target,
                status_code, duration_ms, request_size, response_size,
                user_agent, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&log_entry.id)
        .bind(log_entry.timestamp)
        .bind(&log_entry.client_ip)
        .bind(&log_entry.host)
        .bind(&log_entry.method)
        .bind(&log_entry.path)
        .bind(&log_entry.target)
        .bind(log_entry.status_code as i32)
        .bind(log_entry.duration_ms)
        .bind(log_entry.request_size)
        .bind(log_entry.response_size)
        .bind(&log_entry.user_agent)
        .bind(&log_entry.error_message)
        .execute(&self.pool)
        .await?;

        debug!("Traffic log inserted: {}", log_entry.id);
        Ok(())
    }

    /// Update daily summary statistics
    pub async fn update_daily_summary(&self, log_entry: &TrafficLog) -> DispaResult<()> {
        let date = log_entry.timestamp.format("%Y-%m-%d").to_string();
        let is_error = log_entry.status_code >= 400;

        sqlx::query(
            r#"
            INSERT INTO traffic_summary (date, total_requests, total_errors, avg_duration_ms, total_bytes, unique_ips)
            VALUES (?, 1, ?, ?, 0, 0)
            ON CONFLICT(date) DO UPDATE SET
                total_requests = total_requests + 1,
                total_errors = total_errors + ?,
                avg_duration_ms = (avg_duration_ms * (total_requests - 1) + ?) / total_requests,
                updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(&date)
        .bind(if is_error { 1 } else { 0 })
        .bind(log_entry.duration_ms)
        .bind(if is_error { 1 } else { 0 })
        .bind(log_entry.duration_ms)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get traffic statistics for the last N hours
    pub async fn get_traffic_stats(&self, hours: i64) -> DispaResult<TrafficStats> {
        let cutoff_time = chrono::Utc::now() - chrono::Duration::hours(hours);

        // Get basic statistics
        let row = sqlx::query(
            r#"
            SELECT
                COUNT(*) as total_requests,
                SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as error_count,
                AVG(duration_ms) as avg_duration_ms,
                COUNT(DISTINCT client_ip) as unique_clients
            FROM traffic_logs
            WHERE timestamp >= ?
            "#,
        )
        .bind(cutoff_time)
        .fetch_one(&self.pool)
        .await?;

        let total_requests: i64 = row.get("total_requests");
        let error_count: i64 = row.get("error_count");
        let avg_duration_ms: f64 = row.try_get("avg_duration_ms").unwrap_or(0.0);
        let unique_clients: i64 = row.get("unique_clients");

        // Get top hosts
        let top_hosts_rows = sqlx::query(
            r#"
            SELECT host, COUNT(*) as count
            FROM traffic_logs
            WHERE timestamp >= ?
            GROUP BY host
            ORDER BY count DESC
            LIMIT 10
            "#,
        )
        .bind(cutoff_time)
        .fetch_all(&self.pool)
        .await?;

        let top_hosts: Vec<(String, i64)> = top_hosts_rows
            .iter()
            .map(|row| (row.get::<String, _>("host"), row.get::<i64, _>("count")))
            .collect();

        // Get top targets
        let top_targets_rows = sqlx::query(
            r#"
            SELECT target, COUNT(*) as count
            FROM traffic_logs
            WHERE timestamp >= ?
            GROUP BY target
            ORDER BY count DESC
            LIMIT 10
            "#,
        )
        .bind(cutoff_time)
        .fetch_all(&self.pool)
        .await?;

        let top_targets: Vec<(String, i64)> = top_targets_rows
            .iter()
            .map(|row| (row.get::<String, _>("target"), row.get::<i64, _>("count")))
            .collect();

        let error_rate_percentage = if total_requests > 0 {
            (error_count as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        Ok(TrafficStats {
            total_requests,
            error_count,
            avg_duration_ms,
            total_bytes: 0, // Could be calculated if request/response sizes are tracked
            unique_clients,
            top_hosts,
            top_targets,
            error_rate_percentage,
        })
    }

    /// Get traffic statistics by target for the last N hours
    pub async fn get_traffic_by_target(&self, hours: i64) -> DispaResult<Vec<TargetTrafficStats>> {
        let cutoff_time = chrono::Utc::now() - chrono::Duration::hours(hours);

        let rows = sqlx::query(
            r#"
            SELECT
                target,
                COUNT(*) as total_requests,
                SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as error_count,
                AVG(duration_ms) as avg_duration_ms
            FROM traffic_logs
            WHERE timestamp >= ?
            GROUP BY target
            ORDER BY total_requests DESC
            "#,
        )
        .bind(cutoff_time)
        .fetch_all(&self.pool)
        .await?;

        let mut stats = Vec::new();
        for row in rows {
            let total_requests: i64 = row.get("total_requests");
            let error_count: i64 = row.get("error_count");
            let error_rate_percentage = if total_requests > 0 {
                (error_count as f64 / total_requests as f64) * 100.0
            } else {
                0.0
            };

            stats.push(TargetTrafficStats {
                target: row.get("target"),
                total_requests,
                error_count,
                avg_duration_ms: row.try_get("avg_duration_ms").unwrap_or(0.0),
                error_rate_percentage,
            });
        }

        Ok(stats)
    }

    /// Get recent error logs
    pub async fn get_error_logs(&self, limit: i64) -> DispaResult<Vec<TrafficLog>> {
        let rows = sqlx::query(
            r#"
            SELECT * FROM traffic_logs
            WHERE status_code >= 400 OR error_message IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(TrafficLog {
                id: row.get("id"),
                timestamp: row.get("timestamp"),
                client_ip: row.get("client_ip"),
                host: row.get("host"),
                method: row.get("method"),
                path: row.get("path"),
                target: row.get("target"),
                status_code: row.get::<i32, _>("status_code") as u16,
                duration_ms: row.get("duration_ms"),
                request_size: row.get("request_size"),
                response_size: row.get("response_size"),
                user_agent: row.get("user_agent"),
                error_message: row.get("error_message"),
            });
        }

        Ok(logs)
    }

    /// Clean up old logs based on retention period
    pub async fn cleanup_old_logs(&self, retention_days: u32) -> DispaResult<()> {
        let cutoff_time = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);

        let result = sqlx::query("DELETE FROM traffic_logs WHERE timestamp < ?")
            .bind(cutoff_time)
            .execute(&self.pool)
            .await?;

        info!(
            "Cleaned up {} old traffic log entries older than {} days",
            result.rows_affected(),
            retention_days
        );

        // Also clean up old summary data
        let summary_result = sqlx::query("DELETE FROM traffic_summary WHERE date < ?")
            .bind(cutoff_time.format("%Y-%m-%d").to_string())
            .execute(&self.pool)
            .await?;

        info!(
            "Cleaned up {} old summary entries",
            summary_result.rows_affected()
        );

        Ok(())
    }

    /// Get a reference to the database pool
    pub fn get_pool(&self) -> &SqlitePool {
        &self.pool
    }
}
