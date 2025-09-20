use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration as StdDuration;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::config::{LoggingConfig, LoggingType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficLog {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub target: String,
    pub status_code: u16,
    pub duration_ms: i64,
    pub request_size: Option<i64>,
    pub response_size: Option<i64>,
    pub user_agent: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Clone)]
pub struct TrafficLogger {
    config: LoggingConfig,
    db_pool: Option<SqlitePool>,
}

impl TrafficLogger {
    pub fn new(config: LoggingConfig) -> Self {
        Self {
            config,
            db_pool: None,
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        if !self.config.enabled {
            info!("Traffic logging is disabled");
            return Ok(());
        }

        match self.config.log_type {
            LoggingType::Database | LoggingType::Both => {
                if let Some(ref db_config) = self.config.database {
                    info!("Initializing database logging to: {}", db_config.url);
                    self.db_pool = Some(self.setup_database(&db_config.url).await?);
                    info!("Database logging initialized successfully");
                }
            }
            LoggingType::File => {}
        }

        // Create log directory if using file logging
        if matches!(self.config.log_type, LoggingType::File | LoggingType::Both) {
            if let Some(ref file_config) = self.config.file {
                tokio::fs::create_dir_all(&file_config.directory).await?;
                info!("File logging directory created: {}", file_config.directory);
            }
        }

        // Start cleanup task if retention is configured
        if let Some(retention_days) = self.config.retention_days {
            if retention_days > 0 {
                let logger = self.clone();
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(StdDuration::from_secs(24 * 60 * 60)); // Daily

                    loop {
                        interval.tick().await;
                        if let Err(e) = logger.cleanup_old_logs().await {
                            error!("Failed to cleanup old logs: {}", e);
                        }
                    }
                });
            }
        }

        Ok(())
    }

    async fn setup_database(&self, db_url: &str) -> Result<SqlitePool> {
        // Create data directory if it doesn't exist
        if db_url.starts_with("sqlite://") {
            let db_path = db_url.strip_prefix("sqlite://").unwrap();
            if let Some(parent) = Path::new(db_path).parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        let pool = SqlitePool::connect(db_url).await?;

        // Create tables
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
        .execute(&pool)
        .await?;

        // Create indexes for better query performance
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_traffic_logs_timestamp ON traffic_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_traffic_logs_host ON traffic_logs(host);
            CREATE INDEX IF NOT EXISTS idx_traffic_logs_target ON traffic_logs(target);
            CREATE INDEX IF NOT EXISTS idx_traffic_logs_status_code ON traffic_logs(status_code);
            CREATE INDEX IF NOT EXISTS idx_traffic_logs_created_at ON traffic_logs(created_at);
            "#,
        )
        .execute(&pool)
        .await?;

        // Create summary table for analytics
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
        .execute(&pool)
        .await?;

        Ok(pool)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn log_request(
        &self,
        request_id: Uuid,
        client_addr: SocketAddr,
        host: &str,
        method: &str,
        path: &str,
        target: &str,
        status: StatusCode,
        timestamp: DateTime<Utc>,
        duration: StdDuration,
        user_agent: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let log_entry = TrafficLog {
            id: request_id.to_string(),
            timestamp,
            client_ip: client_addr.ip().to_string(),
            host: host.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            target: target.to_string(),
            status_code: status.as_u16(),
            duration_ms: duration.as_millis() as i64,
            request_size: None, // Placeholder: add request size tracking if needed
            response_size: None, // Placeholder: add response size tracking if needed
            user_agent: user_agent.map(|s| s.to_string()),
            error_message: error_message.map(|s| s.to_string()),
        };

        match self.config.log_type {
            LoggingType::Database => {
                if let Err(e) = self.log_to_database(&log_entry).await {
                    error!("Failed to log to database: {}", e);
                }
            }
            LoggingType::File => {
                if let Err(e) = self.log_to_file(&log_entry).await {
                    error!("Failed to log to file: {}", e);
                }
            }
            LoggingType::Both => {
                let db_result = self.log_to_database(&log_entry).await;
                let file_result = self.log_to_file(&log_entry).await;

                if let Err(e) = db_result {
                    warn!("Failed to log to database: {}", e);
                }
                if let Err(e) = file_result {
                    warn!("Failed to log to file: {}", e);
                }
            }
        }

        debug!(
            "Logged traffic for request {}: {} {} -> {} ({}ms)",
            request_id,
            method,
            path,
            target,
            duration.as_millis()
        );
        Ok(())
    }

    async fn log_to_database(&self, log_entry: &TrafficLog) -> Result<()> {
        if let Some(ref pool) = self.db_pool {
            sqlx::query(
                r#"
                INSERT INTO traffic_logs
                (id, timestamp, client_ip, host, method, path, target, status_code,
                 duration_ms, request_size, response_size, user_agent, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            .execute(pool)
            .await?;

            // Update daily summary
            self.update_daily_summary(log_entry).await?;
        }
        Ok(())
    }

    async fn update_daily_summary(&self, log_entry: &TrafficLog) -> Result<()> {
        if let Some(ref pool) = self.db_pool {
            let date = log_entry.timestamp.format("%Y-%m-%d").to_string();
            let is_error = log_entry.status_code >= 400;

            sqlx::query(
                r#"
                INSERT INTO traffic_summary (date, total_requests, total_errors, avg_duration_ms)
                VALUES (?, 1, ?, ?)
                ON CONFLICT(date) DO UPDATE SET
                    total_requests = total_requests + 1,
                    total_errors = total_errors + ?,
                    avg_duration_ms = (avg_duration_ms * (total_requests - 1) + ?) / total_requests,
                    updated_at = CURRENT_TIMESTAMP
                "#,
            )
            .bind(&date)
            .bind(if is_error { 1 } else { 0 })
            .bind(log_entry.duration_ms as f64)
            .bind(if is_error { 1 } else { 0 })
            .bind(log_entry.duration_ms as f64)
            .execute(pool)
            .await?;
        }
        Ok(())
    }

    async fn log_to_file(&self, log_entry: &TrafficLog) -> Result<()> {
        if let Some(ref file_config) = self.config.file {
            let log_line = serde_json::to_string(log_entry)?;
            let file_path = format!(
                "{}/traffic-{}.log",
                file_config.directory,
                log_entry.timestamp.format("%Y-%m-%d")
            );

            // Check file size if rotation is enabled
            if file_config.rotation {
                if let Some(max_size) = file_config.max_file_size {
                    if let Ok(metadata) = tokio::fs::metadata(&file_path).await {
                        if metadata.len() > max_size {
                            // Rotate the file
                            let rotated_path =
                                format!("{}.{}", file_path, log_entry.timestamp.format("%H%M%S"));
                            let _ = tokio::fs::rename(&file_path, rotated_path).await;
                        }
                    }
                }
            }

            // Append to file
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file_path)
                .await?;

            file.write_all(format!("{}\n", log_line).as_bytes()).await?;
            file.flush().await?;
        }
        Ok(())
    }

    pub async fn cleanup_old_logs(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        if let Some(retention_days) = self.config.retention_days {
            let cutoff_date = Utc::now() - Duration::days(retention_days as i64);
            info!(
                "Cleaning up logs older than {}",
                cutoff_date.format("%Y-%m-%d")
            );

            // Clean database logs
            if let Some(ref pool) = self.db_pool {
                let result = sqlx::query("DELETE FROM traffic_logs WHERE timestamp < ?")
                    .bind(cutoff_date)
                    .execute(pool)
                    .await?;

                let summary_result = sqlx::query("DELETE FROM traffic_summary WHERE date < ?")
                    .bind(cutoff_date.format("%Y-%m-%d").to_string())
                    .execute(pool)
                    .await?;

                info!(
                    "Cleaned {} old database log entries and {} summary records",
                    result.rows_affected(),
                    summary_result.rows_affected()
                );
            }

            // Clean file logs
            if let Some(ref file_config) = self.config.file {
                let mut cleanup_count = 0;
                if let Ok(mut dir) = tokio::fs::read_dir(&file_config.directory).await {
                    while let Ok(Some(entry)) = dir.next_entry().await {
                        if let Some(filename) = entry.file_name().to_str() {
                            if filename.starts_with("traffic-") && filename.ends_with(".log") {
                                if let Ok(metadata) = entry.metadata().await {
                                    if let Ok(created) = metadata.created() {
                                        let created_datetime = DateTime::<Utc>::from(created);
                                        if created_datetime < cutoff_date {
                                            if let Err(e) =
                                                tokio::fs::remove_file(entry.path()).await
                                            {
                                                warn!(
                                                    "Failed to remove old log file {:?}: {}",
                                                    entry.path(),
                                                    e
                                                );
                                            } else {
                                                cleanup_count += 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if cleanup_count > 0 {
                    info!("Removed {} old log files", cleanup_count);
                }
            }
        }

        Ok(())
    }

    pub async fn get_traffic_stats(&self, hours: i64) -> Result<TrafficStats> {
        let since = Utc::now() - Duration::hours(hours);

        if let Some(ref pool) = self.db_pool {
            let row = sqlx::query(
                r#"
                SELECT
                    COUNT(*) as total_requests,
                    AVG(duration_ms) as avg_duration,
                    COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count,
                    COUNT(DISTINCT client_ip) as unique_clients,
                    SUM(COALESCE(request_size, 0) + COALESCE(response_size, 0)) as total_bytes
                FROM traffic_logs
                WHERE timestamp >= ?
                "#,
            )
            .bind(since)
            .fetch_one(pool)
            .await?;

            Ok(TrafficStats {
                total_requests: row.get("total_requests"),
                avg_duration: row.get::<Option<f64>, _>("avg_duration").unwrap_or(0.0),
                error_count: row.get("error_count"),
                unique_clients: row.get("unique_clients"),
                total_bytes: row.get::<i64, _>("total_bytes") as u64,
                time_window_hours: hours,
            })
        } else {
            Ok(TrafficStats::default())
        }
    }

    pub async fn get_traffic_by_target(&self, hours: i64) -> Result<Vec<TargetTrafficStats>> {
        let since = Utc::now() - Duration::hours(hours);

        if let Some(ref pool) = self.db_pool {
            let rows = sqlx::query(
                r#"
                SELECT
                    target,
                    COUNT(*) as request_count,
                    AVG(duration_ms) as avg_duration,
                    COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count
                FROM traffic_logs
                WHERE timestamp >= ?
                GROUP BY target
                ORDER BY request_count DESC
                "#,
            )
            .bind(since)
            .fetch_all(pool)
            .await?;

            let mut stats = Vec::new();
            for row in rows {
                stats.push(TargetTrafficStats {
                    target: row.get("target"),
                    request_count: row.get("request_count"),
                    avg_duration: row.get::<Option<f64>, _>("avg_duration").unwrap_or(0.0),
                    error_count: row.get("error_count"),
                });
            }

            Ok(stats)
        } else {
            Ok(Vec::new())
        }
    }

    #[allow(dead_code)]
    pub async fn get_error_logs(&self, limit: i64) -> Result<Vec<TrafficLog>> {
        if let Some(ref pool) = self.db_pool {
            let rows = sqlx::query(
                r#"
                SELECT * FROM traffic_logs
                WHERE status_code >= 400
                ORDER BY timestamp DESC
                LIMIT ?
                "#,
            )
            .bind(limit)
            .fetch_all(pool)
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
        } else {
            Ok(Vec::new())
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TrafficStats {
    pub total_requests: i64,
    pub avg_duration: f64,
    pub error_count: i64,
    pub unique_clients: i64,
    pub total_bytes: u64,
    pub time_window_hours: i64,
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            avg_duration: 0.0,
            error_count: 0,
            unique_clients: 0,
            total_bytes: 0,
            time_window_hours: 0,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TargetTrafficStats {
    pub target: String,
    pub request_count: i64,
    pub avg_duration: f64,
    pub error_count: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DatabaseConfig, FileConfig};
    use hyper::StatusCode;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn create_test_logging_config_file_only() -> (LoggingConfig, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = LoggingConfig {
            enabled: true,
            log_type: LoggingType::File,
            database: None,
            file: Some(FileConfig {
                directory: temp_dir.path().to_string_lossy().to_string(),
                max_file_size: Some(1_000_000), // 1MB
                rotation: true,
            }),
            retention_days: Some(7),
        };
        (config, temp_dir)
    }

    fn create_test_logging_config_db_only() -> (LoggingConfig, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        // Use in-memory database for testing to avoid file system issues
        let config = LoggingConfig {
            enabled: true,
            log_type: LoggingType::Database,
            database: Some(DatabaseConfig {
                url: "sqlite::memory:".to_string(),
                max_connections: Some(5),
                connection_timeout: Some(30),
            }),
            file: None,
            retention_days: Some(7),
        };
        (config, temp_dir)
    }

    fn create_test_logging_config_both() -> (LoggingConfig, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        // Use in-memory database for testing to avoid file system issues
        let config = LoggingConfig {
            enabled: true,
            log_type: LoggingType::Both,
            database: Some(DatabaseConfig {
                url: "sqlite::memory:".to_string(),
                max_connections: Some(5),
                connection_timeout: Some(30),
            }),
            file: Some(FileConfig {
                directory: temp_dir.path().join("logs").to_string_lossy().to_string(),
                max_file_size: Some(1_000_000),
                rotation: true,
            }),
            retention_days: Some(7),
        };
        (config, temp_dir)
    }

    fn create_disabled_logging_config() -> LoggingConfig {
        LoggingConfig {
            enabled: false,
            log_type: LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        }
    }

    #[tokio::test]
    async fn test_traffic_logger_creation() {
        let config = create_disabled_logging_config();
        let logger = TrafficLogger::new(config.clone());

        assert_eq!(logger.config.enabled, config.enabled);
        assert!(logger.db_pool.is_none());
    }

    #[tokio::test]
    async fn test_disabled_logger_initialization() {
        let config = create_disabled_logging_config();
        let mut logger = TrafficLogger::new(config);

        let result = logger.initialize().await;
        assert!(result.is_ok());
        assert!(logger.db_pool.is_none());
    }

    #[tokio::test]
    async fn test_file_logger_initialization() {
        let (config, _temp_dir) = create_test_logging_config_file_only();
        let mut logger = TrafficLogger::new(config);

        let result = logger.initialize().await;
        assert!(result.is_ok());
        assert!(logger.db_pool.is_none());

        // Verify log directory was created
        assert!(_temp_dir.path().exists());
    }

    #[tokio::test]
    async fn test_database_logger_initialization() {
        let (config, _temp_dir) = create_test_logging_config_db_only();
        let mut logger = TrafficLogger::new(config);

        let result = logger.initialize().await;
        if result.is_err() {
            tracing::error!(
                "Database initialization error: {:?}",
                result.as_ref().unwrap_err()
            );
        }
        assert!(
            result.is_ok(),
            "Database initialization failed: {:?}",
            result.unwrap_err()
        );
        assert!(logger.db_pool.is_some());
    }

    #[tokio::test]
    async fn test_both_logger_initialization() {
        let (config, _temp_dir) = create_test_logging_config_both();
        let mut logger = TrafficLogger::new(config);

        let result = logger.initialize().await;
        assert!(result.is_ok());
        assert!(logger.db_pool.is_some());

        // Verify log directory was created
        let logs_dir = _temp_dir.path().join("logs");
        assert!(logs_dir.exists());
    }

    #[tokio::test]
    async fn test_disabled_logger_no_logging() {
        let config = create_disabled_logging_config();
        let logger = TrafficLogger::new(config);

        let request_id = Uuid::new_v4();
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let result = logger
            .log_request(
                request_id,
                client_addr,
                "example.com",
                "GET",
                "/test",
                "backend1",
                StatusCode::OK,
                Utc::now(),
                std::time::Duration::from_millis(100),
                Some("test-agent/1.0"),
                None,
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_file_logging() {
        let (config, _temp_dir) = create_test_logging_config_file_only();
        let mut logger = TrafficLogger::new(config);
        logger.initialize().await.unwrap();

        let request_id = Uuid::new_v4();
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

        let result = logger
            .log_request(
                request_id,
                client_addr,
                "example.com",
                "POST",
                "/api/test",
                "backend1",
                StatusCode::CREATED,
                Utc::now(),
                std::time::Duration::from_millis(250),
                Some("test-agent/1.0"),
                None,
            )
            .await;

        assert!(result.is_ok());

        // Check that log file was created
        let log_files: Vec<_> = std::fs::read_dir(_temp_dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".log"))
            .collect();

        assert!(!log_files.is_empty(), "No log files were created");
    }

    #[tokio::test]
    async fn test_database_logging() {
        let (config, _temp_dir) = create_test_logging_config_db_only();
        let mut logger = TrafficLogger::new(config);
        logger.initialize().await.unwrap();

        let request_id = Uuid::new_v4();
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);

        let result = logger
            .log_request(
                request_id,
                client_addr,
                "api.example.com",
                "PUT",
                "/api/users/123",
                "backend2",
                StatusCode::NO_CONTENT,
                Utc::now(),
                std::time::Duration::from_millis(150),
                Some("mobile-app/2.1"),
                None,
            )
            .await;

        assert!(result.is_ok());

        // Verify data was written to database
        if let Some(ref pool) = logger.db_pool {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM traffic_logs WHERE id = ?")
                .bind(request_id.to_string())
                .fetch_one(pool)
                .await
                .unwrap();
            assert_eq!(count, 1);
        }
    }

    #[tokio::test]
    async fn test_error_logging() {
        let (config, _temp_dir) = create_test_logging_config_db_only();
        let mut logger = TrafficLogger::new(config);
        logger.initialize().await.unwrap();

        let request_id = Uuid::new_v4();
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 8443);

        let result = logger
            .log_request(
                request_id,
                client_addr,
                "error.example.com",
                "GET",
                "/fail",
                "backend3",
                StatusCode::INTERNAL_SERVER_ERROR,
                Utc::now(),
                std::time::Duration::from_millis(50),
                Some("curl/7.68.0"),
                Some("Database connection failed"),
            )
            .await;

        assert!(result.is_ok());

        // Verify error was logged with error message
        if let Some(ref pool) = logger.db_pool {
            let error_msg: String =
                sqlx::query_scalar("SELECT error_message FROM traffic_logs WHERE id = ?")
                    .bind(request_id.to_string())
                    .fetch_one(pool)
                    .await
                    .unwrap();
            assert_eq!(error_msg, "Database connection failed");
        }
    }

    #[tokio::test]
    async fn test_both_logging_types() {
        let (config, _temp_dir) = create_test_logging_config_both();
        let mut logger = TrafficLogger::new(config);
        logger.initialize().await.unwrap();

        let request_id = Uuid::new_v4();
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 80);

        let result = logger
            .log_request(
                request_id,
                client_addr,
                "both.example.com",
                "DELETE",
                "/api/resource/456",
                "backend4",
                StatusCode::OK,
                Utc::now(),
                std::time::Duration::from_millis(75),
                Some("integration-test/1.0"),
                None,
            )
            .await;

        assert!(result.is_ok());

        // Verify database logging
        if let Some(ref pool) = logger.db_pool {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM traffic_logs WHERE id = ?")
                .bind(request_id.to_string())
                .fetch_one(pool)
                .await
                .unwrap();
            assert_eq!(count, 1);
        }

        // Verify file logging
        let logs_dir = _temp_dir.path().join("logs");
        let log_files: Vec<_> = std::fs::read_dir(logs_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".log"))
            .collect();
        assert!(!log_files.is_empty(), "No log files were created");
    }

    #[tokio::test]
    async fn test_traffic_log_serialization() {
        let log_entry = TrafficLog {
            id: "test-123".to_string(),
            timestamp: Utc::now(),
            client_ip: "192.168.1.1".to_string(),
            host: "test.example.com".to_string(),
            method: "GET".to_string(),
            path: "/test".to_string(),
            target: "backend1".to_string(),
            status_code: 200,
            duration_ms: 100,
            request_size: Some(1024),
            response_size: Some(2048),
            user_agent: Some("test-agent".to_string()),
            error_message: None,
        };

        let json_result = serde_json::to_string(&log_entry);
        assert!(json_result.is_ok());

        let json_str = json_result.unwrap();
        let deserialized: Result<TrafficLog, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok());

        let deserialized_log = deserialized.unwrap();
        assert_eq!(deserialized_log.id, log_entry.id);
        assert_eq!(deserialized_log.status_code, log_entry.status_code);
    }

    #[tokio::test]
    async fn test_traffic_stats_default() {
        let stats = TrafficStats::default();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.avg_duration, 0.0);
        assert_eq!(stats.error_count, 0);
        assert_eq!(stats.unique_clients, 0);
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.time_window_hours, 0);
    }

    #[tokio::test]
    async fn test_multiple_requests_different_targets() {
        let (config, _temp_dir) = create_test_logging_config_db_only();
        let mut logger = TrafficLogger::new(config);
        logger.initialize().await.unwrap();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)), 8080);
        let timestamp = Utc::now();

        // Log requests to different targets
        for i in 1..=3 {
            let request_id = Uuid::new_v4();
            let result = logger
                .log_request(
                    request_id,
                    client_addr,
                    "multi.example.com",
                    "GET",
                    &format!("/api/endpoint/{}", i),
                    &format!("backend{}", i),
                    if i == 2 {
                        StatusCode::BAD_REQUEST
                    } else {
                        StatusCode::OK
                    },
                    timestamp,
                    std::time::Duration::from_millis(100 + i as u64 * 50),
                    Some("multi-test/1.0"),
                    if i == 2 {
                        Some("Validation error")
                    } else {
                        None
                    },
                )
                .await;
            assert!(result.is_ok());
        }

        // Verify all requests were logged
        if let Some(ref pool) = logger.db_pool {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM traffic_logs WHERE host = ?")
                .bind("multi.example.com")
                .fetch_one(pool)
                .await
                .unwrap();
            assert_eq!(count, 3);

            // Verify error was logged
            let error_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM traffic_logs WHERE host = ? AND error_message IS NOT NULL",
            )
            .bind("multi.example.com")
            .fetch_one(pool)
            .await
            .unwrap();
            assert_eq!(error_count, 1);
        }
    }

    #[tokio::test]
    async fn test_concurrent_logging() {
        let (config, _temp_dir) = create_test_logging_config_db_only();
        let mut logger = TrafficLogger::new(config);
        logger.initialize().await.unwrap();

        let logger = std::sync::Arc::new(logger);
        let mut handles = Vec::new();

        // Create multiple concurrent logging tasks
        for i in 0..10 {
            let logger_clone = std::sync::Arc::clone(&logger);
            let handle = tokio::spawn(async move {
                let request_id = Uuid::new_v4();
                let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i + 1)), 8080);

                logger_clone
                    .log_request(
                        request_id,
                        client_addr,
                        "concurrent.example.com",
                        "GET",
                        &format!("/concurrent/{}", i),
                        "backend1",
                        StatusCode::OK,
                        Utc::now(),
                        std::time::Duration::from_millis(50),
                        Some("concurrent-test/1.0"),
                        None,
                    )
                    .await
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }

        // Verify all requests were logged
        if let Some(ref pool) = logger.db_pool {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM traffic_logs WHERE host = ?")
                .bind("concurrent.example.com")
                .fetch_one(pool)
                .await
                .unwrap();
            assert_eq!(count, 10);
        }
    }

    #[tokio::test]
    async fn test_ipv6_client_address() {
        let (config, _temp_dir) = create_test_logging_config_db_only();
        let mut logger = TrafficLogger::new(config);
        logger.initialize().await.unwrap();

        let request_id = Uuid::new_v4();
        let client_addr = SocketAddr::new(IpAddr::V6("2001:db8::1".parse().unwrap()), 8080);

        let result = logger
            .log_request(
                request_id,
                client_addr,
                "ipv6.example.com",
                "GET",
                "/ipv6/test",
                "backend1",
                StatusCode::OK,
                Utc::now(),
                std::time::Duration::from_millis(25),
                Some("ipv6-test/1.0"),
                None,
            )
            .await;

        assert!(result.is_ok());

        // Verify IPv6 address was logged correctly
        if let Some(ref pool) = logger.db_pool {
            let client_ip: String =
                sqlx::query_scalar("SELECT client_ip FROM traffic_logs WHERE id = ?")
                    .bind(request_id.to_string())
                    .fetch_one(pool)
                    .await
                    .unwrap();
            assert_eq!(client_ip, "2001:db8::1");
        }
    }

    #[tokio::test]
    async fn test_logging_with_invalid_unicode_in_fields() {
        let (config, _temp_dir) = create_test_logging_config_db_only();
        let mut logger = TrafficLogger::new(config);
        logger.initialize().await.unwrap();

        let request_id = Uuid::new_v4();
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        // Test with various edge case strings
        let test_cases = vec![
            ("", "", "", ""), // Empty strings
            ("🔥🚀", "GET", "/🎯", "backend-🌟"), // Unicode emojis
            ("very-long-domain-name-that-exceeds-normal-limits-and-could-potentially-cause-issues-with-database-constraints.example.com", "GET", "/", "backend1"), // Very long domain
            ("example.com", "CUSTOM_METHOD", "/", "backend1"), // Non-standard HTTP method
            ("example.com", "GET", "/path/with spaces/and/special&chars?param=value", "backend1"), // Path with spaces and special chars
        ];

        for (host, method, path, target) in test_cases {
            let result = logger
                .log_request(
                    request_id,
                    client_addr,
                    host,
                    method,
                    path,
                    target,
                    StatusCode::OK,
                    Utc::now(),
                    std::time::Duration::from_millis(100),
                    Some("test-agent/1.0"),
                    None,
                )
                .await;

            assert!(
                result.is_ok(),
                "Failed to log request with host='{}', method='{}', path='{}', target='{}'",
                host,
                method,
                path,
                target
            );
        }
    }

    #[tokio::test]
    async fn test_logging_with_extreme_values() {
        let (config, _temp_dir) = create_test_logging_config_db_only();
        let mut logger = TrafficLogger::new(config);
        logger.initialize().await.unwrap();

        let request_id = Uuid::new_v4();
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        // Test with extreme duration values
        let extreme_durations = vec![
            std::time::Duration::from_nanos(1),   // Very small duration
            std::time::Duration::from_secs(3600), // Very large duration (1 hour)
            std::time::Duration::from_millis(0),  // Zero duration
        ];

        for duration in extreme_durations {
            let result = logger
                .log_request(
                    request_id,
                    client_addr,
                    "example.com",
                    "GET",
                    "/test",
                    "backend1",
                    StatusCode::OK,
                    Utc::now(),
                    duration,
                    Some("test-agent/1.0"),
                    None,
                )
                .await;

            assert!(
                result.is_ok(),
                "Failed to log request with duration {:?}",
                duration
            );
        }
    }

    #[tokio::test]
    async fn test_logging_concurrent_requests() {
        let (config, _temp_dir) = create_test_logging_config_db_only();
        let mut logger = TrafficLogger::new(config);
        logger.initialize().await.unwrap();

        let logger = Arc::new(logger);
        let mut handles = Vec::new();

        // Create many concurrent logging tasks
        for i in 0..50 {
            let logger_clone = Arc::clone(&logger);
            let handle = tokio::spawn(async move {
                let request_id = Uuid::new_v4();
                let client_addr =
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000 + i);

                logger_clone
                    .log_request(
                        request_id,
                        client_addr,
                        &format!("concurrent-{}.example.com", i),
                        "GET",
                        &format!("/test/{}", i),
                        &format!("backend-{}", i % 3 + 1),
                        if i % 2 == 0 {
                            StatusCode::OK
                        } else {
                            StatusCode::INTERNAL_SERVER_ERROR
                        },
                        Utc::now(),
                        std::time::Duration::from_millis(100 + i as u64),
                        Some("concurrent-test/1.0"),
                        if i % 5 == 0 {
                            Some("Simulated error")
                        } else {
                            None
                        },
                    )
                    .await
            });
            handles.push(handle);
        }

        // Wait for all logging operations to complete
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok(), "Concurrent logging failed");
        }

        // Verify that all logs were written
        if let Some(ref pool) = logger.db_pool {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM traffic_logs")
                .fetch_one(pool)
                .await
                .unwrap();
            assert!(
                count >= 50,
                "Expected at least 50 log entries, found {}",
                count
            );
        }
    }

    #[tokio::test]
    async fn test_database_connection_failure_handling() {
        let config = LoggingConfig {
            enabled: true,
            log_type: LoggingType::Database,
            database: Some(DatabaseConfig {
                url: "sqlite:///invalid/path/that/does/not/exist.db".to_string(),
                max_connections: Some(5),
                connection_timeout: Some(1), // Very short timeout
            }),
            file: None,
            retention_days: Some(7),
        };

        let mut logger = TrafficLogger::new(config);

        // This should fail gracefully
        let result = logger.initialize().await;
        assert!(
            result.is_err(),
            "Database initialization should fail with invalid path"
        );

        // Even with failed initialization, logging should not panic but may succeed if it falls back gracefully
        let request_id = Uuid::new_v4();
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let log_result = logger
            .log_request(
                request_id,
                client_addr,
                "test.example.com",
                "GET",
                "/test",
                "backend1",
                StatusCode::OK,
                Utc::now(),
                std::time::Duration::from_millis(100),
                Some("test-agent/1.0"),
                None,
            )
            .await;

        // The test passes if it doesn't panic - the exact result depends on the implementation
        // Some implementations might fail gracefully, others might succeed with fallback behavior
        match log_result {
            Ok(_) => tracing::debug!("Logger handled database failure gracefully with fallback"),
            Err(_) => tracing::debug!("Logger correctly reported database failure"),
        }
    }

    #[tokio::test]
    async fn test_get_traffic_stats_edge_cases() {
        let (config, _temp_dir) = create_test_logging_config_db_only();
        let mut logger = TrafficLogger::new(config);
        logger.initialize().await.unwrap();

        // Test when database is empty
        let result_empty = logger.get_traffic_stats(10).await;
        assert!(result_empty.is_ok());
        let stats = result_empty.unwrap();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.error_count, 0);
        assert_eq!(stats.unique_clients, 0);

        // Test with reasonable but large limit (1 year)
        let result_large = logger.get_traffic_stats(8760).await; // 365 * 24 hours
        assert!(result_large.is_ok());

        // Test with zero hours (edge case)
        let result_zero = logger.get_traffic_stats(0).await;
        assert!(result_zero.is_ok());
    }
}
