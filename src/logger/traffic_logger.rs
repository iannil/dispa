use crate::error::DispaResult;
use chrono::{DateTime, Utc};
use hyper::StatusCode;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration as StdDuration, Instant};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::config::{LoggingConfig, LoggingType};

use super::cleanup::CleanupManager;
use super::database::DatabaseManager;
use super::file_logger::FileLogger;
pub use super::models::{TargetTrafficStats, TrafficLog, TrafficStats};

/// Main traffic logger that coordinates database, file logging, and cleanup
#[derive(Clone)]
pub struct TrafficLogger {
    config: Arc<RwLock<LoggingConfig>>,
    db_manager: Arc<RwLock<Option<Arc<DatabaseManager>>>>,
    file_logger: Arc<RwLock<Option<Arc<FileLogger>>>>,
    cleanup_manager: Arc<RwLock<Option<CleanupManager>>>,
}

impl TrafficLogger {
    /// Create a new traffic logger with the given configuration
    pub fn new(config: LoggingConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            db_manager: Arc::new(RwLock::new(None)),
            file_logger: Arc::new(RwLock::new(None)),
            cleanup_manager: Arc::new(RwLock::new(None)),
        }
    }

    /// Helper method to safely read config with better error messages
    fn read_config(&self) -> DispaResult<LoggingConfig> {
        let config = self.config.read()
            .map_err(|e| crate::error::DispaError::internal(format!("Config lock poisoned: {}", e)))?
            .clone();
        Ok(config)
    }

    /// Helper method to safely read db_manager
    fn read_db_manager(&self) -> DispaResult<Option<Arc<DatabaseManager>>> {
        Ok(self.db_manager.read()
            .map_err(|e| crate::error::DispaError::internal(format!("DB manager lock poisoned: {}", e)))?
            .clone())
    }

    /// Helper method to safely read file_logger
    fn read_file_logger(&self) -> DispaResult<Option<Arc<FileLogger>>> {
        Ok(self.file_logger.read()
            .map_err(|e| crate::error::DispaError::internal(format!("File logger lock poisoned: {}", e)))?
            .clone())
    }

    /// Initialize the traffic logger components
    pub async fn initialize(&mut self) -> DispaResult<()> {
        self.initialize_shared().await
    }

    /// Initialize shared resources (idempotent)
    pub async fn initialize_shared(&self) -> DispaResult<()> {
        let config = self.read_config()?;

        if !config.enabled {
            info!("Traffic logging is disabled");
            return Ok(());
        }

        // Initialize database if needed
        match config.log_type {
            LoggingType::Database | LoggingType::Both => {
                if let Some(ref db_config) = config.database {
                    info!("Initializing database logging to: {}", db_config.url);
                    let db_manager = Arc::new(DatabaseManager::new(&db_config.url).await?);
                    *self.db_manager.write()
                        .map_err(|e| crate::error::DispaError::internal(format!("Failed to write db_manager lock: {}", e)))?
                        = Some(db_manager);
                    info!("Database logging initialized successfully");
                }
            }
            LoggingType::File => {}
        }

        // Initialize file logger if needed
        if matches!(config.log_type, LoggingType::File | LoggingType::Both) {
            if let Some(ref file_config) = config.file {
                let file_logger = Arc::new(FileLogger::new(file_config.clone()));
                file_logger.initialize().await?;
                file_logger.ensure_csv_header().await?;
                *self.file_logger.write()
                    .map_err(|e| crate::error::DispaError::internal(format!("Failed to write file_logger lock: {}", e)))?
                    = Some(file_logger);
                info!("File logging initialized successfully");
            }
        }

        // Start cleanup task if retention is configured
        if let Some(retention_days) = config.retention_days {
            if retention_days > 0 {
                self.start_cleanup_task(retention_days).await;
            } else {
                self.stop_cleanup_task().await;
            }
        } else {
            self.stop_cleanup_task().await;
        }

        Ok(())
    }

    /// Log a request/response cycle
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
    ) -> DispaResult<()> {
        if !self.read_config()?.enabled {
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
            request_size: None,  // Can be extended to track actual sizes
            response_size: None, // Can be extended to track actual sizes
            user_agent: user_agent.map(|s| s.to_string()),
            error_message: error_message.map(|s| s.to_string()),
        };

        // 读取日志类型而不需要clone整个配置
        let log_type = self.read_config()?.log_type;

        match log_type {
            LoggingType::Database => {
                self.log_to_database(&log_entry).await?;
            }
            LoggingType::File => {
                self.log_to_file(&log_entry).await?;
            }
            LoggingType::Both => {
                // Log to both, but don't fail if one fails
                if let Err(e) = self.log_to_database(&log_entry).await {
                    warn!("Failed to log to database: {}", e);
                    metrics::counter!("dispa_log_write_errors_total", &[("type", "database")])
                        .increment(1);
                }
                if let Err(e) = self.log_to_file(&log_entry).await {
                    warn!("Failed to log to file: {}", e);
                    metrics::counter!("dispa_log_write_errors_total", &[("type", "file")])
                        .increment(1);
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

    /// Log to database
    async fn log_to_database(&self, log_entry: &TrafficLog) -> DispaResult<()> {
        let start = Instant::now();
        let labels = [("type", "database")];

        // Clone the Arc to avoid holding the lock across await
        let db_manager = self.read_db_manager()?;

        if let Some(db_manager) = db_manager {
            let result = db_manager.insert_log(log_entry).await;
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

            metrics::histogram!("dispa_log_write_duration_ms", &labels).record(elapsed_ms);

            match result {
                Ok(_) => {
                    metrics::counter!("dispa_log_writes_total", &labels).increment(1);
                    // Also update daily summary
                    if let Err(e) = db_manager.update_daily_summary(log_entry).await {
                        warn!("Failed to update daily summary: {}", e);
                    }
                }
                Err(e) => {
                    metrics::counter!("dispa_log_write_errors_total", &labels).increment(1);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Log to file
    async fn log_to_file(&self, log_entry: &TrafficLog) -> DispaResult<()> {
        let start = Instant::now();
        let labels = [("type", "file")];

        // Clone the Arc to avoid holding the lock across await
        let file_logger = self.read_file_logger()?;

        if let Some(file_logger) = file_logger {
            let result = file_logger.write_log(log_entry).await;
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

            metrics::histogram!("dispa_log_write_duration_ms", &labels).record(elapsed_ms);

            match result {
                Ok(_) => {
                    metrics::counter!("dispa_log_writes_total", &labels).increment(1);
                }
                Err(e) => {
                    metrics::counter!("dispa_log_write_errors_total", &labels).increment(1);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Get traffic statistics for the last N hours
    pub async fn get_traffic_stats(&self, hours: i64) -> DispaResult<TrafficStats> {
        let db_manager = self.read_db_manager()?;
        if let Some(db_manager) = db_manager {
            db_manager.get_traffic_stats(hours).await
        } else {
            Ok(TrafficStats::default())
        }
    }

    /// Get traffic statistics by target for the last N hours
    pub async fn get_traffic_by_target(&self, hours: i64) -> DispaResult<Vec<TargetTrafficStats>> {
        let db_manager = self.read_db_manager()?;
        if let Some(db_manager) = db_manager {
            db_manager.get_traffic_by_target(hours).await
        } else {
            Ok(Vec::new())
        }
    }

    /// Get recent error logs
    #[allow(dead_code)]
    pub async fn get_error_logs(&self, limit: i64) -> DispaResult<Vec<TrafficLog>> {
        let db_manager = self.read_db_manager()?;
        if let Some(db_manager) = db_manager {
            db_manager.get_error_logs(limit).await
        } else {
            Ok(Vec::new())
        }
    }

    /// Manually trigger cleanup of old logs
    #[allow(dead_code)]
    pub async fn cleanup_old_logs(&self) -> DispaResult<()> {
        let retention_days = self.read_config()?.retention_days;

        if let Some(days) = retention_days {
            if days > 0 {
                let db_manager: Option<Arc<DatabaseManager>> = self.read_db_manager()?;
                let file_logger: Option<Arc<FileLogger>> = self.read_file_logger()?;

                // Cleanup database logs
                if let Some(ref db) = db_manager {
                    if let Err(e) = db.cleanup_old_logs(days).await {
                        error!("Database cleanup failed: {}", e);
                    } else {
                        metrics::counter!("dispa_log_cleanup_runs_total", &[("type", "database")])
                            .increment(1);
                    }
                }

                // Cleanup file logs
                if let Some(ref file_logger) = file_logger {
                    if let Err(e) = file_logger.cleanup_old_files(days).await {
                        error!("File cleanup failed: {}", e);
                    } else {
                        metrics::counter!("dispa_log_cleanup_runs_total", &[("type", "file")])
                            .increment(1);
                    }
                }

                info!("Manual cleanup completed");
            }
        }

        Ok(())
    }

    /// Reconfigure the logger with new settings
    pub async fn reconfigure(&self, new_config: LoggingConfig) -> DispaResult<()> {
        info!("Reconfiguring traffic logger");

        // Update config
        *self.config.write()
            .map_err(|e| crate::error::DispaError::internal(format!("Failed to write config lock: {}", e)))?
            = new_config.clone();

        // Stop existing cleanup task
        self.stop_cleanup_task().await;

        // Clear existing loggers
        *self.db_manager.write()
            .map_err(|e| crate::error::DispaError::internal(format!("Failed to write db_manager lock: {}", e)))?
            = None;
        *self.file_logger.write()
            .map_err(|e| crate::error::DispaError::internal(format!("Failed to write file_logger lock: {}", e)))?
            = None;

        // Reinitialize with new config
        self.initialize_shared().await?;

        info!("Traffic logger reconfiguration completed");
        Ok(())
    }

    /// Start the cleanup task
    async fn start_cleanup_task(&self, retention_days: u32) {
        let cleanup_manager = CleanupManager::new(retention_days);
        let db_manager = self.read_db_manager().unwrap_or(None);
        let file_logger = self.read_file_logger().unwrap_or(None);

        cleanup_manager.start(db_manager, file_logger).await;
        if let Ok(mut cleanup_guard) = self.cleanup_manager.write() {
            *cleanup_guard = Some(cleanup_manager);
        }
    }

    /// Stop the cleanup task
    async fn stop_cleanup_task(&self) {
        let cleanup_manager = if let Ok(mut cleanup_guard) = self.cleanup_manager.write() {
            cleanup_guard.take()
        } else {
            None
        };

        if let Some(cleanup_manager) = cleanup_manager {
            cleanup_manager.stop().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DatabaseConfig, FileConfig};
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::TempDir;

    fn create_test_config_db_only() -> (LoggingConfig, TempDir) {
        let temp_dir = TempDir::new().unwrap(); // OK in tests - expected to succeed

        (
            LoggingConfig {
                enabled: true,
                log_type: LoggingType::Database,
                database: Some(DatabaseConfig {
                    url: "sqlite::memory:".to_string(),
                    max_connections: None,
                    connection_timeout: None,
                }),
                file: None,
                retention_days: Some(30),
            },
            temp_dir,
        )
    }

    fn create_test_config_file_only() -> (LoggingConfig, TempDir) {
        let temp_dir = TempDir::new().unwrap(); // OK in tests - expected to succeed

        (
            LoggingConfig {
                enabled: true,
                log_type: LoggingType::File,
                database: None,
                file: Some(FileConfig {
                    directory: temp_dir.path().to_string_lossy().to_string(),
                    rotation: false,
                    max_file_size: None,
                }),
                retention_days: Some(7),
            },
            temp_dir,
        )
    }

    #[tokio::test]
    async fn test_traffic_logger_initialization() {
        let (config, _temp_dir) = create_test_config_db_only();
        let mut logger = TrafficLogger::new(config);

        let result = logger.initialize().await;
        if let Err(e) = &result {
            eprintln!("Initialization error: {}", e);
        }
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_traffic_logger_log_request() {
        let (config, _temp_dir) = create_test_config_db_only();
        let mut logger = TrafficLogger::new(config);
        logger.initialize().await.unwrap(); // OK in tests - expected to succeed

        let request_id = Uuid::new_v4();
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let result = logger
            .log_request(
                request_id,
                client_addr,
                "test.example.com",
                "GET",
                "/test",
                "backend1",
                StatusCode::OK,
                Utc::now(),
                StdDuration::from_millis(100),
                Some("test-agent/1.0"),
                None,
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_file_logger_initialization() {
        let (config, _temp_dir) = create_test_config_file_only();
        let mut logger = TrafficLogger::new(config);

        let result = logger.initialize().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_disabled_logger() {
        let config = LoggingConfig {
            enabled: false,
            log_type: LoggingType::File,
            database: None,
            file: None,
            retention_days: None,
        };

        let mut logger = TrafficLogger::new(config);
        let result = logger.initialize().await;
        assert!(result.is_ok());

        // Should succeed but do nothing
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
                StdDuration::from_millis(100),
                Some("test-agent/1.0"),
                None,
            )
            .await;

        assert!(log_result.is_ok());
    }
}
