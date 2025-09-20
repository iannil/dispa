use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite, SqlitePool, Row};
use std::net::SocketAddr;
use std::path::Path;
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::config::{LoggingConfig, LoggingType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficLog {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub host: String,
    pub target: String,
    pub status_code: u16,
    pub duration_ms: i64,
    pub request_size: Option<i64>,
    pub response_size: Option<i64>,
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
            return Ok(());
        }

        match self.config.log_type {
            LoggingType::Database | LoggingType::Both => {
                if let Some(ref db_config) = self.config.database {
                    self.db_pool = Some(self.setup_database(&db_config.url).await?);
                }
            }
            LoggingType::File => {}
        }

        // Create log directory if using file logging
        if matches!(self.config.log_type, LoggingType::File | LoggingType::Both) {
            if let Some(ref file_config) = self.config.file {
                tokio::fs::create_dir_all(&file_config.directory).await?;
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
                target TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                request_size INTEGER,
                response_size INTEGER
            )
            "#,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_traffic_logs_timestamp ON traffic_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_traffic_logs_host ON traffic_logs(host);
            CREATE INDEX IF NOT EXISTS idx_traffic_logs_target ON traffic_logs(target);
            "#,
        )
        .execute(&pool)
        .await?;

        Ok(pool)
    }

    pub async fn log_request(
        &self,
        request_id: Uuid,
        client_addr: SocketAddr,
        host: &str,
        target: &str,
        status: StatusCode,
        timestamp: DateTime<Utc>,
        duration: Duration,
    ) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let log_entry = TrafficLog {
            id: request_id.to_string(),
            timestamp,
            client_ip: client_addr.ip().to_string(),
            host: host.to_string(),
            target: target.to_string(),
            status_code: status.as_u16(),
            duration_ms: duration.num_milliseconds(),
            request_size: None,
            response_size: None,
        };

        match self.config.log_type {
            LoggingType::Database => {
                self.log_to_database(&log_entry).await?;
            }
            LoggingType::File => {
                self.log_to_file(&log_entry).await?;
            }
            LoggingType::Both => {
                if let Err(e) = self.log_to_database(&log_entry).await {
                    warn!("Failed to log to database: {}", e);
                }
                if let Err(e) = self.log_to_file(&log_entry).await {
                    warn!("Failed to log to file: {}", e);
                }
            }
        }

        debug!("Logged traffic for request {}", request_id);
        Ok(())
    }

    async fn log_to_database(&self, log_entry: &TrafficLog) -> Result<()> {
        if let Some(ref pool) = self.db_pool {
            sqlx::query(
                r#"
                INSERT INTO traffic_logs
                (id, timestamp, client_ip, host, target, status_code, duration_ms, request_size, response_size)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&log_entry.id)
            .bind(&log_entry.timestamp)
            .bind(&log_entry.client_ip)
            .bind(&log_entry.host)
            .bind(&log_entry.target)
            .bind(log_entry.status_code as i32)
            .bind(log_entry.duration_ms)
            .bind(log_entry.request_size)
            .bind(log_entry.response_size)
            .execute(pool)
            .await?;
        }
        Ok(())
    }

    async fn log_to_file(&self, log_entry: &TrafficLog) -> Result<()> {
        if let Some(ref file_config) = self.config.file {
            let log_line = serde_json::to_string(log_entry)?;
            let file_path = format!("{}/traffic-{}.log",
                                  file_config.directory,
                                  log_entry.timestamp.format("%Y-%m-%d"));

            tokio::fs::write(&file_path, format!("{}\n", log_line)).await?;
        }
        Ok(())
    }

    pub async fn cleanup_old_logs(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        if let Some(retention_days) = self.config.retention_days {
            let cutoff_date = Utc::now() - Duration::days(retention_days as i64);

            // Clean database logs
            if let Some(ref pool) = self.db_pool {
                match sqlx::query("DELETE FROM traffic_logs WHERE timestamp < ?")
                    .bind(&cutoff_date)
                    .execute(pool)
                    .await
                {
                    Ok(result) => {
                        debug!("Cleaned {} old database log entries", result.rows_affected());
                    }
                    Err(e) => {
                        error!("Failed to clean old database logs: {}", e);
                    }
                }
            }

            // Clean file logs
            if let Some(ref file_config) = self.config.file {
                if let Ok(mut dir) = tokio::fs::read_dir(&file_config.directory).await {
                    while let Ok(Some(entry)) = dir.next_entry().await {
                        if let Ok(metadata) = entry.metadata().await {
                            if let Ok(created) = metadata.created() {
                                let created_datetime = DateTime::<Utc>::from(created);
                                if created_datetime < cutoff_date {
                                    if let Err(e) = tokio::fs::remove_file(entry.path()).await {
                                        warn!("Failed to remove old log file {:?}: {}", entry.path(), e);
                                    } else {
                                        debug!("Removed old log file: {:?}", entry.path());
                                    }
                                }
                            }
                        }
                    }
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
                    COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count
                FROM traffic_logs
                WHERE timestamp >= ?
                "#,
            )
            .bind(&since)
            .fetch_one(pool)
            .await?;

            Ok(TrafficStats {
                total_requests: row.get("total_requests"),
                avg_duration: row.get::<Option<f64>, _>("avg_duration").unwrap_or(0.0),
                error_count: row.get("error_count"),
                time_window_hours: hours,
            })
        } else {
            Ok(TrafficStats::default())
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TrafficStats {
    pub total_requests: i64,
    pub avg_duration: f64,
    pub error_count: i64,
    pub time_window_hours: i64,
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            avg_duration: 0.0,
            error_count: 0,
            time_window_hours: 0,
        }
    }
}