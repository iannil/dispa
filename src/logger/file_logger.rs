#![allow(dead_code)]
use crate::error::DispaResult;
use chrono::Utc;
use serde_json;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info};

use super::models::TrafficLog;
use crate::config::FileConfig;

/// File-based traffic logging implementation
pub struct FileLogger {
    config: FileConfig,
}

impl FileLogger {
    /// Create a new file logger with the given configuration
    pub fn new(config: FileConfig) -> Self {
        Self { config }
    }

    /// Initialize the file logging directory
    pub async fn initialize(&self) -> DispaResult<()> {
        tokio::fs::create_dir_all(&self.config.directory).await?;
        info!("File logging directory created: {}", self.config.directory);
        Ok(())
    }

    /// Write a traffic log entry to file
    pub async fn write_log(&self, log_entry: &TrafficLog) -> DispaResult<()> {
        let file_path = self.get_log_file_path()?;

        // Default to JSON format
        let log_line = self.format_as_json(log_entry)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
            .await?;

        file.write_all(log_line.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;

        debug!("Traffic log written to file: {}", file_path);
        Ok(())
    }

    /// Get the appropriate log file path based on rotation settings
    fn get_log_file_path(&self) -> DispaResult<String> {
        let now = Utc::now();
        let filename = if self.config.rotation {
            format!("traffic-{}.log", now.format("%Y-%m-%d"))
        } else {
            "traffic.log".to_string()
        };

        Ok(format!("{}/{}", self.config.directory, filename))
    }

    /// Format log entry as JSON
    fn format_as_json(&self, log_entry: &TrafficLog) -> DispaResult<String> {
        serde_json::to_string(log_entry).map_err(Into::into)
    }

    /// Clean up old log files based on retention settings
    pub async fn cleanup_old_files(&self, retention_days: u32) -> DispaResult<()> {
        let cutoff_time = Utc::now() - chrono::Duration::days(retention_days as i64);
        let mut entries = tokio::fs::read_dir(&self.config.directory).await?;
        let mut deleted_count = 0;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_file() {
                if let Ok(metadata) = entry.metadata().await {
                    if let Ok(modified) = metadata.modified() {
                        let modified_datetime = chrono::DateTime::<Utc>::from(modified);
                        if modified_datetime < cutoff_time {
                            match tokio::fs::remove_file(&path).await {
                                Ok(_) => {
                                    debug!("Deleted old log file: {:?}", path);
                                    deleted_count += 1;
                                }
                                Err(e) => {
                                    error!("Failed to delete old log file {:?}: {}", path, e);
                                }
                            }
                        }
                    }
                }
            }
        }

        if deleted_count > 0 {
            info!(
                "Cleaned up {} old log files older than {} days",
                deleted_count, retention_days
            );
        }

        Ok(())
    }

    /// Get CSV header for CSV format logging (deprecated)
    pub fn get_csv_header() -> &'static str {
        "timestamp,client_ip,host,method,path,target,status_code,duration_ms,user_agent,error_message"
    }

    /// Write header if needed (for JSON, this does nothing)
    pub async fn ensure_csv_header(&self) -> DispaResult<()> {
        // For JSON format, no header needed
        Ok(())
    }

    /// Update configuration for hot reload
    pub fn update_config(&mut self, new_config: FileConfig) {
        self.config = new_config;
        info!("File logger configuration updated");
    }

    /// Get current configuration
    pub fn get_config(&self) -> &FileConfig {
        &self.config
    }
}
