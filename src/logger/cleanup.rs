#![allow(dead_code)]
use crate::error::DispaResult;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use super::database::DatabaseManager;
use super::file_logger::FileLogger;

/// Background cleanup task manager for traffic logs
pub struct CleanupManager {
    /// Handle to the running cleanup task
    task_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
    /// Retention period in days
    retention_days: u32,
}

impl CleanupManager {
    /// Create a new cleanup manager
    pub fn new(retention_days: u32) -> Self {
        Self {
            task_handle: Arc::new(RwLock::new(None)),
            retention_days,
        }
    }

    /// Start the cleanup task
    pub async fn start(
        &self,
        db_manager: Option<Arc<DatabaseManager>>,
        file_logger: Option<Arc<FileLogger>>,
    ) {
        self.stop().await;

        let retention_days = self.retention_days;
        let task_handle = Arc::clone(&self.task_handle);

        let handle = tokio::spawn(async move {
            info!(
                "Starting cleanup task with {}-day retention",
                retention_days
            );

            let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60)); // Daily cleanup

            loop {
                interval.tick().await;

                if let Some(ref db) = db_manager {
                    if let Err(e) = db.cleanup_old_logs(retention_days).await {
                        error!("Database cleanup failed: {}", e);
                    }
                }

                if let Some(ref file_logger) = file_logger {
                    if let Err(e) = file_logger.cleanup_old_files(retention_days).await {
                        error!("File cleanup failed: {}", e);
                    }
                }

                info!("Cleanup task completed successfully");
            }
        });

        *task_handle.write().unwrap() = Some(handle);
        info!("Cleanup task started");
    }

    /// Stop the cleanup task
    pub async fn stop(&self) {
        let mut handle_guard = self.task_handle.write().unwrap();
        if let Some(handle) = handle_guard.take() {
            handle.abort();
            info!("Cleanup task stopped");
        }
    }

    /// Restart the cleanup task with new retention period
    pub async fn restart(
        &mut self,
        retention_days: u32,
        db_manager: Option<Arc<DatabaseManager>>,
        file_logger: Option<Arc<FileLogger>>,
    ) {
        info!(
            "Restarting cleanup task with {}-day retention",
            retention_days
        );
        self.retention_days = retention_days;
        self.start(db_manager, file_logger).await;
    }

    /// Perform immediate cleanup (can be called manually)
    pub async fn cleanup_now(
        &self,
        db_manager: Option<&DatabaseManager>,
        file_logger: Option<&FileLogger>,
    ) -> DispaResult<()> {
        info!("Performing immediate cleanup");

        if let Some(db) = db_manager {
            if let Err(e) = db.cleanup_old_logs(self.retention_days).await {
                error!("Immediate database cleanup failed: {}", e);
                return Err(e);
            }
        }

        if let Some(file_logger) = file_logger {
            if let Err(e) = file_logger.cleanup_old_files(self.retention_days).await {
                error!("Immediate file cleanup failed: {}", e);
                return Err(e);
            }
        }

        info!("Immediate cleanup completed successfully");
        Ok(())
    }

    /// Check if cleanup task is running
    pub fn is_running(&self) -> bool {
        self.task_handle.read().unwrap().is_some()
    }

    /// Get current retention period
    pub fn get_retention_days(&self) -> u32 {
        self.retention_days
    }

    /// Update retention period (requires restart to take effect)
    pub fn set_retention_days(&mut self, retention_days: u32) {
        if retention_days != self.retention_days {
            warn!(
                "Updating retention period from {} to {} days. Restart cleanup task to apply changes.",
                self.retention_days, retention_days
            );
            self.retention_days = retention_days;
        }
    }
}

impl Drop for CleanupManager {
    fn drop(&mut self) {
        // Abort the task when the manager is dropped
        if let Ok(mut handle_guard) = self.task_handle.write() {
            if let Some(handle) = handle_guard.take() {
                handle.abort();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cleanup_manager_lifecycle() {
        let manager = CleanupManager::new(30);

        // Initially not running
        assert!(!manager.is_running());
        assert_eq!(manager.get_retention_days(), 30);

        // Start (without actual database/file logger for this test)
        manager.start(None, None).await;
        assert!(manager.is_running());

        // Stop
        manager.stop().await;
        assert!(!manager.is_running());
    }

    #[tokio::test]
    async fn test_cleanup_manager_retention_update() {
        let mut manager = CleanupManager::new(7);
        assert_eq!(manager.get_retention_days(), 7);

        manager.set_retention_days(30);
        assert_eq!(manager.get_retention_days(), 30);
    }

    #[tokio::test]
    async fn test_cleanup_now_without_loggers() {
        let manager = CleanupManager::new(7);

        // Should succeed even without database or file logger
        let result = manager.cleanup_now(None, None).await;
        assert!(result.is_ok());
    }
}
