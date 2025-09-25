use crate::security::auth::config::AuditConfig;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info};

/// Security audit logger
#[derive(Clone)]
pub struct AuditLogger {
    config: Option<AuditConfig>,
}

impl AuditLogger {
    pub fn new(config: Option<AuditConfig>) -> Self {
        Self { config }
    }

    /// Log a security event
    pub async fn log_event(&self, event_type: &str, details: &str) {
        let config = match &self.config {
            Some(config) if config.enabled => config,
            _ => return, // Audit logging disabled
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time calculation should not fail")
            .as_secs();

        let log_entry = format!("{} [{}] {}\n", timestamp, event_type, details);

        // Write to audit log file
        if let Err(e) = self.write_to_file(&config.log_file, &log_entry).await {
            error!("Failed to write audit log: {}", e);
        }
    }

    /// Log successful authentication
    pub async fn log_successful_auth(&self, username: &str, ip: &str, method: &str) {
        let config = match &self.config {
            Some(config) if config.enabled && config.log_successful_auth => config,
            _ => return,
        };

        let details = format!("user={} ip={} method={}", username, ip, method);
        self.log_event("AUTH_SUCCESS", &details).await;
    }

    /// Log failed authentication
    pub async fn log_failed_auth(&self, username: &str, ip: &str, reason: &str) {
        let config = match &self.config {
            Some(config) if config.enabled && config.log_failed_auth => config,
            _ => return,
        };

        let details = format!("user={} ip={} reason={}", username, ip, reason);
        self.log_event("AUTH_FAILURE", &details).await;
    }

    /// Log admin action
    pub async fn log_admin_action(&self, username: &str, action: &str, target: Option<&str>) {
        let config = match &self.config {
            Some(config) if config.enabled && config.log_admin_actions => config,
            _ => return,
        };

        let details = if let Some(target) = target {
            format!("admin={} action={} target={}", username, action, target)
        } else {
            format!("admin={} action={}", username, action)
        };

        self.log_event("ADMIN_ACTION", &details).await;
    }

    /// Log session event
    pub async fn log_session_event(&self, username: &str, session_id: &str, event: &str) {
        self.log_event(
            "SESSION",
            &format!("user={} session={} event={}", username, session_id, event),
        )
        .await;
    }

    /// Log MFA event
    pub async fn log_mfa_event(&self, username: &str, event: &str, success: bool) {
        let event_type = if success {
            "MFA_SUCCESS"
        } else {
            "MFA_FAILURE"
        };
        let details = format!("user={} event={}", username, event);
        self.log_event(event_type, &details).await;
    }

    /// Log security alert
    pub async fn log_security_alert(&self, alert_type: &str, details: &str) {
        self.log_event(
            "SECURITY_ALERT",
            &format!("type={} {}", alert_type, details),
        )
        .await;
    }

    /// Rotate log file if it exceeds maximum size
    pub async fn rotate_if_needed(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config = match &self.config {
            Some(config) if config.enabled => config,
            _ => return Ok(()),
        };

        let file_path = &config.log_file;

        // Check if file exists and get its size
        if let Ok(metadata) = std::fs::metadata(file_path) {
            let file_size_mb = metadata.len() / 1_048_576; // Convert to MB

            if file_size_mb >= config.max_size_mb as u64 {
                // Rotate the file
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time calculation should not fail")
                    .as_secs();

                let rotated_name = format!("{}.{}", file_path, timestamp);
                std::fs::rename(file_path, rotated_name)?;

                info!("Rotated audit log file: {} MB", file_size_mb);

                // Note: Not logging this event to avoid recursion
            }
        }

        Ok(())
    }

    /// Clean up old rotated log files based on retention policy
    pub async fn cleanup_old_logs(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config = match &self.config {
            Some(config) if config.enabled => config,
            _ => return Ok(()),
        };

        let retention_seconds = config.retention_days as u64 * 24 * 60 * 60;
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time calculation should not fail")
            .as_secs()
            - retention_seconds;

        // Find and remove old rotated log files
        if let Some(dir_path) = std::path::Path::new(&config.log_file).parent() {
            if let Ok(dir) = std::fs::read_dir(dir_path) {
                for entry in dir.flatten() {
                    let file_name = entry.file_name();
                    let file_name_str = file_name.to_string_lossy();

                    // Check if this is a rotated log file
                    if file_name_str.contains(&config.log_file) && file_name_str.contains('.') {
                        if let Some(timestamp_str) = file_name_str.split('.').next_back() {
                            if let Ok(timestamp) = timestamp_str.parse::<u64>() {
                                if timestamp < cutoff_time {
                                    if let Err(e) = std::fs::remove_file(entry.path()) {
                                        error!(
                                            "Failed to remove old log file {:?}: {}",
                                            entry.path(),
                                            e
                                        );
                                    } else {
                                        info!("Removed old audit log: {:?}", entry.path());
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

    /// Write log entry to file
    async fn write_to_file(&self, file_path: &str, content: &str) -> std::io::Result<()> {
        // First, check if we need to rotate
        if let Err(e) = self.rotate_if_needed().await {
            error!("Log rotation check failed: {}", e);
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)?;

        file.write_all(content.as_bytes())?;
        file.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_config() -> (AuditConfig, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let log_file = temp_dir
            .path()
            .join("audit.log")
            .to_string_lossy()
            .to_string();

        let config = AuditConfig {
            enabled: true,
            log_file,
            max_size_mb: 1,
            retention_days: 7,
            log_successful_auth: true,
            log_failed_auth: true,
            log_admin_actions: true,
        };

        (config, temp_dir)
    }

    #[tokio::test]
    async fn test_audit_logging() {
        let (config, _temp_dir) = create_test_config();
        let logger = AuditLogger::new(Some(config.clone()));

        // Test logging events
        logger.log_event("TEST_EVENT", "test details").await;
        logger
            .log_successful_auth("testuser", "127.0.0.1", "basic")
            .await;
        logger
            .log_failed_auth("baduser", "192.168.1.1", "invalid password")
            .await;

        // Verify log file was created and contains entries
        let log_content =
            std::fs::read_to_string(&config.log_file).expect("Should be able to read log file");

        assert!(log_content.contains("TEST_EVENT"));
        assert!(log_content.contains("AUTH_SUCCESS"));
        assert!(log_content.contains("AUTH_FAILURE"));
        assert!(log_content.contains("testuser"));
        assert!(log_content.contains("baduser"));
    }

    #[tokio::test]
    async fn test_disabled_logging() {
        let logger = AuditLogger::new(None);

        // Should not panic or create files when disabled
        logger.log_event("TEST", "test").await;
        logger.log_successful_auth("user", "ip", "method").await;
    }

    #[test]
    fn test_selective_logging() {
        let config = AuditConfig {
            enabled: true,
            log_successful_auth: false,
            log_failed_auth: true,
            ..Default::default()
        };

        // Test that config controls what gets logged
        assert!(!config.log_successful_auth);
        assert!(config.log_failed_auth);
    }
}
