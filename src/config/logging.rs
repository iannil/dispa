use serde::{Deserialize, Serialize};

/// Logging configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub enabled: bool,
    pub log_type: LoggingType,
    pub database: Option<DatabaseConfig>,
    pub file: Option<FileConfig>,
    pub retention_days: Option<u32>,
}

/// Logging output types
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
pub enum LoggingType {
    File,
    Database,
    Both,
}

/// Database logging configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: Option<u32>,
    pub connection_timeout: Option<u64>,
}

/// File logging configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileConfig {
    pub directory: String,
    pub rotation: bool,
    pub max_file_size: Option<u64>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_type: LoggingType::File,
            database: None,
            file: Some(FileConfig {
                directory: "logs".to_string(),
                rotation: true,
                max_file_size: Some(1_000_000), // 1MB
            }),
            retention_days: Some(30),
        }
    }
}

impl LoggingConfig {
    /// Validate logging configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate output configuration
        match self.log_type {
            LoggingType::File => {
                if self.file.is_none() {
                    return Err(anyhow::anyhow!(
                        "File configuration required when log_type is 'File'"
                    ));
                }
            }
            LoggingType::Database => {
                if self.database.is_none() {
                    return Err(anyhow::anyhow!(
                        "Database configuration required when log_type is 'Database'"
                    ));
                }
            }
            LoggingType::Both => {
                if self.file.is_none() || self.database.is_none() {
                    return Err(anyhow::anyhow!(
                        "Both file and database configurations required when log_type is 'Both'"
                    ));
                }
            }
        }

        // Validate file config if present
        if let Some(file_config) = &self.file {
            file_config.validate()?;
        }

        // Validate database config if present
        if let Some(db_config) = &self.database {
            db_config.validate()?;
        }

        Ok(())
    }
}

impl FileConfig {
    /// Validate file logging configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.directory.is_empty() {
            return Err(anyhow::anyhow!("File directory cannot be empty"));
        }

        Ok(())
    }
}

impl DatabaseConfig {
    /// Validate database logging configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.url.is_empty() {
            return Err(anyhow::anyhow!("Database URL cannot be empty"));
        }

        Ok(())
    }
}
