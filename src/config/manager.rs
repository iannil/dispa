#![allow(dead_code)]
use anyhow::Result;
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::Config;

/// Configuration manager with hot-reload support
pub struct ConfigManager {
    config: Arc<RwLock<Config>>,
    config_path: PathBuf,
    _watcher: Option<RecommendedWatcher>,
    #[allow(clippy::type_complexity)]
    reload_hook: Option<Arc<dyn Fn(&Config) + Send + Sync>>, // optional callback on reload
}

impl ConfigManager {
    /// Create a new configuration manager
    pub async fn new<P: AsRef<Path>>(config_path: P) -> Result<Self> {
        let config_path = config_path.as_ref().to_path_buf();
        let config = Config::from_file_with_env(&config_path).await?;

        Ok(ConfigManager {
            config: Arc::new(RwLock::new(config)),
            config_path,
            _watcher: None,
            reload_hook: None,
        })
    }

    /// Get a clone of the current configuration
    pub fn get_config(&self) -> Config {
        self.config.read().unwrap().clone()
    }

    /// Get a reference to the shared configuration
    pub fn get_config_ref(&self) -> Arc<RwLock<Config>> {
        Arc::clone(&self.config)
    }

    /// Set a callback to be invoked after config reload succeeds
    pub fn set_reload_hook<F>(&mut self, hook: F)
    where
        F: Fn(&Config) + Send + Sync + 'static,
    {
        self.reload_hook = Some(Arc::new(hook));
    }

    /// Start watching for configuration file changes
    pub async fn start_hot_reload(&mut self) -> Result<()> {
        let (tx, mut rx) = mpsc::channel(100);
        let config_arc = Arc::clone(&self.config);
        let config_path = self.config_path.clone();
        let reload_hook = self.reload_hook.clone();

        // Create file watcher
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| match res {
                Ok(event) => {
                    if let Err(e) = tx.blocking_send(event) {
                        error!("Failed to send file change event: {}", e);
                    }
                }
                Err(e) => error!("File watch error: {}", e),
            },
            NotifyConfig::default().with_poll_interval(Duration::from_secs(1)),
        )?;

        // Watch the config file and its directory
        watcher.watch(&config_path, RecursiveMode::NonRecursive)?;
        if let Some(parent) = config_path.parent() {
            watcher.watch(parent, RecursiveMode::NonRecursive)?;
        }

        info!("Started watching config file: {:?}", config_path);

        // Spawn task to handle file change events
        let config_path_clone = config_path.clone();
        let reload_hook_clone = reload_hook.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Err(e) = handle_config_change(
                    &event,
                    &config_arc,
                    &config_path_clone,
                    reload_hook_clone.clone(),
                )
                .await
                {
                    error!("Failed to handle config change: {}", e);
                }
            }
        });

        self._watcher = Some(watcher);
        Ok(())
    }

    /// Manually reload configuration from file
    pub async fn reload_config(&self) -> Result<()> {
        info!(
            "Manually reloading configuration from {:?}",
            self.config_path
        );

        match Config::from_file_with_env(&self.config_path).await {
            Ok(new_config) => {
                let mut config = self.config.write().unwrap();
                *config = new_config;
                info!("Configuration reloaded successfully");
                Ok(())
            }
            Err(e) => {
                error!("Failed to reload configuration: {}", e);
                Err(e)
            }
        }
    }
}

/// Handle configuration file change events
#[allow(clippy::type_complexity)]
async fn handle_config_change(
    event: &Event,
    config: &Arc<RwLock<Config>>,
    config_path: &Path,
    reload_hook: Option<Arc<dyn Fn(&Config) + Send + Sync>>,
) -> Result<()> {
    use notify::EventKind;

    // Only handle write/modify events for the config file
    if !matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
        return Ok(());
    }

    // Check if the event is for our config file
    let config_file_changed = event
        .paths
        .iter()
        .any(|path| path == config_path || (path.is_dir() && config_path.starts_with(path)));

    if !config_file_changed {
        return Ok(());
    }

    debug!("Config file change detected: {:?}", event);

    // Add a small delay to allow file write to complete
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Try to reload the configuration
    match Config::from_file_with_env(config_path).await {
        Ok(new_config) => {
            let mut current_config = config.write().unwrap();
            *current_config = new_config;
            info!("Configuration hot-reloaded successfully");

            // Invoke reload hook if present (best-effort)
            if let Some(hook) = reload_hook {
                let cfg_snapshot = current_config.clone();
                drop(current_config); // release lock before running hook
                (hook)(&cfg_snapshot);
            }
        }
        Err(e) => {
            warn!(
                "Failed to hot-reload configuration (keeping current): {}",
                e
            );
        }
    }

    Ok(())
}
