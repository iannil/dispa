#![allow(dead_code)]
use crate::error::DispaResult;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio::time::{sleep, timeout, Instant};
use tracing::{debug, error, info, warn};

/// Graceful shutdown manager
#[derive(Debug)]
pub struct ShutdownManager {
    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<ShutdownSignal>,
    /// Active tasks counter
    active_tasks: Arc<AtomicUsize>,
    /// Resources that need cleanup
    resources: Arc<Mutex<Vec<Box<dyn ResourceCleanup + Send + Sync>>>>,
    /// Shutdown timeout
    timeout: Duration,
    /// Whether shutdown has been initiated
    shutdown_initiated: Arc<AtomicBool>,
    /// Shutdown hooks
    hooks: Arc<RwLock<Vec<ShutdownHook>>>,
}

/// Shutdown signal types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownSignal {
    /// Graceful shutdown requested (SIGTERM)
    Graceful,
    /// Immediate shutdown requested (SIGINT)
    Immediate,
    /// Force shutdown (SIGKILL equivalent)
    #[allow(dead_code)]
    Force,
}

impl fmt::Display for ShutdownSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShutdownSignal::Graceful => write!(f, "GRACEFUL"),
            ShutdownSignal::Immediate => write!(f, "IMMEDIATE"),
            ShutdownSignal::Force => write!(f, "FORCE"),
        }
    }
}

/// Resource cleanup trait
pub trait ResourceCleanup: std::fmt::Debug {
    /// Cleanup the resource
    fn cleanup(&self) -> Pin<Box<dyn Future<Output = DispaResult<()>> + Send + '_>>;
    /// Get resource name for logging
    fn name(&self) -> &str;
}

/// Task handle for tracking active tasks
#[derive(Debug)]
pub struct TaskHandle {
    manager: Arc<ShutdownManager>,
    active: AtomicBool,
}

impl TaskHandle {
    /// Create a new task handle
    fn new(manager: Arc<ShutdownManager>) -> Self {
        manager.active_tasks.fetch_add(1, Ordering::SeqCst);
        Self {
            manager,
            active: AtomicBool::new(true),
        }
    }

    /// Check if shutdown has been requested
    #[allow(dead_code)]
    pub fn is_shutdown_requested(&self) -> bool {
        self.manager.shutdown_initiated.load(Ordering::Relaxed)
    }

    /// Get a shutdown signal receiver
    pub fn shutdown_receiver(&self) -> broadcast::Receiver<ShutdownSignal> {
        self.manager.shutdown_tx.subscribe()
    }
}

impl Drop for TaskHandle {
    fn drop(&mut self) {
        if self.active.swap(false, Ordering::SeqCst) {
            self.manager.active_tasks.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Shutdown hook function type
type ShutdownHookFn = Box<
    dyn Fn(ShutdownSignal) -> Pin<Box<dyn Future<Output = DispaResult<()>> + Send>> + Send + Sync,
>;

/// Shutdown hook registration
pub struct ShutdownHook {
    name: String,
    priority: u32,
    hook: ShutdownHookFn,
}

impl std::fmt::Debug for ShutdownHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownHook")
            .field("name", &self.name)
            .field("priority", &self.priority)
            .field("hook", &"<function>")
            .finish()
    }
}

impl ShutdownHook {
    /// Create a new shutdown hook
    pub fn new<F, Fut>(name: String, priority: u32, hook: F) -> Self
    where
        F: Fn(ShutdownSignal) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = DispaResult<()>> + Send + 'static,
    {
        Self {
            name,
            priority,
            hook: Box::new(move |signal| Box::pin(hook(signal))),
        }
    }
}

impl ShutdownManager {
    /// Create a new shutdown manager
    pub fn new(timeout: Duration) -> Self {
        let (shutdown_tx, _) = broadcast::channel(16);
        Self {
            shutdown_tx,
            active_tasks: Arc::new(AtomicUsize::new(0)),
            resources: Arc::new(Mutex::new(Vec::new())),
            timeout,
            shutdown_initiated: Arc::new(AtomicBool::new(false)),
            hooks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create with default timeout
    pub fn with_default_timeout() -> Self {
        Self::new(Duration::from_secs(30))
    }

    /// Register a resource for cleanup
    pub async fn register_resource<R>(&self, resource: R)
    where
        R: ResourceCleanup + Send + Sync + 'static,
    {
        let resource_name = resource.name().to_string();
        let mut resources = self.resources.lock().await;
        resources.push(Box::new(resource));
        debug!(resource = %resource_name, "Registered resource for cleanup");
    }

    /// Register a shutdown hook
    pub async fn register_hook(&self, hook: ShutdownHook) {
        let hook_name = hook.name.clone();
        let hook_priority = hook.priority;
        let mut hooks = self.hooks.write().await;
        hooks.push(hook);
        // Sort by priority (higher priority first)
        hooks.sort_by(|a, b| b.priority.cmp(&a.priority));
        debug!(hook = %hook_name, priority = hook_priority, "Registered shutdown hook");
    }

    /// Create a task handle for tracking
    pub fn create_task_handle(self: &Arc<Self>) -> TaskHandle {
        TaskHandle::new(Arc::clone(self))
    }

    /// Start listening for shutdown signals
    #[allow(dead_code)]
    pub async fn listen_for_signals(self: Arc<Self>) -> DispaResult<()> {
        let manager = Arc::clone(&self);

        tokio::spawn(async move {
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to register SIGTERM handler");
            let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
                .expect("Failed to register SIGINT handler");

            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating graceful shutdown");
                    if let Err(e) = manager.shutdown(ShutdownSignal::Graceful).await {
                        error!(error = %e, "Error during graceful shutdown");
                    }
                },
                _ = sigint.recv() => {
                    info!("Received SIGINT, initiating immediate shutdown");
                    if let Err(e) = manager.shutdown(ShutdownSignal::Immediate).await {
                        error!(error = %e, "Error during immediate shutdown");
                    }
                },
            }
        });

        Ok(())
    }

    /// Initiate shutdown
    pub async fn shutdown(&self, signal: ShutdownSignal) -> DispaResult<()> {
        if self.shutdown_initiated.swap(true, Ordering::SeqCst) {
            warn!("Shutdown already initiated");
            return Ok(());
        }

        info!(signal = %signal, "Initiating shutdown");

        // Send shutdown signal to all listeners
        if let Err(e) = self.shutdown_tx.send(signal) {
            warn!(error = %e, "Failed to send shutdown signal");
        }

        // Execute shutdown with timeout
        let shutdown_timeout = match signal {
            ShutdownSignal::Graceful => self.timeout,
            ShutdownSignal::Immediate => self.timeout / 2,
            ShutdownSignal::Force => Duration::from_secs(5),
        };

        match timeout(shutdown_timeout, self.execute_shutdown(signal)).await {
            Ok(result) => result,
            Err(_) => {
                error!(timeout = ?shutdown_timeout, "Shutdown timed out, forcing exit");
                std::process::exit(1);
            }
        }
    }

    /// Execute the shutdown process
    async fn execute_shutdown(&self, signal: ShutdownSignal) -> DispaResult<()> {
        let start_time = Instant::now();

        // Step 1: Execute shutdown hooks
        if let Err(e) = self.execute_hooks(signal).await {
            error!(error = %e, "Error executing shutdown hooks");
        }

        // Step 2: Wait for active tasks to complete (only for graceful shutdown)
        if matches!(signal, ShutdownSignal::Graceful) {
            self.wait_for_active_tasks().await;
        }

        // Step 3: Cleanup resources
        if let Err(e) = self.cleanup_resources().await {
            error!(error = %e, "Error during resource cleanup");
        }

        let elapsed = start_time.elapsed();
        info!(
            signal = %signal,
            duration = ?elapsed,
            "Shutdown completed"
        );

        Ok(())
    }

    /// Execute shutdown hooks
    async fn execute_hooks(&self, signal: ShutdownSignal) -> DispaResult<()> {
        let hooks = self.hooks.read().await;

        for hook in hooks.iter() {
            debug!(hook = %hook.name, priority = hook.priority, "Executing shutdown hook");

            if let Err(e) = (hook.hook)(signal).await {
                error!(
                    hook = %hook.name,
                    error = %e,
                    "Shutdown hook failed"
                );
            } else {
                debug!(hook = %hook.name, "Shutdown hook completed successfully");
            }
        }

        Ok(())
    }

    /// Wait for active tasks to complete
    async fn wait_for_active_tasks(&self) {
        let max_wait = self.timeout / 2;
        let check_interval = Duration::from_millis(100);
        let start_time = Instant::now();

        while self.active_tasks.load(Ordering::SeqCst) > 0 {
            let elapsed = start_time.elapsed();
            if elapsed >= max_wait {
                let remaining_tasks = self.active_tasks.load(Ordering::SeqCst);
                warn!(
                    remaining_tasks = remaining_tasks,
                    elapsed = ?elapsed,
                    "Timeout waiting for tasks to complete, proceeding with shutdown"
                );
                break;
            }

            let remaining_tasks = self.active_tasks.load(Ordering::SeqCst);
            debug!(
                remaining_tasks = remaining_tasks,
                elapsed = ?elapsed,
                "Waiting for active tasks to complete"
            );

            sleep(check_interval).await;
        }

        info!("All active tasks completed");
    }

    /// Cleanup all registered resources
    async fn cleanup_resources(&self) -> DispaResult<()> {
        let mut resources = self.resources.lock().await;

        for resource in resources.iter() {
            debug!(resource = resource.name(), "Cleaning up resource");

            if let Err(e) = resource.cleanup().await {
                error!(
                    resource = resource.name(),
                    error = %e,
                    "Failed to cleanup resource"
                );
            } else {
                debug!(
                    resource = resource.name(),
                    "Resource cleaned up successfully"
                );
            }
        }

        resources.clear();
        info!("All resources cleaned up");
        Ok(())
    }

    /// Get current number of active tasks
    pub fn active_task_count(&self) -> usize {
        self.active_tasks.load(Ordering::SeqCst)
    }

    /// Check if shutdown has been initiated
    pub fn is_shutdown_initiated(&self) -> bool {
        self.shutdown_initiated.load(Ordering::Relaxed)
    }
}

/// Example resource cleanup implementations
#[derive(Debug)]
pub struct DatabaseConnection {
    name: String,
    // Simulate database connection
}

impl DatabaseConnection {
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

impl ResourceCleanup for DatabaseConnection {
    fn cleanup(&self) -> Pin<Box<dyn Future<Output = DispaResult<()>> + Send + '_>> {
        Box::pin(async {
            debug!(connection = %self.name, "Closing database connection");
            // Simulate cleanup time
            sleep(Duration::from_millis(100)).await;
            info!(connection = %self.name, "Database connection closed");
            Ok(())
        })
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug)]
pub struct FileHandle {
    name: String,
    // Simulate file handle
}

impl FileHandle {
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

impl ResourceCleanup for FileHandle {
    fn cleanup(&self) -> Pin<Box<dyn Future<Output = DispaResult<()>> + Send + '_>> {
        Box::pin(async {
            debug!(file = %self.name, "Closing file handle");
            // Simulate cleanup time
            sleep(Duration::from_millis(50)).await;
            info!(file = %self.name, "File handle closed");
            Ok(())
        })
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_shutdown_manager_creation() {
        let manager = ShutdownManager::with_default_timeout();
        assert_eq!(manager.active_task_count(), 0);
        assert!(!manager.is_shutdown_initiated());
    }

    #[tokio::test]
    async fn test_task_handle_tracking() {
        let manager = Arc::new(ShutdownManager::with_default_timeout());
        assert_eq!(manager.active_task_count(), 0);

        {
            let _handle1 = manager.create_task_handle();
            assert_eq!(manager.active_task_count(), 1);

            {
                let _handle2 = manager.create_task_handle();
                assert_eq!(manager.active_task_count(), 2);
            } // handle2 dropped

            assert_eq!(manager.active_task_count(), 1);
        } // handle1 dropped

        assert_eq!(manager.active_task_count(), 0);
    }

    #[tokio::test]
    async fn test_resource_registration() {
        let manager = ShutdownManager::with_default_timeout();

        let db_conn = DatabaseConnection::new("test_db".to_string());
        manager.register_resource(db_conn).await;

        let file_handle = FileHandle::new("test_file.log".to_string());
        manager.register_resource(file_handle).await;

        // Resources are registered but we can't easily test cleanup without shutdown
        assert!(!manager.is_shutdown_initiated());
    }

    #[tokio::test]
    async fn test_shutdown_hooks() {
        let manager = Arc::new(ShutdownManager::with_default_timeout());

        let hook1 = ShutdownHook::new("test_hook_1".to_string(), 100, |signal| async move {
            debug!("Hook 1 executed with signal: {}", signal);
            Ok(())
        });

        let hook2 = ShutdownHook::new("test_hook_2".to_string(), 200, |signal| async move {
            debug!("Hook 2 executed with signal: {}", signal);
            Ok(())
        });

        manager.register_hook(hook1).await;
        manager.register_hook(hook2).await;

        // Hooks are registered but we can't easily test execution without full shutdown
        assert!(!manager.is_shutdown_initiated());
    }

    #[tokio::test]
    async fn test_graceful_shutdown() {
        let manager = Arc::new(ShutdownManager::new(Duration::from_secs(1)));

        // Add some resources
        let db_conn = DatabaseConnection::new("test_db".to_string());
        manager.register_resource(db_conn).await;

        // Create some task handles
        let _handle1 = manager.create_task_handle();
        let handle2 = manager.create_task_handle();

        assert_eq!(manager.active_task_count(), 2);

        // Start shutdown in background
        let manager_clone = Arc::clone(&manager);
        let shutdown_task =
            tokio::spawn(async move { manager_clone.shutdown(ShutdownSignal::Graceful).await });

        // Simulate task completion
        drop(handle2);

        // Wait for shutdown to complete
        let result = timeout(Duration::from_secs(2), shutdown_task).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
        assert!(manager.is_shutdown_initiated());
    }

    #[tokio::test]
    async fn test_immediate_shutdown() {
        let manager = Arc::new(ShutdownManager::new(Duration::from_secs(1)));

        let result = manager.shutdown(ShutdownSignal::Immediate).await;
        assert!(result.is_ok());
        assert!(manager.is_shutdown_initiated());
    }

    #[tokio::test]
    async fn test_shutdown_signal_broadcast() {
        let manager = Arc::new(ShutdownManager::with_default_timeout());
        let handle = manager.create_task_handle();

        let mut receiver = handle.shutdown_receiver();

        // Spawn shutdown in background
        let manager_clone = Arc::clone(&manager);
        tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            let _ = manager_clone.shutdown(ShutdownSignal::Graceful).await;
        });

        // Wait for shutdown signal
        let signal = timeout(Duration::from_secs(1), receiver.recv()).await;
        assert!(signal.is_ok());
        assert_eq!(signal.unwrap().unwrap(), ShutdownSignal::Graceful);
    }

    #[tokio::test]
    async fn test_resource_cleanup() {
        let db_conn = DatabaseConnection::new("test_db".to_string());
        assert_eq!(db_conn.name(), "test_db");

        let result = db_conn.cleanup().await;
        assert!(result.is_ok());

        let file_handle = FileHandle::new("test_file.log".to_string());
        assert_eq!(file_handle.name(), "test_file.log");

        let result = file_handle.cleanup().await;
        assert!(result.is_ok());
    }
}
