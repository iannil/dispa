#![allow(dead_code)]
use crate::error::{DispaError, DispaResult};
use std::fmt;
use std::future::Future;
use std::time::Duration;
use tokio::time::{sleep, timeout, Instant};
use tracing::{debug, error, info, warn};

/// Retry strategy configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Base delay between retries
    pub base_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Backoff strategy
    pub backoff: BackoffStrategy,
    /// Jitter to add to delays
    pub jitter: bool,
    /// Timeout for each attempt
    pub attempt_timeout: Option<Duration>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff: BackoffStrategy::Exponential { multiplier: 2.0 },
            jitter: true,
            attempt_timeout: None,
        }
    }
}

/// Backoff strategies for retry delays
#[derive(Debug, Clone, Copy)]
pub enum BackoffStrategy {
    /// Fixed delay between retries
    Fixed,
    /// Linear backoff: delay = base_delay * attempt
    Linear,
    /// Exponential backoff: delay = base_delay * multiplier^(attempt-1)
    Exponential { multiplier: f64 },
}

/// Result of a retry attempt
#[derive(Debug, Clone)]
pub enum RetryResult<T> {
    /// Operation succeeded
    Success(T),
    /// Operation failed but should be retried
    Retry(DispaError),
    /// Operation failed and should not be retried
    Abort(DispaError),
}

/// Retry context information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RetryContext {
    /// Current attempt number (1-based)
    pub attempt: u32,
    /// Total elapsed time
    pub elapsed: Duration,
    /// Last error that occurred
    pub last_error: Option<DispaError>,
    /// Delay until next attempt
    pub next_delay: Duration,
}

/// Retry execution with configurable strategy
pub struct RetryExecutor {
    config: RetryConfig,
}

impl RetryExecutor {
    /// Create a new retry executor with the given configuration
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    /// Create a retry executor with default configuration
    pub fn with_defaults() -> Self {
        Self::new(RetryConfig::default())
    }

    /// Execute a function with retry logic
    pub async fn execute<F, Fut, T>(&self, operation: F) -> DispaResult<T>
    where
        F: Fn(RetryContext) -> Fut,
        Fut: Future<Output = RetryResult<T>>,
    {
        let start_time = Instant::now();
        let mut last_error = None;

        for attempt in 1..=self.config.max_attempts {
            let elapsed = start_time.elapsed();
            let next_delay = self.calculate_delay(attempt);

            let context = RetryContext {
                attempt,
                elapsed,
                last_error: last_error.clone(),
                next_delay,
            };

            debug!(
                attempt = attempt,
                max_attempts = self.config.max_attempts,
                elapsed = ?elapsed,
                next_delay = ?next_delay,
                "Executing retry attempt"
            );

            // Execute operation with optional timeout
            let result = if let Some(attempt_timeout) = self.config.attempt_timeout {
                match timeout(attempt_timeout, operation(context)).await {
                    Ok(result) => result,
                    Err(_) => {
                        let timeout_error = DispaError::timeout(attempt_timeout, "retry attempt");
                        RetryResult::Retry(timeout_error)
                    }
                }
            } else {
                operation(context).await
            };

            match result {
                RetryResult::Success(value) => {
                    if attempt > 1 {
                        info!(
                            attempt = attempt,
                            elapsed = ?elapsed,
                            "Operation succeeded after retry"
                        );
                    }
                    return Ok(value);
                }
                RetryResult::Abort(error) => {
                    warn!(
                        attempt = attempt,
                        error = %error,
                        "Operation failed with non-retryable error"
                    );
                    return Err(error);
                }
                RetryResult::Retry(error) => {
                    last_error = Some(error.clone());

                    if attempt == self.config.max_attempts {
                        error!(
                            attempt = attempt,
                            max_attempts = self.config.max_attempts,
                            error = %error,
                            elapsed = ?elapsed,
                            "Operation failed after maximum retry attempts"
                        );
                        return Err(error);
                    }

                    warn!(
                        attempt = attempt,
                        error = %error,
                        next_delay = ?next_delay,
                        "Operation failed, will retry"
                    );

                    // Wait before next attempt (but not after the last attempt)
                    if attempt < self.config.max_attempts && next_delay > Duration::ZERO {
                        sleep(next_delay).await;
                    }
                }
            }
        }

        // This should never be reached due to the logic above
        unreachable!("Retry loop should have returned or errored")
    }

    /// Calculate delay for the given attempt
    fn calculate_delay(&self, attempt: u32) -> Duration {
        let base_delay_millis = self.config.base_delay.as_millis() as f64;

        let delay_millis = match self.config.backoff {
            BackoffStrategy::Fixed => base_delay_millis,
            BackoffStrategy::Linear => base_delay_millis * attempt as f64,
            BackoffStrategy::Exponential { multiplier } => {
                base_delay_millis * multiplier.powi((attempt - 1) as i32)
            }
        };

        let mut delay = Duration::from_millis(
            delay_millis.min(self.config.max_delay.as_millis() as f64) as u64,
        );

        // Add jitter if enabled
        if self.config.jitter {
            delay = add_jitter(delay);
        }

        delay.min(self.config.max_delay)
    }
}

/// Add random jitter to a duration (±25%)
fn add_jitter(duration: Duration) -> Duration {
    use rand::Rng;

    let millis = duration.as_millis() as f64;
    let jitter_range = millis * 0.25; // ±25%
    let mut rng = rand::thread_rng();
    let jitter: f64 = rng.gen_range(-jitter_range..=jitter_range);
    let new_millis = (millis + jitter).max(0.0) as u64;

    Duration::from_millis(new_millis)
}

/// Error recovery strategies
pub struct ErrorRecovery;

impl ErrorRecovery {
    /// Create a retry result based on error characteristics
    pub fn classify_error<T>(error: DispaError) -> RetryResult<T> {
        if error.is_retryable() {
            RetryResult::Retry(error)
        } else {
            RetryResult::Abort(error)
        }
    }

    /// Execute operation with default retry logic
    pub async fn with_retry<F, Fut, T>(operation: F) -> DispaResult<T>
    where
        F: Fn(RetryContext) -> Fut,
        Fut: Future<Output = DispaResult<T>>,
    {
        let executor = RetryExecutor::with_defaults();
        executor
            .execute(|ctx| async {
                match operation(ctx).await {
                    Ok(value) => RetryResult::Success(value),
                    Err(error) => Self::classify_error(error),
                }
            })
            .await
    }

    /// Execute operation with custom retry configuration
    #[allow(dead_code)]
    pub async fn with_custom_retry<F, Fut, T>(config: RetryConfig, operation: F) -> DispaResult<T>
    where
        F: Fn(RetryContext) -> Fut,
        Fut: Future<Output = DispaResult<T>>,
    {
        let executor = RetryExecutor::new(config);
        executor
            .execute(|ctx| async {
                match operation(ctx).await {
                    Ok(value) => RetryResult::Success(value),
                    Err(error) => Self::classify_error(error),
                }
            })
            .await
    }

    /// Execute operation with circuit breaker and retry
    #[allow(dead_code)]
    pub async fn with_circuit_breaker_and_retry<F, Fut, T>(
        circuit_breaker: &crate::circuit_breaker::CircuitBreaker,
        retry_config: RetryConfig,
        operation: F,
    ) -> DispaResult<T>
    where
        F: Fn(RetryContext) -> Fut + Clone,
        Fut: Future<Output = DispaResult<T>>,
    {
        let executor = RetryExecutor::new(retry_config);

        circuit_breaker
            .call(|| async {
                executor
                    .execute(|ctx| {
                        let op = operation.clone();
                        async move {
                            match op(ctx).await {
                                Ok(value) => RetryResult::Success(value),
                                Err(error) => Self::classify_error(error),
                            }
                        }
                    })
                    .await
            })
            .await
    }
}

/// Exponential backoff with jitter implementation
pub struct ExponentialBackoff {
    config: RetryConfig,
    current_attempt: u32,
    start_time: Instant,
}

impl ExponentialBackoff {
    /// Create a new exponential backoff instance
    pub fn new(config: RetryConfig) -> Self {
        Self {
            config,
            current_attempt: 0,
            start_time: Instant::now(),
        }
    }

    /// Create with default configuration
    #[allow(dead_code)]
    pub fn with_defaults() -> Self {
        Self::new(RetryConfig::default())
    }

    /// Reset the backoff to initial state
    pub fn reset(&mut self) {
        self.current_attempt = 0;
        self.start_time = Instant::now();
    }

    /// Get the next delay duration
    pub fn next_delay(&mut self) -> Option<Duration> {
        self.current_attempt += 1;

        if self.current_attempt > self.config.max_attempts {
            return None;
        }

        let executor = RetryExecutor::new(self.config.clone());
        Some(executor.calculate_delay(self.current_attempt))
    }

    /// Get current attempt number
    pub fn current_attempt(&self) -> u32 {
        self.current_attempt
    }

    /// Get elapsed time since start
    #[allow(dead_code)]
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
}

impl fmt::Display for BackoffStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackoffStrategy::Fixed => write!(f, "FIXED"),
            BackoffStrategy::Linear => write!(f, "LINEAR"),
            BackoffStrategy::Exponential { multiplier } => {
                write!(f, "EXPONENTIAL({})", multiplier)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_retry_success_on_first_attempt() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let executor = RetryExecutor::with_defaults();
            let counter = Arc::new(AtomicUsize::new(0));
            let result = executor
                .execute(|_ctx| {
                    let counter = Arc::clone(&counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        RetryResult::Success(42)
                    }
                })
                .await;
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), 42);
            assert_eq!(counter.load(Ordering::SeqCst), 1);
        })
        .await
        .expect("test_retry_success_on_first_attempt timed out");
    }

    #[tokio::test]
    async fn test_retry_success_after_failures() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let config = RetryConfig {
                max_attempts: 3,
                base_delay: Duration::from_millis(1), // Fast test
                ..Default::default()
            };

            let executor = RetryExecutor::new(config);
            let counter = Arc::new(AtomicUsize::new(0));

            let result = executor
                .execute(|_ctx| {
                    let counter = Arc::clone(&counter);
                    async move {
                        let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
                        if count < 3 {
                            RetryResult::Retry(DispaError::network("temporary failure"))
                        } else {
                            RetryResult::Success(42)
                        }
                    }
                })
                .await;

            assert!(result.is_ok());
            assert_eq!(result.unwrap(), 42);
            assert_eq!(counter.load(Ordering::SeqCst), 3);
        })
        .await
        .expect("test_retry_success_after_failures timed out");
    }

    #[tokio::test]
    async fn test_retry_max_attempts_exceeded() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let config = RetryConfig {
                max_attempts: 2,
                base_delay: Duration::from_millis(1), // Fast test
                ..Default::default()
            };

            let executor = RetryExecutor::new(config);
            let counter = Arc::new(AtomicUsize::new(0));

            let result = executor
                .execute(|_ctx| {
                    let counter = Arc::clone(&counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        RetryResult::<i32>::Retry(DispaError::network("always failing"))
                    }
                })
                .await;

            assert!(result.is_err());
            assert_eq!(counter.load(Ordering::SeqCst), 2);
        })
        .await
        .expect("test_retry_max_attempts_exceeded timed out");
    }

    #[tokio::test]
    async fn test_retry_abort_on_non_retryable_error() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let executor = RetryExecutor::with_defaults();
            let counter = Arc::new(AtomicUsize::new(0));
            let result = executor
                .execute(|_ctx| {
                    let counter = Arc::clone(&counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        RetryResult::<i32>::Abort(DispaError::config("invalid configuration"))
                    }
                })
                .await;
            assert!(result.is_err());
            assert_eq!(counter.load(Ordering::SeqCst), 1);
        })
        .await
        .expect("test_retry_abort_on_non_retryable_error timed out");
    }

    #[tokio::test]
    async fn test_exponential_backoff() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let config = RetryConfig {
                base_delay: Duration::from_millis(100),
                backoff: BackoffStrategy::Exponential { multiplier: 2.0 },
                jitter: false, // Disable jitter for predictable testing
                ..Default::default()
            };

            let executor = RetryExecutor::new(config);

            // Test delay calculation
            assert_eq!(executor.calculate_delay(1), Duration::from_millis(100));
            assert_eq!(executor.calculate_delay(2), Duration::from_millis(200));
            assert_eq!(executor.calculate_delay(3), Duration::from_millis(400));
        })
        .await
        .expect("test_exponential_backoff timed out");
    }

    #[tokio::test]
    async fn test_linear_backoff() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let config = RetryConfig {
                base_delay: Duration::from_millis(100),
                backoff: BackoffStrategy::Linear,
                jitter: false, // Disable jitter for predictable testing
                ..Default::default()
            };

            let executor = RetryExecutor::new(config);

            // Test delay calculation
            assert_eq!(executor.calculate_delay(1), Duration::from_millis(100));
            assert_eq!(executor.calculate_delay(2), Duration::from_millis(200));
            assert_eq!(executor.calculate_delay(3), Duration::from_millis(300));
        })
        .await
        .expect("test_linear_backoff timed out");
    }

    #[tokio::test]
    async fn test_fixed_backoff() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let config = RetryConfig {
                base_delay: Duration::from_millis(100),
                backoff: BackoffStrategy::Fixed,
                jitter: false, // Disable jitter for predictable testing
                ..Default::default()
            };

            let executor = RetryExecutor::new(config);

            // Test delay calculation
            assert_eq!(executor.calculate_delay(1), Duration::from_millis(100));
            assert_eq!(executor.calculate_delay(2), Duration::from_millis(100));
            assert_eq!(executor.calculate_delay(3), Duration::from_millis(100));
        })
        .await
        .expect("test_fixed_backoff timed out");
    }

    #[tokio::test]
    async fn test_error_recovery_with_retry() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let counter = Arc::new(AtomicUsize::new(0));
            let result = ErrorRecovery::with_retry(|_ctx| {
                let counter = Arc::clone(&counter);
                async move {
                    let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    if count < 2 {
                        Err(DispaError::network("temporary failure"))
                    } else {
                        Ok(42)
                    }
                }
            })
            .await;
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), 42);
            assert_eq!(counter.load(Ordering::SeqCst), 2);
        })
        .await
        .expect("test_error_recovery_with_retry timed out");
    }

    #[tokio::test]
    async fn test_exponential_backoff_helper() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let config = RetryConfig {
                max_attempts: 3,
                base_delay: Duration::from_millis(100),
                ..Default::default()
            };

            let mut backoff = ExponentialBackoff::new(config);

            assert_eq!(backoff.current_attempt(), 0);

            let delay1 = backoff.next_delay();
            assert!(delay1.is_some());
            assert_eq!(backoff.current_attempt(), 1);

            let delay2 = backoff.next_delay();
            assert!(delay2.is_some());
            assert_eq!(backoff.current_attempt(), 2);

            let delay3 = backoff.next_delay();
            assert!(delay3.is_some());
            assert_eq!(backoff.current_attempt(), 3);

            let delay4 = backoff.next_delay();
            assert!(delay4.is_none());
            assert_eq!(backoff.current_attempt(), 4);

            // Test reset
            backoff.reset();
            assert_eq!(backoff.current_attempt(), 0);
        })
        .await
        .expect("test_exponential_backoff_helper timed out");
    }

    #[tokio::test]
    async fn test_retry_context() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let executor = RetryExecutor::with_defaults();
            let contexts = Arc::new(std::sync::Mutex::new(Vec::new()));
            let _ = executor
                .execute(|ctx| {
                    let contexts = Arc::clone(&contexts);
                    async move {
                        contexts.lock().unwrap().push(ctx);
                        RetryResult::<i32>::Retry(DispaError::network("test error"))
                    }
                })
                .await;
            let contexts = contexts.lock().unwrap();
            assert!(!contexts.is_empty());
            for (i, ctx) in contexts.iter().enumerate() {
                assert_eq!(ctx.attempt, (i + 1) as u32);
            }
        })
        .await
        .expect("test_retry_context timed out");
    }
}
