use crate::error::{DispaError, DispaResult};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    /// Circuit is closed, requests flow normally
    Closed,
    /// Circuit is open, requests are blocked
    Open,
    /// Circuit is half-open, testing if service has recovered
    HalfOpen,
}

impl std::fmt::Display for CircuitBreakerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitBreakerState::Closed => write!(f, "CLOSED"),
            CircuitBreakerState::Open => write!(f, "OPEN"),
            CircuitBreakerState::HalfOpen => write!(f, "HALF_OPEN"),
        }
    }
}

/// Configuration for circuit breaker
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Failure threshold to open the circuit
    pub failure_threshold: u64,
    /// Success threshold to close the circuit from half-open
    pub success_threshold: u64,
    /// Timeout before attempting recovery (half-open)
    pub timeout: Duration,
    /// Time window for counting failures
    pub time_window: Duration,
    /// Minimum number of requests in time window before considering failure rate
    pub min_requests: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(60),
            time_window: Duration::from_secs(60),
            min_requests: 10,
        }
    }
}

/// Circuit breaker implementation for fault tolerance
///
/// Provides automatic failure detection and recovery mechanisms to prevent
/// cascading failures in distributed systems. The circuit breaker monitors
/// request success/failure rates and can temporarily block requests when
/// a service appears to be failing.
///
/// # States
///
/// - **Closed**: Normal operation, all requests pass through
/// - **Open**: Service appears down, requests are blocked
/// - **Half-Open**: Testing if service has recovered
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use dispa::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
///
/// let config = CircuitBreakerConfig {
///     failure_threshold: 5,
///     success_threshold: 3,
///     timeout: Duration::from_secs(60),
///     time_window: Duration::from_secs(60),
///     min_requests: 10,
/// };
///
/// let cb = CircuitBreaker::new("my-service".to_string(), config);
///
/// // Use the circuit breaker to protect a call
/// let result = cb.call(|| async {
///     // Your service call here
///     Ok("success")
/// }).await;
/// ```
#[derive(Debug)]
pub struct CircuitBreaker {
    name: String,
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitBreakerState>>,
    failure_count: AtomicU64,
    success_count: AtomicU64,
    last_failure_time: AtomicI64,
    last_success_time: AtomicI64,
    request_count: AtomicU64,
    window_start: AtomicI64,
}

#[allow(dead_code)]
impl CircuitBreaker {
    /// Create a new circuit breaker with custom configuration
    ///
    /// # Parameters
    ///
    /// * `name` - Unique identifier for this circuit breaker (used in logs)
    /// * `config` - Configuration specifying thresholds and timeouts
    ///
    /// # Examples
    ///
    /// ```
    /// let config = CircuitBreakerConfig {
    ///     failure_threshold: 10,
    ///     success_threshold: 5,
    ///     timeout: Duration::from_secs(30),
    ///     time_window: Duration::from_secs(60),
    ///     min_requests: 5,
    /// };
    /// let cb = CircuitBreaker::new("api-service".to_string(), config);
    /// ```
    pub fn new(name: String, config: CircuitBreakerConfig) -> Self {
        let now = now_timestamp();
        Self {
            name,
            config,
            state: Arc::new(RwLock::new(CircuitBreakerState::Closed)),
            failure_count: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            last_failure_time: AtomicI64::new(now),
            last_success_time: AtomicI64::new(now),
            request_count: AtomicU64::new(0),
            window_start: AtomicI64::new(now),
        }
    }

    /// Create a circuit breaker with default configuration
    ///
    /// Uses reasonable defaults for most use cases:
    /// - Failure threshold: 5 failures
    /// - Success threshold: 3 successes to recover
    /// - Timeout: 60 seconds before retry
    /// - Time window: 60 seconds for failure counting
    /// - Minimum requests: 10 before considering failure rate
    ///
    /// # Parameters
    ///
    /// * `name` - Unique identifier for this circuit breaker
    pub fn with_defaults(name: String) -> Self {
        Self::new(name, CircuitBreakerConfig::default())
    }

    /// Execute a function with circuit breaker protection
    ///
    /// This is the main method for using the circuit breaker. It will:
    /// 1. Check if the circuit allows the request (based on current state)
    /// 2. Execute the provided function if allowed
    /// 3. Record the result (success/failure) for future decisions
    /// 4. Update the circuit breaker state based on the outcome
    ///
    /// # Parameters
    ///
    /// * `f` - A closure that returns a Future yielding a `DispaResult<T>`
    ///
    /// # Returns
    ///
    /// * `Ok(T)` - The function executed successfully
    /// * `Err(DispaError::CircuitBreakerOpen)` - Circuit is open, request blocked
    /// * `Err(other)` - The function failed with an error
    ///
    /// # Examples
    ///
    /// ```
    /// use dispa::circuit_breaker::CircuitBreaker;
    ///
    /// let cb = CircuitBreaker::with_defaults("my-service".to_string());
    ///
    /// let result = cb.call(|| async {
    ///     // Your potentially failing operation
    ///     make_api_call().await
    /// }).await;
    ///
    /// match result {
    ///     Ok(value) => println!("Success: {:?}", value),
    ///     Err(e) => println!("Failed: {}", e),
    /// }
    /// ```
    pub async fn call<F, T, Fut>(&self, f: F) -> DispaResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = DispaResult<T>>,
    {
        // Check if circuit allows the request
        if !self.can_execute().await {
            return Err(DispaError::circuit_breaker_open(&self.name));
        }

        // Execute the function
        let result = f().await;

        // Record the result
        match &result {
            Ok(_) => self.record_success().await,
            Err(err) => {
                if err.should_trigger_circuit_breaker() {
                    self.record_failure().await;
                }
            }
        }

        result
    }

    /// Check if the circuit breaker allows execution
    pub async fn can_execute(&self) -> bool {
        let state = *self.state.read().await;

        match state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => {
                // Check if timeout has passed
                let now = now_timestamp();
                let last_failure = self.last_failure_time.load(Ordering::Relaxed);

                if now - last_failure >= self.config.timeout.as_secs() as i64 {
                    // Try to transition to half-open
                    self.try_half_open().await;
                    let new_state = *self.state.read().await;
                    new_state == CircuitBreakerState::HalfOpen
                } else {
                    false
                }
            }
            CircuitBreakerState::HalfOpen => true,
        }
    }

    /// Record a successful execution
    pub async fn record_success(&self) {
        let now = now_timestamp();
        self.last_success_time.store(now, Ordering::Relaxed);
        self.request_count.fetch_add(1, Ordering::Relaxed);

        let state = *self.state.read().await;

        match state {
            CircuitBreakerState::HalfOpen => {
                let success_count = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
                debug!(
                    circuit_breaker = %self.name,
                    state = %state,
                    success_count = success_count,
                    threshold = self.config.success_threshold,
                    "Circuit breaker recorded success"
                );

                if success_count >= self.config.success_threshold {
                    self.close_circuit().await;
                }
            }
            CircuitBreakerState::Closed => {
                // Reset failure count on success in closed state
                self.reset_window_if_needed().await;
            }
            CircuitBreakerState::Open => {
                // Shouldn't happen, but reset if it does
                self.reset_counters();
            }
        }
    }

    /// Record a failed execution
    pub async fn record_failure(&self) {
        let now = now_timestamp();
        self.last_failure_time.store(now, Ordering::Relaxed);
        self.request_count.fetch_add(1, Ordering::Relaxed);

        let state = *self.state.read().await;

        match state {
            CircuitBreakerState::Closed => {
                self.reset_window_if_needed().await;
                let failure_count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
                let request_count = self.request_count.load(Ordering::Relaxed);

                debug!(
                    circuit_breaker = %self.name,
                    state = %state,
                    failure_count = failure_count,
                    request_count = request_count,
                    threshold = self.config.failure_threshold,
                    min_requests = self.config.min_requests,
                    "Circuit breaker recorded failure"
                );

                if request_count >= self.config.min_requests
                    && failure_count >= self.config.failure_threshold
                {
                    self.open_circuit().await;
                }
            }
            CircuitBreakerState::HalfOpen => {
                // Go back to open state on any failure in half-open
                self.open_circuit().await;
            }
            CircuitBreakerState::Open => {
                // Already open, just update timestamp
            }
        }
    }

    /// Get current circuit breaker state
    pub async fn state(&self) -> CircuitBreakerState {
        *self.state.read().await
    }

    /// Get circuit breaker statistics
    pub async fn stats(&self) -> CircuitBreakerStats {
        let state = *self.state.read().await;
        CircuitBreakerStats {
            name: self.name.clone(),
            state,
            failure_count: self.failure_count.load(Ordering::Relaxed),
            success_count: self.success_count.load(Ordering::Relaxed),
            request_count: self.request_count.load(Ordering::Relaxed),
            last_failure_time: self.last_failure_time.load(Ordering::Relaxed),
            last_success_time: self.last_success_time.load(Ordering::Relaxed),
        }
    }

    /// Force the circuit breaker to open state
    pub async fn force_open(&self) {
        self.open_circuit().await;
    }

    /// Force the circuit breaker to closed state
    pub async fn force_close(&self) {
        self.close_circuit().await;
    }

    /// Reset circuit breaker to initial state
    pub async fn reset(&self) {
        {
            let mut state = self.state.write().await;
            *state = CircuitBreakerState::Closed;
        }
        self.reset_counters();
        info!(
            circuit_breaker = %self.name,
            "Circuit breaker reset to closed state"
        );
    }

    /// Try to transition from open to half-open
    async fn try_half_open(&self) {
        let mut state = self.state.write().await;
        if *state == CircuitBreakerState::Open {
            *state = CircuitBreakerState::HalfOpen;
            self.success_count.store(0, Ordering::Relaxed);
            info!(
                circuit_breaker = %self.name,
                "Circuit breaker transitioned to HALF_OPEN"
            );
        }
    }

    /// Transition to open state
    async fn open_circuit(&self) {
        {
            let mut state = self.state.write().await;
            *state = CircuitBreakerState::Open;
        }
        warn!(
            circuit_breaker = %self.name,
            failure_count = self.failure_count.load(Ordering::Relaxed),
            request_count = self.request_count.load(Ordering::Relaxed),
            "Circuit breaker opened due to failures"
        );
    }

    /// Transition to closed state
    async fn close_circuit(&self) {
        {
            let mut state = self.state.write().await;
            *state = CircuitBreakerState::Closed;
        }
        self.reset_counters();
        info!(
            circuit_breaker = %self.name,
            success_count = self.success_count.load(Ordering::Relaxed),
            "Circuit breaker closed after successful recovery"
        );
    }

    /// Reset counters if time window has passed
    async fn reset_window_if_needed(&self) {
        let now = now_timestamp();
        let window_start = self.window_start.load(Ordering::Relaxed);

        if now - window_start >= self.config.time_window.as_secs() as i64 {
            self.reset_counters();
            self.window_start.store(now, Ordering::Relaxed);
        }
    }

    /// Reset all counters
    fn reset_counters(&self) {
        self.failure_count.store(0, Ordering::Relaxed);
        self.success_count.store(0, Ordering::Relaxed);
        self.request_count.store(0, Ordering::Relaxed);
        self.window_start.store(now_timestamp(), Ordering::Relaxed);
    }
}

/// Circuit breaker statistics
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CircuitBreakerStats {
    pub name: String,
    pub state: CircuitBreakerState,
    pub failure_count: u64,
    pub success_count: u64,
    pub request_count: u64,
    pub last_failure_time: i64,
    pub last_success_time: i64,
}

/// Get current timestamp in seconds
fn now_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_circuit_breaker_closed_state() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let cb = CircuitBreaker::with_defaults("test".to_string());
            assert_eq!(cb.state().await, CircuitBreakerState::Closed);
            assert!(cb.can_execute().await);
        })
        .await
        .expect("test_circuit_breaker_closed_state timed out");
    }

    #[tokio::test]
    async fn test_circuit_breaker_success() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let cb = CircuitBreaker::with_defaults("test".to_string());
            let result = cb.call(|| async { Ok::<i32, DispaError>(42) }).await;
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), 42);
            let stats = cb.stats().await;
            assert_eq!(stats.success_count, 0);
            assert_eq!(stats.failure_count, 0);
        })
        .await
        .expect("test_circuit_breaker_success timed out");
    }

    #[tokio::test]
    async fn test_circuit_breaker_failure() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let config = CircuitBreakerConfig {
                failure_threshold: 2,
                min_requests: 2,
                ..Default::default()
            };

            let cb = CircuitBreaker::new("test".to_string(), config);

            // First failure
            let result = cb
                .call(|| async { Err::<i32, DispaError>(DispaError::network("connection failed")) })
                .await;
            assert!(result.is_err());
            assert_eq!(cb.state().await, CircuitBreakerState::Closed);

            // Second failure should open the circuit
            let result = cb
                .call(|| async { Err::<i32, DispaError>(DispaError::network("connection failed")) })
                .await;
            assert!(result.is_err());
            assert_eq!(cb.state().await, CircuitBreakerState::Open);

            // Third call should be blocked
            assert!(!cb.can_execute().await);
        })
        .await
        .expect("test_circuit_breaker_failure timed out");
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_transition() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let config = CircuitBreakerConfig {
                failure_threshold: 1,
                min_requests: 1,
                timeout: Duration::from_millis(100),
                ..Default::default()
            };

            let cb = CircuitBreaker::new("test".to_string(), config);

            // Trigger failure to open circuit
            let _ = cb
                .call(|| async { Err::<i32, DispaError>(DispaError::network("connection failed")) })
                .await;
            assert_eq!(cb.state().await, CircuitBreakerState::Open);

            // Wait for timeout
            sleep(Duration::from_millis(150)).await;

            // Should transition to half-open
            assert!(cb.can_execute().await);
            assert_eq!(cb.state().await, CircuitBreakerState::HalfOpen);
        })
        .await
        .expect("test_circuit_breaker_half_open_transition timed out");
    }

    #[tokio::test]
    async fn test_circuit_breaker_recovery() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let config = CircuitBreakerConfig {
                failure_threshold: 1,
                success_threshold: 2,
                min_requests: 1,
                timeout: Duration::from_millis(100),
                ..Default::default()
            };

            let cb = CircuitBreaker::new("test".to_string(), config);

            // Trigger failure to open circuit
            let _ = cb
                .call(|| async { Err::<i32, DispaError>(DispaError::network("connection failed")) })
                .await;
            assert_eq!(cb.state().await, CircuitBreakerState::Open);

            // Wait for timeout and transition to half-open
            sleep(Duration::from_millis(150)).await;
            assert!(cb.can_execute().await);
            assert_eq!(cb.state().await, CircuitBreakerState::HalfOpen);

            // First success
            let _ = cb.call(|| async { Ok::<i32, DispaError>(1) }).await;
            assert_eq!(cb.state().await, CircuitBreakerState::HalfOpen);

            // Second success should close the circuit
            let _ = cb.call(|| async { Ok::<i32, DispaError>(2) }).await;
            assert_eq!(cb.state().await, CircuitBreakerState::Closed);
        })
        .await
        .expect("test_circuit_breaker_recovery timed out");
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_failure() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let config = CircuitBreakerConfig {
                failure_threshold: 1,
                min_requests: 1,
                timeout: Duration::from_millis(100),
                ..Default::default()
            };

            let cb = CircuitBreaker::new("test".to_string(), config);

            // Trigger failure to open circuit
            let _ = cb
                .call(|| async { Err::<i32, DispaError>(DispaError::network("connection failed")) })
                .await;
            assert_eq!(cb.state().await, CircuitBreakerState::Open);

            // Wait for timeout and transition to half-open
            sleep(Duration::from_millis(150)).await;
            assert!(cb.can_execute().await);
            assert_eq!(cb.state().await, CircuitBreakerState::HalfOpen);

            // Failure in half-open should go back to open
            let _ = cb
                .call(|| async { Err::<i32, DispaError>(DispaError::network("still failing")) })
                .await;
            assert_eq!(cb.state().await, CircuitBreakerState::Open);
        })
        .await
        .expect("test_circuit_breaker_half_open_failure timed out");
    }

    #[tokio::test]
    async fn test_circuit_breaker_force_operations() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let cb = CircuitBreaker::with_defaults("test".to_string());
            cb.force_open().await;
            assert_eq!(cb.state().await, CircuitBreakerState::Open);
            cb.force_close().await;
            assert_eq!(cb.state().await, CircuitBreakerState::Closed);
            cb.force_open().await;
            cb.reset().await;
            assert_eq!(cb.state().await, CircuitBreakerState::Closed);
        })
        .await
        .expect("test_circuit_breaker_force_operations timed out");
    }

    #[tokio::test]
    async fn test_circuit_breaker_stats() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let cb = CircuitBreaker::with_defaults("test".to_string());
            let stats = cb.stats().await;
            assert_eq!(stats.name, "test");
            assert_eq!(stats.state, CircuitBreakerState::Closed);
            assert_eq!(stats.failure_count, 0);
            assert_eq!(stats.success_count, 0);
        })
        .await
        .expect("test_circuit_breaker_stats timed out");
    }
}
