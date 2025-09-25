use dispa::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerState};
use dispa::error::DispaResult;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

/// Test circuit breaker edge cases and boundary conditions
mod circuit_breaker_edge_tests {
    #![allow(clippy::redundant_closure)]
    #![allow(dead_code)]
    use super::*;

    /// Create a simple success function
    async fn success_fn() -> DispaResult<&'static str> {
        Ok("success")
    }

    /// Create a simple failure function
    async fn failure_fn() -> DispaResult<&'static str> {
        Err(dispa::error::DispaError::internal("test failure"))
    }

    /// Create a function that fails after N successful calls
    fn failing_after_n(
        n: u32,
    ) -> impl Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = DispaResult<String>> + Send>>
           + Clone {
        let counter = Arc::new(AtomicU32::new(0));
        move || {
            let counter = counter.clone();
            Box::pin(async move {
                let count = counter.fetch_add(1, Ordering::Relaxed);
                if count < n {
                    Ok(format!("success-{}", count))
                } else {
                    Err(dispa::error::DispaError::internal("failing after n calls"))
                }
            })
        }
    }

    /// Test circuit breaker with zero failure threshold
    #[tokio::test]
    async fn test_zero_failure_threshold() {
        let config = CircuitBreakerConfig {
            failure_threshold: 0, // Should open immediately on any failure
            success_threshold: 1,
            timeout: Duration::from_millis(100),
            time_window: Duration::from_secs(60),
            min_requests: 1,
        };

        let cb = CircuitBreaker::new("zero-threshold".to_string(), config);

        // First failure should open the circuit immediately
        let result = cb.call(|| failure_fn()).await;
        assert!(result.is_err(), "First call should fail");

        // Circuit should now be open
        assert_eq!(cb.state().await, CircuitBreakerState::Open);

        // Subsequent calls should be blocked
        let result = cb.call(|| success_fn()).await;
        assert!(
            result.is_err(),
            "Call should be blocked when circuit is open"
        );

        // Verify it's a circuit breaker error, not the function error
        assert!(result.unwrap_err().to_string().contains("circuit breaker"));
    }

    /// Test circuit breaker with zero success threshold
    #[tokio::test]
    async fn test_zero_success_threshold() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 0, // Should close immediately
            timeout: Duration::from_millis(100),
            time_window: Duration::from_secs(60),
            min_requests: 1,
        };

        let cb = CircuitBreaker::new("zero-success-threshold".to_string(), config);

        // Trigger failure to open circuit
        let _ = cb.call(|| failure_fn()).await;
        assert_eq!(cb.state().await, CircuitBreakerState::Open);

        // Wait for timeout
        sleep(Duration::from_millis(150)).await;

        // Should transition to half-open
        let can_execute = cb.can_execute().await;
        assert!(can_execute, "Should allow execution in half-open state");

        // With zero success threshold, any success should close circuit
        let result = cb.call(|| success_fn()).await;
        assert!(result.is_ok(), "Call should succeed");
        assert_eq!(cb.state().await, CircuitBreakerState::Closed);
    }

    /// Test circuit breaker with very short timeout
    #[tokio::test]
    async fn test_very_short_timeout() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 1,
            timeout: Duration::from_millis(1), // Very short timeout
            time_window: Duration::from_secs(60),
            min_requests: 1,
        };

        let cb = CircuitBreaker::new("short-timeout".to_string(), config);

        // Open the circuit
        let _ = cb.call(|| failure_fn()).await;
        assert_eq!(cb.state().await, CircuitBreakerState::Open);

        // Wait longer than timeout
        sleep(Duration::from_millis(10)).await;

        // Should allow execution (half-open state)
        let can_execute = cb.can_execute().await;
        assert!(can_execute, "Should allow execution after timeout");

        // Successful call should close the circuit
        let result = cb.call(|| success_fn()).await;
        assert!(result.is_ok(), "Call should succeed");
        assert_eq!(cb.state().await, CircuitBreakerState::Closed);
    }

    /// Test circuit breaker under high concurrency
    #[tokio::test]
    async fn test_concurrent_circuit_breaker_operations() {
        let config = CircuitBreakerConfig {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_millis(100),
            time_window: Duration::from_secs(60),
            min_requests: 1,
        };

        let cb = Arc::new(CircuitBreaker::new("concurrent".to_string(), config));

        // Spawn multiple tasks that will cause failures
        let mut handles = vec![];
        for i in 0..10 {
            let cb_clone = cb.clone();
            let handle = tokio::spawn(async move {
                // Some tasks succeed, some fail
                if i % 3 == 0 {
                    cb_clone.call(|| success_fn()).await
                } else {
                    cb_clone.call(|| failure_fn()).await
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        let mut success_count = 0;
        let mut failure_count = 0;

        for handle in handles {
            match handle.await.unwrap() {
                Ok(_) => success_count += 1,
                Err(_) => failure_count += 1,
            }
        }

        assert!(success_count > 0, "Some calls should succeed");
        assert!(failure_count > 0, "Some calls should fail");

        // Circuit breaker should still be functional
        let stats = cb.stats().await;
        assert!(stats.request_count > 0, "Should have recorded requests");
    }

    /// Test circuit breaker with rapid state transitions
    #[tokio::test]
    async fn test_rapid_state_transitions() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(50),
            time_window: Duration::from_secs(60),
            min_requests: 1,
        };

        let cb = CircuitBreaker::new("rapid-transitions".to_string(), config);

        // Start in closed state
        assert_eq!(cb.state().await, CircuitBreakerState::Closed);

        // Cause failures to open circuit
        let _ = cb.call(|| failure_fn()).await;
        let _ = cb.call(|| failure_fn()).await;

        assert_eq!(cb.state().await, CircuitBreakerState::Open);

        // Wait for timeout to enter half-open
        sleep(Duration::from_millis(60)).await;

        // Should be able to execute in half-open
        assert!(cb.can_execute().await);

        // Success should close circuit
        let _ = cb.call(|| success_fn()).await;
        let _ = cb.call(|| success_fn()).await;

        assert_eq!(cb.state().await, CircuitBreakerState::Closed);

        // Should work normally in closed state
        let result = cb.call(|| success_fn()).await;
        assert!(result.is_ok());
    }

    /// Test circuit breaker statistics accuracy
    #[tokio::test]
    async fn test_circuit_breaker_statistics() {
        let config = CircuitBreakerConfig {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_millis(100),
            time_window: Duration::from_secs(60),
            min_requests: 1,
        };

        let cb = CircuitBreaker::new("stats-test".to_string(), config);

        // Make some successful calls
        for _ in 0..3 {
            let _ = cb.call(|| success_fn()).await;
        }

        // Make some failed calls
        for _ in 0..2 {
            let _ = cb.call(|| failure_fn()).await;
        }

        let stats = cb.stats().await;
        assert_eq!(stats.request_count, 5, "Should record all requests");
        assert_eq!(stats.success_count, 3, "Should record successful requests");
        assert_eq!(stats.failure_count, 2, "Should record failed requests");
        assert_eq!(stats.state, CircuitBreakerState::Closed);
    }

    /// Test circuit breaker with functions that take time to execute
    #[tokio::test]
    async fn test_slow_function_execution() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout: Duration::from_millis(100),
            time_window: Duration::from_secs(60),
            min_requests: 1,
        };

        let cb = CircuitBreaker::new("slow-function".to_string(), config);

        // Function that takes time to execute
        let slow_success = || async {
            sleep(Duration::from_millis(50)).await;
            Ok("slow success")
        };

        let slow_failure = || async {
            sleep(Duration::from_millis(50)).await;
            Err(dispa::error::DispaError::internal("slow failure"))
        };

        // Execute slow functions
        let start = std::time::Instant::now();

        let result1 = cb.call(slow_success).await;
        assert!(result1.is_ok());

        let result2: Result<&str, _> = cb.call(slow_failure).await;
        assert!(result2.is_err());

        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(100),
            "Should take at least 100ms for both calls"
        );

        // Circuit breaker should still work correctly
        assert_eq!(cb.state().await, CircuitBreakerState::Closed);
    }

    /// Test circuit breaker reset functionality
    #[tokio::test]
    async fn test_circuit_breaker_reset() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(100),
            time_window: Duration::from_secs(60),
            min_requests: 1,
        };

        let cb = CircuitBreaker::new("reset-test".to_string(), config);

        // Open the circuit
        let _ = cb.call(|| failure_fn()).await;
        let _ = cb.call(|| failure_fn()).await;

        assert_eq!(cb.state().await, CircuitBreakerState::Open);

        // Reset should close the circuit
        cb.reset().await;
        assert_eq!(cb.state().await, CircuitBreakerState::Closed);

        // Should work normally after reset
        let result = cb.call(|| success_fn()).await;
        assert!(result.is_ok());
    }

    /// Test circuit breaker force operations
    #[tokio::test]
    async fn test_circuit_breaker_force_operations() {
        let config = CircuitBreakerConfig::default();
        let cb = CircuitBreaker::new("force-test".to_string(), config);

        // Force open
        cb.force_open().await;
        assert_eq!(cb.state().await, CircuitBreakerState::Open);

        // Should block calls
        let result = cb.call(|| success_fn()).await;
        assert!(result.is_err());

        // Force close
        cb.force_close().await;
        assert_eq!(cb.state().await, CircuitBreakerState::Closed);

        // Should allow calls
        let result = cb.call(|| success_fn()).await;
        assert!(result.is_ok());
    }
}
