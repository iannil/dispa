pub mod balancer;
pub mod cache;
pub mod circuit_breaker;
pub mod config;
pub mod error;
pub mod graceful_shutdown;
pub mod logger;
pub mod monitoring;
pub mod proxy;
pub mod plugins;
pub mod retry;
pub mod routing;
pub mod tls;

// Re-export commonly used types
pub use cache::{CacheConfig, CacheEntry, CacheMetrics, CachePolicy, CachePolicyPattern};
pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerState, CircuitBreakerStats,
};
pub use error::{DispaError, DispaResult, ErrorSeverity};
pub use graceful_shutdown::{ResourceCleanup, ShutdownManager, ShutdownSignal, TaskHandle};
pub use retry::{BackoffStrategy, ErrorRecovery, ExponentialBackoff, RetryConfig, RetryExecutor};
pub use routing::{RoutingConfig, RoutingDecision, RoutingEngine, RoutingRule};
pub use tls::{CertificateConfig, TlsConfig, TlsManager, TlsVersion};
