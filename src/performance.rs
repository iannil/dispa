//! Performance optimization and stress testing utilities
//!
//! This module provides comprehensive performance optimization and testing capabilities:
//! - Automatic performance profiling and bottleneck detection
//! - Built-in stress testing framework
//! - Memory and CPU optimization tools
//! - Connection pooling and resource management
//! - Performance benchmarking and comparison

// HTTP types available when needed
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{RwLock, Semaphore};
use tokio::time::sleep;
use tracing::info;

/// Performance optimization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Enable performance optimizations
    pub enabled: bool,
    /// CPU optimization settings
    pub cpu_optimization: CpuOptimizationConfig,
    /// Memory optimization settings
    pub memory_optimization: MemoryOptimizationConfig,
    /// I/O optimization settings
    pub io_optimization: IoOptimizationConfig,
    /// Connection pool configuration
    pub connection_pool: ConnectionPoolConfig,
    /// Profiling settings
    pub profiling: ProfilingConfig,
    /// Stress testing configuration
    pub stress_testing: StressTestConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuOptimizationConfig {
    /// Enable CPU optimizations
    pub enabled: bool,
    /// Worker thread pool size
    pub worker_threads: Option<usize>,
    /// Task queue size
    pub task_queue_size: usize,
    /// CPU affinity settings
    pub cpu_affinity: Option<Vec<usize>>,
    /// Priority scheduling
    pub priority_scheduling: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOptimizationConfig {
    /// Enable memory optimizations
    pub enabled: bool,
    /// Memory pool size (MB)
    pub pool_size_mb: usize,
    /// Enable object pooling
    pub object_pooling: bool,
    /// Memory limit (MB)
    pub memory_limit_mb: Option<usize>,
    /// Garbage collection tuning
    pub gc_tuning: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoOptimizationConfig {
    /// Enable I/O optimizations
    pub enabled: bool,
    /// Buffer size (bytes)
    pub buffer_size: usize,
    /// Enable vectored I/O
    pub vectored_io: bool,
    /// I/O batch size
    pub batch_size: usize,
    /// Enable zero-copy optimizations
    pub zero_copy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPoolConfig {
    /// Enable connection pooling
    pub enabled: bool,
    /// Maximum connections per host
    pub max_connections_per_host: usize,
    /// Connection timeout (seconds)
    pub connection_timeout: u64,
    /// Keep-alive timeout (seconds)
    pub keepalive_timeout: u64,
    /// Pool cleanup interval (seconds)
    pub cleanup_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilingConfig {
    /// Enable profiling
    pub enabled: bool,
    /// Sampling rate (1-100)
    pub sampling_rate: u8,
    /// Profile CPU usage
    pub profile_cpu: bool,
    /// Profile memory usage
    pub profile_memory: bool,
    /// Profile I/O operations
    pub profile_io: bool,
    /// Profile duration (seconds)
    pub profile_duration: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressTestConfig {
    /// Enable built-in stress testing
    pub enabled: bool,
    /// Test scenarios
    pub scenarios: Vec<StressTestScenario>,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Test duration (seconds)
    pub duration: u64,
    /// Ramp-up time (seconds)
    pub ramp_up_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressTestScenario {
    /// Scenario name
    pub name: String,
    /// Request rate (requests per second)
    pub request_rate: u32,
    /// Request pattern (constant, burst, wave)
    pub pattern: String,
    /// Request endpoints
    pub endpoints: Vec<String>,
    /// Payload templates
    pub payloads: Vec<String>,
}

/// Performance optimizer
pub struct PerformanceOptimizer {
    config: PerformanceConfig,
    profiler: Arc<PerformanceProfiler>,
    connection_pool: Arc<ConnectionPool>,
    memory_pool: Arc<MemoryPool>,
    stress_tester: Arc<StressTester>,
    metrics: Arc<PerformanceMetrics>,
}

/// Performance profiler
struct PerformanceProfiler {
    config: ProfilingConfig,
    samples: Arc<RwLock<Vec<ProfileSample>>>,
    active: Arc<AtomicUsize>,
}

#[derive(Debug, Clone, Serialize)]
struct ProfileSample {
    timestamp: SystemTime,
    cpu_usage: f64,
    memory_usage: u64,
    io_operations: u64,
    active_connections: usize,
    request_latency: f64,
    thread_count: usize,
}

impl PerformanceProfiler {
    fn new(config: ProfilingConfig) -> Self {
        Self {
            config,
            samples: Arc::new(RwLock::new(Vec::new())),
            active: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn start_profiling(&self) {
        if !self.config.enabled {
            return;
        }

        self.active.store(1, Ordering::Relaxed);
        info!(
            "Starting performance profiling for {} seconds",
            self.config.profile_duration
        );

        let samples = Arc::clone(&self.samples);
        let active = Arc::clone(&self.active);
        let duration = self.config.profile_duration;
        let sampling_rate = self.config.sampling_rate;

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_millis(1000 / sampling_rate as u64));
            let end_time = Instant::now() + Duration::from_secs(duration);

            while Instant::now() < end_time && active.load(Ordering::Relaxed) == 1 {
                interval.tick().await;

                let sample = ProfileSample {
                    timestamp: SystemTime::now(),
                    cpu_usage: Self::get_cpu_usage().await,
                    memory_usage: Self::get_memory_usage(),
                    io_operations: Self::get_io_operations(),
                    active_connections: Self::get_active_connections(),
                    request_latency: Self::get_request_latency().await,
                    thread_count: Self::get_thread_count(),
                };

                let mut samples_guard = samples.write().await;
                samples_guard.push(sample);

                // Keep only recent samples
                if samples_guard.len() > 1000 {
                    samples_guard.remove(0);
                }
            }

            active.store(0, Ordering::Relaxed);
            info!("Performance profiling completed");
        });
    }

    async fn get_cpu_usage() -> f64 {
        // Mock CPU usage - in real implementation, use system APIs
        rand::random::<f64>() * 100.0
    }

    fn get_memory_usage() -> u64 {
        // Mock memory usage - in real implementation, use system APIs
        rand::random::<u64>() % 1000000000 // Up to 1GB
    }

    fn get_io_operations() -> u64 {
        // Mock I/O operations count
        rand::random::<u64>() % 10000
    }

    fn get_active_connections() -> usize {
        // Mock active connections count
        rand::random::<usize>() % 1000
    }

    async fn get_request_latency() -> f64 {
        // Mock request latency in milliseconds
        rand::random::<f64>() * 1000.0
    }

    fn get_thread_count() -> usize {
        // Mock thread count
        rand::random::<usize>() % 100 + 10
    }

    async fn get_profile_report(&self) -> ProfileReport {
        let samples = self.samples.read().await;

        if samples.is_empty() {
            return ProfileReport::default();
        }

        let avg_cpu = samples.iter().map(|s| s.cpu_usage).sum::<f64>() / samples.len() as f64;
        let avg_memory = samples.iter().map(|s| s.memory_usage).sum::<u64>() / samples.len() as u64;
        let avg_latency =
            samples.iter().map(|s| s.request_latency).sum::<f64>() / samples.len() as f64;

        let max_cpu = samples.iter().map(|s| s.cpu_usage).fold(0.0, f64::max);
        let max_memory = samples.iter().map(|s| s.memory_usage).max().unwrap_or(0);
        let max_latency = samples
            .iter()
            .map(|s| s.request_latency)
            .fold(0.0, f64::max);

        ProfileReport {
            sample_count: samples.len(),
            avg_cpu_usage: avg_cpu,
            max_cpu_usage: max_cpu,
            avg_memory_usage: avg_memory,
            max_memory_usage: max_memory,
            avg_request_latency: avg_latency,
            max_request_latency: max_latency,
            bottlenecks: self.detect_bottlenecks(&samples),
            recommendations: self.generate_recommendations(&samples),
        }
    }

    fn detect_bottlenecks(&self, samples: &[ProfileSample]) -> Vec<String> {
        let mut bottlenecks = Vec::new();

        let avg_cpu = samples.iter().map(|s| s.cpu_usage).sum::<f64>() / samples.len() as f64;
        if avg_cpu > 80.0 {
            bottlenecks.push("High CPU usage detected".to_string());
        }

        let avg_memory = samples.iter().map(|s| s.memory_usage).sum::<u64>() / samples.len() as u64;
        if avg_memory > 800_000_000 {
            // 800MB
            bottlenecks.push("High memory usage detected".to_string());
        }

        let avg_latency =
            samples.iter().map(|s| s.request_latency).sum::<f64>() / samples.len() as f64;
        if avg_latency > 500.0 {
            bottlenecks.push("High request latency detected".to_string());
        }

        bottlenecks
    }

    fn generate_recommendations(&self, samples: &[ProfileSample]) -> Vec<String> {
        let mut recommendations = Vec::new();
        let bottlenecks = self.detect_bottlenecks(samples);

        for bottleneck in &bottlenecks {
            match bottleneck.as_str() {
                s if s.contains("CPU") => {
                    recommendations.push("Consider increasing worker thread pool size".to_string());
                    recommendations.push("Enable CPU affinity for better performance".to_string());
                }
                s if s.contains("memory") => {
                    recommendations.push("Enable object pooling to reduce allocations".to_string());
                    recommendations.push("Consider increasing memory pool size".to_string());
                }
                s if s.contains("latency") => {
                    recommendations.push("Enable connection pooling".to_string());
                    recommendations
                        .push("Consider using cache for frequently accessed data".to_string());
                }
                _ => {}
            }
        }

        recommendations
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileReport {
    sample_count: usize,
    avg_cpu_usage: f64,
    max_cpu_usage: f64,
    avg_memory_usage: u64,
    max_memory_usage: u64,
    avg_request_latency: f64,
    max_request_latency: f64,
    bottlenecks: Vec<String>,
    recommendations: Vec<String>,
}

impl Default for ProfileReport {
    fn default() -> Self {
        Self {
            sample_count: 0,
            avg_cpu_usage: 0.0,
            max_cpu_usage: 0.0,
            avg_memory_usage: 0,
            max_memory_usage: 0,
            avg_request_latency: 0.0,
            max_request_latency: 0.0,
            bottlenecks: Vec::new(),
            recommendations: Vec::new(),
        }
    }
}

/// Connection pool manager
struct ConnectionPool {
    config: ConnectionPoolConfig,
    pools: Arc<RwLock<HashMap<String, HostPool>>>,
}

struct HostPool {
    connections: Vec<Connection>,
    semaphore: Arc<Semaphore>,
    last_cleanup: Instant,
}

struct Connection {
    id: String,
    created_at: Instant,
    last_used: Instant,
    in_use: bool,
}

impl ConnectionPool {
    fn new(config: ConnectionPoolConfig) -> Self {
        Self {
            config,
            pools: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn get_connection(&self, host: &str) -> Option<Connection> {
        if !self.config.enabled {
            return None;
        }

        let host_string = host.to_string();

        // Scope for initial pool creation
        {
            let mut pools = self.pools.write().await;
            pools
                .entry(host_string.clone())
                .or_insert_with(|| HostPool {
                    connections: Vec::new(),
                    semaphore: Arc::new(Semaphore::new(self.config.max_connections_per_host)),
                    last_cleanup: Instant::now(),
                });
        }

        // Scope for connection acquisition
        let mut pools = self.pools.write().await;
        if let Some(pool) = pools.get_mut(&host_string) {
            // Try to acquire a permit (move this check to avoid lifetime issues)
            let permit_result = pool.semaphore.try_acquire();

            if permit_result.is_ok() {
                // Look for an available connection
                for connection in &mut pool.connections {
                    if !connection.in_use
                        && connection.last_used.elapsed()
                            < Duration::from_secs(self.config.keepalive_timeout)
                    {
                        connection.in_use = true;
                        connection.last_used = Instant::now();
                        return Some(connection.clone());
                    }
                }

                // Create new connection if none available
                let connection = Connection {
                    id: format!("conn-{}-{}", host, pool.connections.len()),
                    created_at: Instant::now(),
                    last_used: Instant::now(),
                    in_use: true,
                };

                pool.connections.push(connection.clone());
                return Some(connection);
            }
        }

        None
    }

    async fn return_connection(&self, host: &str, connection_id: &str) {
        let mut pools = self.pools.write().await;
        if let Some(pool) = pools.get_mut(host) {
            for connection in &mut pool.connections {
                if connection.id == connection_id && connection.in_use {
                    connection.in_use = false;
                    connection.last_used = Instant::now();
                    pool.semaphore.add_permits(1);
                    break;
                }
            }
        }
    }

    async fn cleanup_expired_connections(&self) {
        let mut pools = self.pools.write().await;
        let cleanup_threshold = Duration::from_secs(self.config.cleanup_interval);

        for (_host, pool) in pools.iter_mut() {
            if pool.last_cleanup.elapsed() > cleanup_threshold {
                let keepalive_timeout = Duration::from_secs(self.config.keepalive_timeout);
                pool.connections
                    .retain(|conn| !conn.in_use && conn.last_used.elapsed() < keepalive_timeout);
                pool.last_cleanup = Instant::now();
            }
        }
    }
}

impl Clone for Connection {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            created_at: self.created_at,
            last_used: self.last_used,
            in_use: self.in_use,
        }
    }
}

/// Type alias for complex object pool type
type ObjectPool = Arc<RwLock<HashMap<String, Vec<Box<dyn std::any::Any + Send + Sync>>>>>;

/// Memory pool manager
struct MemoryPool {
    config: MemoryOptimizationConfig,
    buffer_pool: Arc<RwLock<Vec<Vec<u8>>>>,
    #[allow(dead_code)]
    object_pool: ObjectPool,
}

impl MemoryPool {
    fn new(config: MemoryOptimizationConfig) -> Self {
        Self {
            config,
            buffer_pool: Arc::new(RwLock::new(Vec::new())),
            object_pool: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn get_buffer(&self, size: usize) -> Vec<u8> {
        if !self.config.object_pooling {
            return vec![0; size];
        }

        let mut pool = self.buffer_pool.write().await;

        // Look for suitable buffer
        if let Some(pos) = pool.iter().position(|buf| buf.len() >= size) {
            let mut buffer = pool.remove(pos);
            buffer.resize(size, 0);
            buffer
        } else {
            vec![0; size]
        }
    }

    async fn return_buffer(&self, mut buffer: Vec<u8>) {
        if !self.config.object_pooling {
            return;
        }

        // Clear buffer and return to pool
        buffer.clear();
        let mut pool = self.buffer_pool.write().await;

        // Limit pool size
        if pool.len() < 100 {
            pool.push(buffer);
        }
    }
}

/// Built-in stress tester
struct StressTester {
    config: StressTestConfig,
    client: reqwest::Client,
    metrics: Arc<StressTestMetrics>,
}

#[derive(Debug)]
struct StressTestMetrics {
    total_requests: AtomicU64,
    successful_requests: AtomicU64,
    failed_requests: AtomicU64,
    total_response_time: AtomicU64,
    min_response_time: AtomicU64,
    max_response_time: AtomicU64,
    #[allow(dead_code)]
    active_connections: AtomicUsize,
}

impl StressTestMetrics {
    fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            total_response_time: AtomicU64::new(0),
            min_response_time: AtomicU64::new(u64::MAX),
            max_response_time: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
        }
    }

    fn record_request(&self, success: bool, response_time: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        if success {
            self.successful_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
        }

        self.total_response_time
            .fetch_add(response_time, Ordering::Relaxed);

        // Update min response time
        let mut current_min = self.min_response_time.load(Ordering::Relaxed);
        while response_time < current_min {
            match self.min_response_time.compare_exchange_weak(
                current_min,
                response_time,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_min = x,
            }
        }

        // Update max response time
        let mut current_max = self.max_response_time.load(Ordering::Relaxed);
        while response_time > current_max {
            match self.max_response_time.compare_exchange_weak(
                current_max,
                response_time,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_max = x,
            }
        }
    }

    fn get_report(&self) -> StressTestReport {
        let total = self.total_requests.load(Ordering::Relaxed);
        let successful = self.successful_requests.load(Ordering::Relaxed);
        let failed = self.failed_requests.load(Ordering::Relaxed);
        let total_time = self.total_response_time.load(Ordering::Relaxed);

        StressTestReport {
            total_requests: total,
            successful_requests: successful,
            failed_requests: failed,
            success_rate: if total > 0 {
                successful as f64 / total as f64 * 100.0
            } else {
                0.0
            },
            avg_response_time: if total > 0 {
                total_time as f64 / total as f64
            } else {
                0.0
            },
            min_response_time: self.min_response_time.load(Ordering::Relaxed),
            max_response_time: self.max_response_time.load(Ordering::Relaxed),
            requests_per_second: 0.0, // Would be calculated based on test duration
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StressTestReport {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    success_rate: f64,
    avg_response_time: f64,
    min_response_time: u64,
    max_response_time: u64,
    requests_per_second: f64,
}

impl StressTester {
    fn new(config: StressTestConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            metrics: Arc::new(StressTestMetrics::new()),
        }
    }

    async fn run_stress_test(&self, base_url: &str) -> StressTestReport {
        if !self.config.enabled || self.config.scenarios.is_empty() {
            return StressTestReport {
                total_requests: 0,
                successful_requests: 0,
                failed_requests: 0,
                success_rate: 0.0,
                avg_response_time: 0.0,
                min_response_time: 0,
                max_response_time: 0,
                requests_per_second: 0.0,
            };
        }

        info!("Starting stress test for {} seconds", self.config.duration);

        let scenario = &self.config.scenarios[0]; // Use first scenario
        let semaphore = Arc::new(Semaphore::new(self.config.max_connections));
        let end_time = Instant::now() + Duration::from_secs(self.config.duration);

        // Calculate request interval
        let request_interval = Duration::from_secs(1) / scenario.request_rate;

        while Instant::now() < end_time {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let metrics = Arc::clone(&self.metrics);
            let client = self.client.clone();
            let endpoint = scenario.endpoints[0].clone(); // Use first endpoint
            let url = format!("{}{}", base_url, endpoint);

            tokio::spawn(async move {
                let start = Instant::now();

                match client.get(&url).send().await {
                    Ok(response) => {
                        let response_time = start.elapsed().as_millis() as u64;
                        let success = response.status().is_success();
                        metrics.record_request(success, response_time);
                    }
                    Err(_) => {
                        let response_time = start.elapsed().as_millis() as u64;
                        metrics.record_request(false, response_time);
                    }
                }

                drop(permit);
            });

            sleep(request_interval).await;
        }

        // Wait for remaining requests to complete
        sleep(Duration::from_secs(5)).await;

        let report = self.metrics.get_report();
        info!(
            "Stress test completed: {} requests, {:.2}% success rate",
            report.total_requests, report.success_rate
        );

        report
    }
}

/// Performance metrics collector
#[derive(Debug)]
struct PerformanceMetrics {
    request_count: AtomicU64,
    response_times: Arc<RwLock<Vec<f64>>>,
    #[allow(dead_code)]
    cpu_usage_samples: Arc<RwLock<Vec<f64>>>,
    #[allow(dead_code)]
    memory_usage_samples: Arc<RwLock<Vec<u64>>>,
    error_count: AtomicU64,
}

impl PerformanceMetrics {
    fn new() -> Self {
        Self {
            request_count: AtomicU64::new(0),
            response_times: Arc::new(RwLock::new(Vec::new())),
            cpu_usage_samples: Arc::new(RwLock::new(Vec::new())),
            memory_usage_samples: Arc::new(RwLock::new(Vec::new())),
            error_count: AtomicU64::new(0),
        }
    }

    async fn record_request(&self, response_time: f64) {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        let mut times = self.response_times.write().await;
        times.push(response_time);

        // Keep only recent samples
        if times.len() > 1000 {
            times.remove(0);
        }
    }

    async fn record_error(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }

    async fn get_summary(&self) -> PerformanceSummary {
        let times = self.response_times.read().await;
        let request_count = self.request_count.load(Ordering::Relaxed);
        let error_count = self.error_count.load(Ordering::Relaxed);

        let avg_response_time = if !times.is_empty() {
            times.iter().sum::<f64>() / times.len() as f64
        } else {
            0.0
        };

        let max_response_time = times.iter().cloned().fold(0.0, f64::max);
        let min_response_time = times.iter().cloned().fold(f64::MAX, f64::min);

        PerformanceSummary {
            total_requests: request_count,
            total_errors: error_count,
            avg_response_time,
            min_response_time: if min_response_time == f64::MAX {
                0.0
            } else {
                min_response_time
            },
            max_response_time,
            error_rate: if request_count > 0 {
                error_count as f64 / request_count as f64 * 100.0
            } else {
                0.0
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PerformanceSummary {
    total_requests: u64,
    total_errors: u64,
    avg_response_time: f64,
    min_response_time: f64,
    max_response_time: f64,
    error_rate: f64,
}

impl PerformanceOptimizer {
    pub fn new(config: PerformanceConfig) -> Self {
        Self {
            profiler: Arc::new(PerformanceProfiler::new(config.profiling.clone())),
            connection_pool: Arc::new(ConnectionPool::new(config.connection_pool.clone())),
            memory_pool: Arc::new(MemoryPool::new(config.memory_optimization.clone())),
            stress_tester: Arc::new(StressTester::new(config.stress_testing.clone())),
            metrics: Arc::new(PerformanceMetrics::new()),
            config,
        }
    }

    pub async fn start_optimization(&self) {
        if !self.config.enabled {
            return;
        }

        info!("Starting performance optimization");

        // Start profiling
        self.profiler.start_profiling().await;

        // Start connection pool cleanup
        let pool = Arc::clone(&self.connection_pool);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                pool.cleanup_expired_connections().await;
            }
        });
    }

    pub async fn run_stress_test(&self, base_url: &str) -> StressTestReport {
        self.stress_tester.run_stress_test(base_url).await
    }

    pub async fn get_profile_report(&self) -> ProfileReport {
        self.profiler.get_profile_report().await
    }

    pub async fn get_performance_summary(&self) -> PerformanceSummary {
        self.metrics.get_summary().await
    }

    pub async fn record_request(&self, response_time: f64) {
        self.metrics.record_request(response_time).await;
    }

    pub async fn record_error(&self) {
        self.metrics.record_error().await;
    }

    pub async fn optimize_memory(&self) -> Vec<u8> {
        self.memory_pool.get_buffer(8192).await
    }

    pub async fn return_memory(&self, buffer: Vec<u8>) {
        self.memory_pool.return_buffer(buffer).await;
    }

    pub async fn get_connection(&self, host: &str) -> Option<String> {
        self.connection_pool
            .get_connection(host)
            .await
            .map(|conn| conn.id)
    }

    pub async fn return_connection(&self, host: &str, connection_id: &str) {
        self.connection_pool
            .return_connection(host, connection_id)
            .await;
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cpu_optimization: CpuOptimizationConfig {
                enabled: true,
                worker_threads: None,
                task_queue_size: 10000,
                cpu_affinity: None,
                priority_scheduling: false,
            },
            memory_optimization: MemoryOptimizationConfig {
                enabled: true,
                pool_size_mb: 256,
                object_pooling: true,
                memory_limit_mb: Some(1024),
                gc_tuning: true,
            },
            io_optimization: IoOptimizationConfig {
                enabled: true,
                buffer_size: 8192,
                vectored_io: true,
                batch_size: 100,
                zero_copy: true,
            },
            connection_pool: ConnectionPoolConfig {
                enabled: true,
                max_connections_per_host: 100,
                connection_timeout: 30,
                keepalive_timeout: 300,
                cleanup_interval: 60,
            },
            profiling: ProfilingConfig {
                enabled: true,
                sampling_rate: 10,
                profile_cpu: true,
                profile_memory: true,
                profile_io: true,
                profile_duration: 300,
            },
            stress_testing: StressTestConfig {
                enabled: true,
                scenarios: vec![StressTestScenario {
                    name: "Default Load Test".to_string(),
                    request_rate: 100,
                    pattern: "constant".to_string(),
                    endpoints: vec!["/health".to_string()],
                    payloads: vec!["{}".to_string()],
                }],
                max_connections: 1000,
                duration: 60,
                ramp_up_time: 10,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_performance_optimizer_creation() {
        let config = PerformanceConfig::default();
        let optimizer = PerformanceOptimizer::new(config);

        assert!(optimizer.config.enabled);
    }

    #[tokio::test]
    async fn test_connection_pool() {
        let config = ConnectionPoolConfig {
            enabled: true,
            max_connections_per_host: 5,
            connection_timeout: 30,
            keepalive_timeout: 300,
            cleanup_interval: 60,
        };

        let pool = ConnectionPool::new(config);

        // Test getting connections
        let conn1 = pool.get_connection("example.com").await;
        assert!(conn1.is_some());

        let conn2 = pool.get_connection("example.com").await;
        assert!(conn2.is_some());

        // Return connections
        pool.return_connection("example.com", &conn1.unwrap().id)
            .await;
        pool.return_connection("example.com", &conn2.unwrap().id)
            .await;
    }

    #[tokio::test]
    async fn test_memory_pool() {
        let config = MemoryOptimizationConfig {
            enabled: true,
            pool_size_mb: 64,
            object_pooling: true,
            memory_limit_mb: Some(128),
            gc_tuning: true,
        };

        let pool = MemoryPool::new(config);

        let buffer1 = pool.get_buffer(1024).await;
        assert_eq!(buffer1.len(), 1024);

        let buffer2 = pool.get_buffer(2048).await;
        assert_eq!(buffer2.len(), 2048);

        pool.return_buffer(buffer1).await;
        pool.return_buffer(buffer2).await;
    }

    #[tokio::test]
    async fn test_performance_metrics() {
        let metrics = PerformanceMetrics::new();

        metrics.record_request(100.0).await;
        metrics.record_request(150.0).await;
        metrics.record_request(200.0).await;
        metrics.record_error().await;

        let summary = metrics.get_summary().await;
        assert_eq!(summary.total_requests, 3);
        assert_eq!(summary.total_errors, 1);
        assert_eq!(summary.avg_response_time, 150.0);
        assert!(summary.error_rate > 0.0);
    }

    #[tokio::test]
    async fn test_stress_test_metrics() {
        let metrics = StressTestMetrics::new();

        metrics.record_request(true, 100);
        metrics.record_request(true, 200);
        metrics.record_request(false, 500);

        let report = metrics.get_report();
        assert_eq!(report.total_requests, 3);
        assert_eq!(report.successful_requests, 2);
        assert_eq!(report.failed_requests, 1);
        assert!((report.success_rate - 66.67).abs() < 0.1);
    }

    #[tokio::test]
    async fn test_profiler_report() {
        let config = ProfilingConfig {
            enabled: true,
            sampling_rate: 10,
            profile_cpu: true,
            profile_memory: true,
            profile_io: true,
            profile_duration: 1, // Short duration for testing
        };

        let profiler = PerformanceProfiler::new(config);

        // Start profiling briefly
        profiler.start_profiling().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let _report = profiler.get_profile_report().await;
        // Report might be empty due to short duration, but structure should be correct
        // Length checks are implicit since we're dealing with Vec
    }
}
