//! Enhanced load balancing algorithms with advanced routing capabilities

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Backend server representation for enhanced algorithms
#[derive(Debug, Clone)]
pub struct Backend {
    pub id: String,
    pub url: String,
    pub weight: u32,
    pub healthy: bool,
    pub region: Option<String>,
    pub zone: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl Default for Backend {
    fn default() -> Self {
        Self {
            id: String::new(),
            url: String::new(),
            weight: 100,
            healthy: true,
            region: None,
            zone: None,
            metadata: HashMap::new(),
        }
    }
}

/// Enhanced load balancing algorithm types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnhancedLoadBalancingAlgorithm {
    /// Consistent hashing for session stickiness
    ConsistentHash {
        virtual_nodes: u32,
        hash_function: HashFunction,
    },
    /// Geographic-aware routing
    GeoAware {
        regions: HashMap<String, Vec<String>>,
        fallback_strategy: GeoFallbackStrategy,
    },
    /// Session-based sticky routing
    SessionSticky {
        session_timeout: Duration,
        fallback_algorithm: Box<EnhancedLoadBalancingAlgorithm>,
    },
    /// Adaptive weighted round robin with health-based adjustments
    AdaptiveWeighted {
        adjustment_factor: f64,
        health_threshold: f64,
        response_time_weight: f64,
    },
    /// Priority-based routing with failover
    Priority {
        tiers: Vec<PriorityTier>,
        failover_threshold: f64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashFunction {
    DefaultHash,
    Sha256,
    Murmur3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GeoFallbackStrategy {
    NearestRegion,
    RoundRobin,
    WeightedRoundRobin,
    HealthiestFirst,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityTier {
    pub name: String,
    pub weight: u32,
    pub backends: Vec<String>,
    pub min_healthy_ratio: f64,
}

/// Consistent hash ring for session stickiness
pub struct ConsistentHashRing {
    ring: std::collections::BTreeMap<u64, String>,
    virtual_nodes: u32,
    hash_function: HashFunction,
}

impl ConsistentHashRing {
    pub fn new(virtual_nodes: u32, hash_function: HashFunction) -> Self {
        Self {
            ring: std::collections::BTreeMap::new(),
            virtual_nodes,
            hash_function,
        }
    }

    pub fn add_backend(&mut self, backend_id: &str) {
        for i in 0..self.virtual_nodes {
            let virtual_key = format!("{}:{}", backend_id, i);
            let hash = self.hash(&virtual_key);
            self.ring.insert(hash, backend_id.to_string());
        }
    }

    pub fn remove_backend(&mut self, backend_id: &str) {
        for i in 0..self.virtual_nodes {
            let virtual_key = format!("{}:{}", backend_id, i);
            let hash = self.hash(&virtual_key);
            self.ring.remove(&hash);
        }
    }

    pub fn get_backend(&self, key: &str) -> Option<String> {
        if self.ring.is_empty() {
            return None;
        }

        let hash = self.hash(key);

        // Find the first backend with hash >= key hash (clockwise on ring)
        self.ring
            .range(hash..)
            .next()
            .or_else(|| self.ring.iter().next()) // Wrap around to first if no match found
            .map(|(_, backend)| backend.clone())
    }

    fn hash(&self, key: &str) -> u64 {
        match self.hash_function {
            HashFunction::DefaultHash => {
                let mut hasher = DefaultHasher::new();
                key.hash(&mut hasher);
                hasher.finish()
            }
            HashFunction::Sha256 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(key.as_bytes());
                let result = hasher.finalize();
                u64::from_be_bytes([
                    result[0], result[1], result[2], result[3], result[4], result[5], result[6],
                    result[7],
                ])
            }
            HashFunction::Murmur3 => {
                // Simplified hash - in production, use a proper murmur3 implementation
                let mut hasher = DefaultHasher::new();
                key.hash(&mut hasher);
                hasher.finish().wrapping_mul(0xc4ceb9fe1a85ec53u64)
            }
        }
    }
}

/// Geographic routing manager
pub struct GeoRoutingManager {
    regions: HashMap<String, Vec<String>>,
    backend_regions: HashMap<String, String>,
    fallback_strategy: GeoFallbackStrategy,
}

impl GeoRoutingManager {
    pub fn new(
        regions: HashMap<String, Vec<String>>,
        fallback_strategy: GeoFallbackStrategy,
    ) -> Self {
        let mut backend_regions = HashMap::new();

        for (region, backends) in &regions {
            for backend in backends {
                backend_regions.insert(backend.clone(), region.clone());
            }
        }

        Self {
            regions,
            backend_regions,
            fallback_strategy,
        }
    }

    pub fn get_backends_for_region(&self, region: &str) -> Vec<String> {
        self.regions.get(region).cloned().unwrap_or_default()
    }

    pub fn get_fallback_backends(
        &self,
        failed_region: &str,
        available_backends: &[Backend],
    ) -> Vec<String> {
        match self.fallback_strategy {
            GeoFallbackStrategy::NearestRegion => {
                // Find geographically nearest region (simplified logic)
                self.find_nearest_region_backends(failed_region, available_backends)
            }
            GeoFallbackStrategy::RoundRobin => {
                available_backends.iter().map(|b| b.id.clone()).collect()
            }
            GeoFallbackStrategy::WeightedRoundRobin => available_backends
                .iter()
                .filter(|b| b.weight > 0)
                .map(|b| b.id.clone())
                .collect(),
            GeoFallbackStrategy::HealthiestFirst => {
                let mut backends: Vec<_> = available_backends
                    .iter()
                    .filter(|b| b.healthy)
                    .map(|b| b.id.clone())
                    .collect();
                backends.sort_by(|a, b| {
                    // Sort by health score if available, otherwise by ID
                    a.cmp(b)
                });
                backends
            }
        }
    }

    fn find_nearest_region_backends(
        &self,
        _failed_region: &str,
        available_backends: &[Backend],
    ) -> Vec<String> {
        // Simplified nearest region logic - in production, this would use actual geographic distances
        available_backends.iter().map(|b| b.id.clone()).collect()
    }
}

/// Session sticky routing manager
pub struct SessionStickyManager {
    sessions: Arc<std::sync::RwLock<HashMap<String, SessionInfo>>>,
    timeout: Duration,
    fallback_algorithm: EnhancedLoadBalancingAlgorithm,
    cleanup_counter: AtomicU64,
}

#[derive(Debug, Clone)]
struct SessionInfo {
    backend_id: String,
    last_access: Instant,
    created_at: Instant,
}

impl SessionStickyManager {
    pub fn new(timeout: Duration, fallback_algorithm: EnhancedLoadBalancingAlgorithm) -> Self {
        Self {
            sessions: Arc::new(std::sync::RwLock::new(HashMap::new())),
            timeout,
            fallback_algorithm,
            cleanup_counter: AtomicU64::new(0),
        }
    }

    pub fn get_backend_for_session(
        &self,
        session_id: &str,
        available_backends: &[Backend],
    ) -> Option<String> {
        // Periodic cleanup of expired sessions
        let counter = self.cleanup_counter.fetch_add(1, Ordering::Relaxed);
        if counter % 100 == 0 {
            self.cleanup_expired_sessions();
        }

        // Check if session exists and is valid
        let backend_id = {
            let sessions = self.sessions.read().unwrap();
            if let Some(session_info) = sessions.get(session_id) {
                if session_info.last_access.elapsed() < self.timeout {
                    // Check if the backend is still available and healthy
                    if available_backends
                        .iter()
                        .any(|b| b.id == session_info.backend_id && b.healthy)
                    {
                        Some(session_info.backend_id.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(backend_id) = backend_id {
            // Update last access time
            let mut sessions = self.sessions.write().unwrap();
            if let Some(session_info) = sessions.get_mut(session_id) {
                session_info.last_access = Instant::now();
            }
            return Some(backend_id);
        }

        // No valid session found, assign new backend using fallback algorithm
        let backend_id = match &self.fallback_algorithm {
            EnhancedLoadBalancingAlgorithm::ConsistentHash { .. } => {
                // Use consistent hash for new session assignment
                self.assign_with_consistent_hash(session_id, available_backends)
            }
            _ => {
                // Use simple round-robin as fallback
                available_backends
                    .iter()
                    .find(|b| b.healthy)
                    .map(|b| b.id.clone())
            }
        };

        if let Some(ref backend) = backend_id {
            let mut sessions = self.sessions.write().unwrap();
            sessions.insert(
                session_id.to_string(),
                SessionInfo {
                    backend_id: backend.clone(),
                    last_access: Instant::now(),
                    created_at: Instant::now(),
                },
            );
        }

        backend_id
    }

    fn assign_with_consistent_hash(
        &self,
        session_id: &str,
        available_backends: &[Backend],
    ) -> Option<String> {
        if available_backends.is_empty() {
            return None;
        }

        let mut hash_ring = ConsistentHashRing::new(150, HashFunction::DefaultHash);
        for backend in available_backends.iter().filter(|b| b.healthy) {
            hash_ring.add_backend(&backend.id);
        }

        hash_ring.get_backend(session_id)
    }

    fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().unwrap();
        let now = Instant::now();
        sessions
            .retain(|_, session_info| now.duration_since(session_info.last_access) < self.timeout);
    }

    pub fn get_session_stats(&self) -> (usize, usize) {
        let sessions = self.sessions.read().unwrap();
        let total_sessions = sessions.len();
        let active_sessions = sessions
            .values()
            .filter(|s| s.last_access.elapsed() < self.timeout)
            .count();
        (total_sessions, active_sessions)
    }
}

/// Adaptive weighted load balancer with health-based adjustments
pub struct AdaptiveWeightedBalancer {
    backend_stats: HashMap<String, BackendStats>,
    adjustment_factor: f64,
    health_threshold: f64,
    response_time_weight: f64,
    last_adjustment: Instant,
}

#[derive(Debug, Clone)]
struct BackendStats {
    response_times: Vec<u64>, // Rolling window of response times in milliseconds
    success_count: u64,
    error_count: u64,
    current_weight: f64,
    original_weight: u32,
    last_updated: Instant,
}

impl AdaptiveWeightedBalancer {
    pub fn new(adjustment_factor: f64, health_threshold: f64, response_time_weight: f64) -> Self {
        Self {
            backend_stats: HashMap::new(),
            adjustment_factor,
            health_threshold,
            response_time_weight,
            last_adjustment: Instant::now(),
        }
    }

    pub fn update_backend_stats(
        &mut self,
        backend_id: &str,
        response_time_ms: u64,
        success: bool,
        original_weight: u32,
    ) {
        let stats = self
            .backend_stats
            .entry(backend_id.to_string())
            .or_insert_with(|| BackendStats {
                response_times: Vec::new(),
                success_count: 0,
                error_count: 0,
                current_weight: original_weight as f64,
                original_weight,
                last_updated: Instant::now(),
            });

        // Update response times (keep rolling window of last 100)
        stats.response_times.push(response_time_ms);
        if stats.response_times.len() > 100 {
            stats.response_times.remove(0);
        }

        // Update success/error counts
        if success {
            stats.success_count += 1;
        } else {
            stats.error_count += 1;
        }

        stats.last_updated = Instant::now();
    }

    pub fn get_adjusted_weights(&mut self, backends: &[Backend]) -> HashMap<String, u32> {
        let mut adjusted_weights = HashMap::new();

        // Only adjust weights periodically
        if self.last_adjustment.elapsed() < Duration::from_secs(10) {
            for backend in backends {
                adjusted_weights.insert(backend.id.clone(), backend.weight);
            }
            return adjusted_weights;
        }

        self.last_adjustment = Instant::now();

        for backend in backends {
            let adjusted_weight = if let Some(stats) = self.backend_stats.get(&backend.id) {
                self.calculate_adjusted_weight(stats)
            } else {
                backend.weight as f64
            };

            adjusted_weights.insert(backend.id.clone(), adjusted_weight.max(1.0) as u32);
        }

        adjusted_weights
    }

    fn calculate_adjusted_weight(&self, stats: &BackendStats) -> f64 {
        let total_requests = stats.success_count + stats.error_count;
        if total_requests == 0 {
            return stats.original_weight as f64;
        }

        // Calculate health ratio
        let health_ratio = stats.success_count as f64 / total_requests as f64;

        // Calculate average response time
        let avg_response_time = if !stats.response_times.is_empty() {
            stats.response_times.iter().sum::<u64>() as f64 / stats.response_times.len() as f64
        } else {
            100.0 // Default if no data
        };

        // Adjust weight based on health and response time
        let mut weight_multiplier = 1.0;

        // Health-based adjustment
        if health_ratio < self.health_threshold {
            weight_multiplier *= health_ratio / self.health_threshold;
        }

        // Response time-based adjustment
        let response_time_factor = (200.0 / (avg_response_time + 50.0)).min(2.0);
        weight_multiplier *= 1.0 + (response_time_factor - 1.0) * self.response_time_weight;

        // Apply adjustment factor
        let adjusted_weight = stats.original_weight as f64 * weight_multiplier;

        // Ensure weight doesn't change too drastically
        let max_change = stats.original_weight as f64 * self.adjustment_factor;
        adjusted_weight
            .max(stats.original_weight as f64 - max_change)
            .min(stats.original_weight as f64 + max_change)
    }
}

/// Priority-based load balancer with tier failover
pub struct PriorityLoadBalancer {
    tiers: Vec<PriorityTier>,
    failover_threshold: f64,
    tier_stats: HashMap<String, TierStats>,
}

#[derive(Debug)]
struct TierStats {
    healthy_backends: usize,
    total_backends: usize,
    last_check: Instant,
}

impl PriorityLoadBalancer {
    pub fn new(tiers: Vec<PriorityTier>, failover_threshold: f64) -> Self {
        Self {
            tiers,
            failover_threshold,
            tier_stats: HashMap::new(),
        }
    }

    pub fn select_tier(&mut self, backends: &[Backend]) -> Option<&PriorityTier> {
        self.update_tier_stats(backends);

        // Find the highest priority tier with sufficient healthy backends
        for tier in &self.tiers {
            if let Some(stats) = self.tier_stats.get(&tier.name) {
                let health_ratio = if stats.total_backends > 0 {
                    stats.healthy_backends as f64 / stats.total_backends as f64
                } else {
                    0.0
                };

                if health_ratio >= tier.min_healthy_ratio {
                    return Some(tier);
                }
            }
        }

        // Fallback to any tier with healthy backends
        for tier in &self.tiers {
            if let Some(stats) = self.tier_stats.get(&tier.name) {
                if stats.healthy_backends > 0 {
                    return Some(tier);
                }
            }
        }

        None
    }

    fn update_tier_stats(&mut self, backends: &[Backend]) {
        for tier in &self.tiers {
            let tier_backends: Vec<_> = backends
                .iter()
                .filter(|b| tier.backends.contains(&b.id))
                .collect();

            let healthy_backends = tier_backends.iter().filter(|b| b.healthy).count();
            let total_backends = tier_backends.len();

            self.tier_stats.insert(
                tier.name.clone(),
                TierStats {
                    healthy_backends,
                    total_backends,
                    last_check: Instant::now(),
                },
            );
        }
    }

    pub fn get_tier_stats(&self) -> &HashMap<String, TierStats> {
        &self.tier_stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_backends() -> Vec<Backend> {
        vec![
            Backend {
                id: "backend1".to_string(),
                url: "http://backend1:8080".to_string(),
                weight: 100,
                healthy: true,
                region: Some("us-east-1".to_string()),
                zone: Some("us-east-1a".to_string()),
                metadata: HashMap::new(),
            },
            Backend {
                id: "backend2".to_string(),
                url: "http://backend2:8080".to_string(),
                weight: 150,
                healthy: true,
                region: Some("us-east-1".to_string()),
                zone: Some("us-east-1b".to_string()),
                metadata: HashMap::new(),
            },
            Backend {
                id: "backend3".to_string(),
                url: "http://backend3:8080".to_string(),
                weight: 75,
                healthy: false,
                region: Some("us-west-2".to_string()),
                zone: Some("us-west-2a".to_string()),
                metadata: HashMap::new(),
            },
        ]
    }

    #[test]
    fn test_consistent_hash_ring() {
        let mut ring = ConsistentHashRing::new(100, HashFunction::DefaultHash);

        ring.add_backend("backend1");
        ring.add_backend("backend2");
        ring.add_backend("backend3");

        // Test that same key always maps to same backend
        let backend1 = ring.get_backend("user123");
        let backend2 = ring.get_backend("user123");
        assert_eq!(backend1, backend2);

        // Test that different keys can map to different backends
        let backend_a = ring.get_backend("userA");
        let backend_b = ring.get_backend("userB");
        // They might be the same, but the ring should work
        assert!(backend_a.is_some());
        assert!(backend_b.is_some());
    }

    #[test]
    fn test_session_sticky_manager() {
        let fallback = EnhancedLoadBalancingAlgorithm::ConsistentHash {
            virtual_nodes: 100,
            hash_function: HashFunction::DefaultHash,
        };

        let manager = SessionStickyManager::new(Duration::from_secs(300), fallback);
        let backends = create_test_backends();

        // First request should assign a backend
        let backend1 = manager.get_backend_for_session("session123", &backends);
        assert!(backend1.is_some());

        // Second request should return the same backend
        let backend2 = manager.get_backend_for_session("session123", &backends);
        assert_eq!(backend1, backend2);

        // Check session stats
        let (total, active) = manager.get_session_stats();
        assert_eq!(total, 1);
        assert_eq!(active, 1);
    }

    #[test]
    fn test_adaptive_weighted_balancer() {
        let mut balancer = AdaptiveWeightedBalancer::new(0.5, 0.9, 0.3);
        let backends = create_test_backends();

        // Update stats for backend1 (good performance)
        balancer.update_backend_stats("backend1", 50, true, 100);
        balancer.update_backend_stats("backend1", 60, true, 100);

        // Update stats for backend2 (poor performance)
        balancer.update_backend_stats("backend2", 200, false, 150);
        balancer.update_backend_stats("backend2", 250, false, 150);

        // Force weight adjustment by setting last_adjustment to past
        balancer.last_adjustment = Instant::now() - Duration::from_secs(20);

        let weights = balancer.get_adjusted_weights(&backends);

        // backend1 should maintain or improve its weight
        assert!(weights.get("backend1").unwrap() >= &80);

        // backend2 should have reduced weight due to poor performance
        assert!(weights.get("backend2").unwrap() < &150);
    }

    #[test]
    fn test_priority_load_balancer() {
        let tiers = vec![
            PriorityTier {
                name: "primary".to_string(),
                weight: 100,
                backends: vec!["backend1".to_string(), "backend2".to_string()],
                min_healthy_ratio: 0.5,
            },
            PriorityTier {
                name: "secondary".to_string(),
                weight: 50,
                backends: vec!["backend3".to_string()],
                min_healthy_ratio: 0.5,
            },
        ];

        let mut balancer = PriorityLoadBalancer::new(tiers, 0.8);
        let backends = create_test_backends();

        let selected_tier = balancer.select_tier(&backends);
        assert!(selected_tier.is_some());
        assert_eq!(selected_tier.unwrap().name, "primary");

        let stats = balancer.get_tier_stats();
        assert_eq!(stats.len(), 2);
        assert!(stats.contains_key("primary"));
        assert!(stats.contains_key("secondary"));
    }

    #[test]
    fn test_geo_routing_manager() {
        let mut regions = HashMap::new();
        regions.insert(
            "us-east-1".to_string(),
            vec!["backend1".to_string(), "backend2".to_string()],
        );
        regions.insert("us-west-2".to_string(), vec!["backend3".to_string()]);

        let manager = GeoRoutingManager::new(regions, GeoFallbackStrategy::HealthiestFirst);

        let east_backends = manager.get_backends_for_region("us-east-1");
        assert_eq!(east_backends.len(), 2);
        assert!(east_backends.contains(&"backend1".to_string()));

        let backends = create_test_backends();
        let fallback = manager.get_fallback_backends("us-east-1", &backends);
        assert!(!fallback.is_empty());
    }
}
