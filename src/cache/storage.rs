use crate::cache::{CacheConfig, CacheEntry};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, info, warn};

/// In-memory cache storage with TTL support
#[derive(Clone)]
pub struct InMemoryCache {
    /// Cache storage
    storage: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Cache configuration
    config: CacheConfig,
    /// Cache metrics
    metrics: Arc<RwLock<CacheMetrics>>,
    /// Maximum cache size in bytes
    max_size: u64,
    /// Current cache size in bytes
    current_size: Arc<RwLock<u64>>,
}

impl InMemoryCache {
    /// Create a new in-memory cache
    pub fn new(config: CacheConfig) -> Self {
        let cache = Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
            max_size: config.max_size,
            config,
            metrics: Arc::new(RwLock::new(CacheMetrics::default())),
            current_size: Arc::new(RwLock::new(0)),
        };

        // Start cleanup task
        if cache.config.enabled {
            cache.start_cleanup_task();
        }

        cache
    }

    /// Get a cached entry
    pub async fn get(&self, key: &str) -> Option<CacheEntry> {
        if !self.config.enabled {
            return None;
        }

        let storage = self.storage.read().await;

        if let Some(entry) = storage.get(key) {
            if entry.is_expired() {
                // Entry is expired, will be cleaned up later
                self.record_miss().await;
                None
            } else {
                self.record_hit().await;
                Some(entry.clone())
            }
        } else {
            self.record_miss().await;
            None
        }
    }

    /// Store an entry in the cache
    pub async fn put(&self, key: String, entry: CacheEntry) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let entry_size = entry.size as u64;

        // Check if we need to evict entries to make space
        if let Err(e) = self.ensure_space(entry_size).await {
            warn!("Failed to ensure space for cache entry: {}", e);
            return Err(e);
        }

        // Store the entry
        {
            let mut storage = self.storage.write().await;

            // If key already exists, subtract old size first
            if let Some(old_entry) = storage.get(&key) {
                let mut current_size = self.current_size.write().await;
                *current_size -= old_entry.size as u64;
            }

            storage.insert(key, entry);
        }

        // Update current size
        {
            let mut current_size = self.current_size.write().await;
            *current_size += entry_size;
        }

        // Update metrics
        self.record_store().await;

        debug!("Stored cache entry of size {} bytes", entry_size);
        Ok(())
    }

    /// Remove an entry from the cache
    pub async fn remove(&self, key: &str) -> Option<CacheEntry> {
        if !self.config.enabled {
            return None;
        }

        let mut storage = self.storage.write().await;

        if let Some(entry) = storage.remove(key) {
            // Update current size
            {
                let mut current_size = self.current_size.write().await;
                *current_size -= entry.size as u64;
            }

            debug!("Removed cache entry for key: {}", key);
            Some(entry)
        } else {
            None
        }
    }

    /// Clear all cache entries
    pub async fn clear(&self) {
        let mut storage = self.storage.write().await;
        storage.clear();

        let mut current_size = self.current_size.write().await;
        *current_size = 0;

        info!("Cache cleared");
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let storage = self.storage.read().await;
        let metrics = self.metrics.read().await;
        let current_size = *self.current_size.read().await;

        CacheStats {
            entry_count: storage.len(),
            total_size: current_size,
            max_size: self.max_size,
            hit_ratio: metrics.hit_ratio(),
            hits: metrics.hits,
            misses: metrics.misses,
            stores: metrics.stores,
            evictions: metrics.evictions,
        }
    }

    /// Get cache metrics for monitoring
    pub async fn get_metrics(&self) -> CacheMetrics {
        let metrics = self.metrics.read().await;
        let mut result = metrics.clone();

        // Update current state metrics
        let storage = self.storage.read().await;
        result.entry_count = storage.len() as u64;
        result.current_size = *self.current_size.read().await;

        result
    }

    /// Check if the cache contains a key
    pub async fn contains_key(&self, key: &str) -> bool {
        if !self.config.enabled {
            return false;
        }

        let storage = self.storage.read().await;

        if let Some(entry) = storage.get(key) {
            !entry.is_expired()
        } else {
            false
        }
    }

    /// Get all cache keys (for debugging/monitoring)
    pub async fn keys(&self) -> Vec<String> {
        let storage = self.storage.read().await;
        storage.keys().cloned().collect()
    }

    /// Ensure there's enough space for a new entry
    async fn ensure_space(&self, needed_size: u64) -> Result<()> {
        let current_size = *self.current_size.read().await;

        if current_size + needed_size <= self.max_size {
            return Ok(());
        }

        // Need to evict entries
        let target_size = self.max_size - needed_size;
        self.evict_until_size(target_size).await
    }

    /// Evict entries until cache size is below target
    async fn evict_until_size(&self, target_size: u64) -> Result<()> {
        let mut storage = self.storage.write().await;
        let mut current_size = self.current_size.write().await;

        // Collect entries with their last access time (using creation time as proxy)
        let mut entries: Vec<(String, SystemTime, u64)> = storage
            .iter()
            .map(|(key, entry)| (key.clone(), entry.created_at, entry.size as u64))
            .collect();

        // Sort by creation time (LRU approximation)
        entries.sort_by_key(|(_, created_at, _)| *created_at);

        let mut evicted_count = 0;

        // Remove oldest entries until we reach target size
        for (key, _, entry_size) in entries {
            if *current_size <= target_size {
                break;
            }

            storage.remove(&key);
            *current_size -= entry_size;
            evicted_count += 1;

            debug!("Evicted cache entry: {} (size: {} bytes)", key, entry_size);
        }

        if evicted_count > 0 {
            // Update metrics
            let mut metrics = self.metrics.write().await;
            metrics.evictions += evicted_count;

            info!("Evicted {} cache entries to free space", evicted_count);
        }

        Ok(())
    }

    /// Start background cleanup task
    fn start_cleanup_task(&self) {
        let storage = Arc::clone(&self.storage);
        let current_size = Arc::clone(&self.current_size);
        let metrics = Arc::clone(&self.metrics);

        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(60)); // Run every minute

            loop {
                cleanup_interval.tick().await;

                let mut removed_count = 0;
                let mut removed_size = 0u64;

                // Clean up expired entries
                {
                    let mut storage_guard = storage.write().await;
                    let mut to_remove = Vec::new();

                    for (key, entry) in storage_guard.iter() {
                        if entry.is_expired() {
                            to_remove.push((key.clone(), entry.size as u64));
                        }
                    }

                    for (key, size) in to_remove {
                        storage_guard.remove(&key);
                        removed_size += size;
                        removed_count += 1;
                    }
                }

                // Update current size
                if removed_size > 0 {
                    let mut current_size_guard = current_size.write().await;
                    *current_size_guard -= removed_size;
                }

                // Update metrics
                if removed_count > 0 {
                    let mut metrics_guard = metrics.write().await;
                    metrics_guard.expired_cleaned += removed_count;

                    debug!(
                        "Cleaned up {} expired cache entries (freed {} bytes)",
                        removed_count, removed_size
                    );
                }
            }
        });
    }

    /// Record a cache hit
    async fn record_hit(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.hits += 1;
    }

    /// Record a cache miss
    async fn record_miss(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.misses += 1;
    }

    /// Record a cache store
    async fn record_store(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.stores += 1;
    }
}

/// Cache statistics for monitoring
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of entries in cache
    pub entry_count: usize,
    /// Total size in bytes
    pub total_size: u64,
    /// Maximum size in bytes
    pub max_size: u64,
    /// Hit ratio as percentage
    pub hit_ratio: f64,
    /// Total cache hits
    pub hits: u64,
    /// Total cache misses
    pub misses: u64,
    /// Total stores
    pub stores: u64,
    /// Total evictions
    pub evictions: u64,
}

/// Cache metrics for detailed monitoring
#[derive(Debug, Clone, Default)]
pub struct CacheMetrics {
    /// Total number of cache hits
    pub hits: u64,
    /// Total number of cache misses
    pub misses: u64,
    /// Total number of cache stores
    pub stores: u64,
    /// Total number of cache evictions
    pub evictions: u64,
    /// Current cache size in bytes
    pub current_size: u64,
    /// Number of cached entries
    pub entry_count: u64,
    /// Number of expired entries cleaned up
    pub expired_cleaned: u64,
}

impl CacheMetrics {
    /// Calculate hit ratio as percentage
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total > 0 {
            (self.hits as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }

    /// Get total requests (hits + misses)
    pub fn total_requests(&self) -> u64 {
        self.hits + self.misses
    }
}

impl CacheStats {
    /// Get cache utilization as percentage
    pub fn utilization_percent(&self) -> f64 {
        if self.max_size > 0 {
            (self.total_size as f64 / self.max_size as f64) * 100.0
        } else {
            0.0
        }
    }

    /// Get average entry size
    pub fn average_entry_size(&self) -> f64 {
        if self.entry_count > 0 {
            self.total_size as f64 / self.entry_count as f64
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheEntry;
    use hyper::{HeaderMap, StatusCode};
    use tokio::time::{sleep, Duration};

    fn create_test_config() -> CacheConfig {
        CacheConfig {
            enabled: true,
            max_size: 1024, // 1KB for testing
            default_ttl: 60,
            policies: vec![],
            etag_enabled: true,
            key_prefix: None,
            metrics_enabled: true,
        }
    }

    fn create_test_entry(body: &str, ttl_secs: u64) -> CacheEntry {
        CacheEntry::new(
            StatusCode::OK,
            HeaderMap::new(),
            body.as_bytes().to_vec(),
            Duration::from_secs(ttl_secs),
        )
    }

    #[tokio::test]
    async fn test_cache_creation() {
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let config = create_test_config();
            let cache = InMemoryCache::new(config);
            let stats = cache.stats().await;
            assert_eq!(stats.entry_count, 0);
            assert_eq!(stats.total_size, 0);
            assert_eq!(stats.max_size, 1024);
        })
        .await
        .expect("test_cache_creation timed out");
    }

    #[tokio::test]
    async fn test_cache_put_and_get() {
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let config = create_test_config();
            let cache = InMemoryCache::new(config);

            let entry = create_test_entry("test data", 60);
            let key = "test_key".to_string();

            // Store entry
            cache.put(key.clone(), entry.clone()).await.unwrap();

            // Retrieve entry
            let retrieved = cache.get(&key).await.unwrap();
            assert_eq!(retrieved.body, entry.body);
            assert_eq!(retrieved.status, entry.status);

            // Check stats
            let stats = cache.stats().await;
            assert_eq!(stats.entry_count, 1);
            assert!(stats.total_size > 0);
            assert_eq!(stats.hits, 1);
            assert_eq!(stats.stores, 1);
        })
        .await
        .expect("test_cache_put_and_get timed out");
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let config = create_test_config();
            let cache = InMemoryCache::new(config);

            let result = cache.get("nonexistent").await;
            assert!(result.is_none());

            let stats = cache.stats().await;
            assert_eq!(stats.misses, 1);
        })
        .await
        .expect("test_cache_miss timed out");
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let config = create_test_config();
            let cache = InMemoryCache::new(config);

            // Create entry with very short TTL
            let entry = create_test_entry("test data", 0); // 0 seconds TTL
            let key = "test_key".to_string();

            cache.put(key.clone(), entry).await.unwrap();

            // Wait a bit to ensure expiration
            sleep(Duration::from_millis(10)).await;

            // Should not retrieve expired entry
            let result = cache.get(&key).await;
            assert!(result.is_none());

            let stats = cache.stats().await;
            assert_eq!(stats.misses, 1); // Should count as miss
        })
        .await
        .expect("test_cache_expiration timed out");
    }

    #[tokio::test]
    async fn test_cache_remove() {
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let config = create_test_config();
            let cache = InMemoryCache::new(config);

            let entry = create_test_entry("test data", 60);
            let key = "test_key".to_string();

            cache.put(key.clone(), entry).await.unwrap();

            // Remove entry
            let removed = cache.remove(&key).await.unwrap();
            assert_eq!(removed.body, b"test data");

            // Should not find entry after removal
            let result = cache.get(&key).await;
            assert!(result.is_none());

            let stats = cache.stats().await;
            assert_eq!(stats.entry_count, 0);
            assert_eq!(stats.total_size, 0);
        })
        .await
        .expect("test_cache_remove timed out");
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let config = create_test_config();
            let cache = InMemoryCache::new(config);

            // Add multiple entries
            for i in 0..3 {
                let entry = create_test_entry(&format!("data{}", i), 60);
                cache.put(format!("key{}", i), entry).await.unwrap();
            }

            let stats_before = cache.stats().await;
            assert_eq!(stats_before.entry_count, 3);

            // Clear cache
            cache.clear().await;

            let stats_after = cache.stats().await;
            assert_eq!(stats_after.entry_count, 0);
            assert_eq!(stats_after.total_size, 0);
        })
        .await
        .expect("test_cache_clear timed out");
    }

    #[tokio::test]
    async fn test_cache_size_limit_eviction() {
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let config = create_test_config(); // 1KB limit
            let cache = InMemoryCache::new(config);

            // Create entries that will exceed the limit
            let large_data = "x".repeat(400); // 400 bytes each

            // Add entries until we exceed the limit
            for i in 0..4 {
                let entry = create_test_entry(&large_data, 60);
                cache.put(format!("key{}", i), entry).await.unwrap();
            }

            let stats = cache.stats().await;
            assert!(stats.total_size <= 1024); // Should not exceed limit
            assert!(stats.evictions > 0); // Should have evicted some entries
            assert!(stats.entry_count < 4); // Should have fewer than 4 entries
        })
        .await
        .expect("test_cache_size_limit_eviction timed out");
    }

    #[tokio::test]
    async fn test_cache_contains_key() {
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let config = create_test_config();
            let cache = InMemoryCache::new(config);

            let entry = create_test_entry("test data", 60);
            let key = "test_key".to_string();

            assert!(!cache.contains_key(&key).await);

            cache.put(key.clone(), entry).await.unwrap();
            assert!(cache.contains_key(&key).await);

            cache.remove(&key).await;
            assert!(!cache.contains_key(&key).await);
        })
        .await
        .expect("test_cache_contains_key timed out");
    }

    #[tokio::test]
    async fn test_cache_disabled() {
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let mut config = create_test_config();
            config.enabled = false;
            let cache = InMemoryCache::new(config);

            let entry = create_test_entry("test data", 60);
            let key = "test_key".to_string();

            // Operations should succeed but do nothing
            cache.put(key.clone(), entry).await.unwrap();

            let result = cache.get(&key).await;
            assert!(result.is_none());

            assert!(!cache.contains_key(&key).await);

            let stats = cache.stats().await;
            assert_eq!(stats.entry_count, 0);
        })
        .await
        .expect("test_cache_disabled timed out");
    }

    #[tokio::test]
    async fn test_cache_metrics() {
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let config = create_test_config();
            let cache = InMemoryCache::new(config);

            let entry = create_test_entry("test data", 60);

            // Perform various operations
            cache.put("key1".to_string(), entry.clone()).await.unwrap();
            cache.put("key2".to_string(), entry).await.unwrap();

            cache.get("key1").await; // hit
            cache.get("key2").await; // hit
            cache.get("key3").await; // miss

            let metrics = cache.get_metrics().await;
            assert_eq!(metrics.hits, 2);
            assert_eq!(metrics.misses, 1);
            assert_eq!(metrics.stores, 2);
            assert_eq!(metrics.entry_count, 2);
            assert!(metrics.current_size > 0);

            let hit_ratio = metrics.hit_ratio();
            assert!((hit_ratio - 66.67).abs() < 0.1); // Approximately 66.67%
        })
        .await
        .expect("test_cache_metrics timed out");
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let config = create_test_config();
            let cache = InMemoryCache::new(config);

            let entry = create_test_entry("test data", 60);
            cache.put("key1".to_string(), entry).await.unwrap();

            let stats = cache.stats().await;
            assert_eq!(stats.entry_count, 1);
            assert!(stats.total_size > 0);
            assert_eq!(stats.max_size, 1024);

            let utilization = stats.utilization_percent();
            assert!(utilization > 0.0 && utilization <= 100.0);

            let avg_size = stats.average_entry_size();
            assert!(avg_size > 0.0);
        })
        .await
        .expect("test_cache_stats timed out");
    }
}
