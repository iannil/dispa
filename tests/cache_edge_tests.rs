use dispa::cache::{CacheConfig, CacheEntry, InMemoryCache};
use hyper::{HeaderMap, StatusCode};
use std::time::Duration;
use tokio::time::sleep;

/// Test cache system edge cases and boundary conditions
mod cache_edge_tests {
    use super::*;

    /// Helper function to create a test cache entry
    fn create_test_entry(data: &str, ttl_secs: u64) -> CacheEntry {
        CacheEntry::new(
            StatusCode::OK,
            HeaderMap::new(),
            data.as_bytes().to_vec(),
            Duration::from_secs(ttl_secs),
        )
    }

    /// Test cache with zero max size
    #[tokio::test]
    async fn test_cache_zero_max_size() {
        let config = CacheConfig {
            enabled: true,
            max_size: 0, // Zero size should reject all entries
            default_ttl: 3600,
            policies: vec![],
            enable_etag: false,
            key_prefix: None,
            enable_metrics: true,
        };

        let cache = InMemoryCache::new(config);

        let entry = create_test_entry("test data", 300);
        let result = cache.put("test-key".to_string(), entry).await;

        // Should succeed but entry won't be stored due to size limit
        assert!(result.is_ok());

        // Should not be able to retrieve the entry
        let retrieved = cache.get("test-key").await;
        assert!(
            retrieved.is_none(),
            "Entry should not be stored with zero max size"
        );
    }

    /// Test cache with very small max size
    #[tokio::test]
    async fn test_cache_small_max_size() {
        let config = CacheConfig {
            enabled: true,
            max_size: 10, // Very small size - only 10 bytes
            default_ttl: 3600,
            policies: vec![],
            enable_etag: false,
            key_prefix: None,
            enable_metrics: true,
        };

        let cache = InMemoryCache::new(config);

        // Try to store entry larger than max size
        let large_entry = create_test_entry("This is much larger than 10 bytes", 300);
        let result = cache.put("large-key".to_string(), large_entry).await;
        assert!(result.is_ok());

        // Should not be retrievable
        let retrieved = cache.get("large-key").await;
        assert!(retrieved.is_none(), "Large entry should not be stored");

        // Small entry should work
        let small_entry = create_test_entry("tiny", 300);
        let result = cache.put("small-key".to_string(), small_entry).await;
        assert!(result.is_ok());

        let retrieved = cache.get("small-key").await;
        assert!(retrieved.is_some(), "Small entry should be stored");
    }

    /// Test cache entry expiration edge cases
    #[tokio::test]
    async fn test_cache_expiration_edge_cases() {
        let config = CacheConfig {
            enabled: true,
            max_size: 1024,
            default_ttl: 1, // Very short default TTL
            policies: vec![],
            enable_etag: false,
            key_prefix: None,
            enable_metrics: true,
        };

        let cache = InMemoryCache::new(config);

        // Entry with zero TTL
        let zero_ttl_entry = create_test_entry("zero ttl", 0);
        cache
            .put("zero-ttl".to_string(), zero_ttl_entry)
            .await
            .unwrap();

        // Should be immediately expired
        let retrieved = cache.get("zero-ttl").await;
        assert!(
            retrieved.is_none(),
            "Zero TTL entry should be expired immediately"
        );

        // Entry with very short TTL
        let short_ttl_entry = create_test_entry("short ttl", 1);
        cache
            .put("short-ttl".to_string(), short_ttl_entry)
            .await
            .unwrap();

        // Should be available immediately
        let retrieved = cache.get("short-ttl").await;
        assert!(retrieved.is_some(), "Entry should be available immediately");

        // Wait for expiration
        sleep(Duration::from_millis(1100)).await;

        // Should now be expired
        let retrieved = cache.get("short-ttl").await;
        assert!(retrieved.is_none(), "Entry should be expired after TTL");
    }

    /// Test cache with many small entries (stress test)
    #[tokio::test]
    async fn test_cache_many_small_entries() {
        let config = CacheConfig {
            enabled: true,
            max_size: 10_000, // 10KB
            default_ttl: 3600,
            policies: vec![],
            enable_etag: false,
            key_prefix: None,
            enable_metrics: true,
        };

        let cache = InMemoryCache::new(config);

        // Add many small entries
        let num_entries = 1000;
        for i in 0..num_entries {
            let entry = create_test_entry(&format!("data-{}", i), 300);
            let result = cache.put(format!("key-{}", i), entry).await;
            assert!(result.is_ok(), "Failed to store entry {}", i);
        }

        // Verify some entries are still accessible
        // (some might have been evicted due to size limits)
        let mut found_count = 0;
        for i in 0..num_entries {
            if cache.get(&format!("key-{}", i)).await.is_some() {
                found_count += 1;
            }
        }

        assert!(found_count > 0, "At least some entries should be found");

        // Check cache stats
        let metrics = cache.get_metrics().await;
        assert!(
            metrics.total_requests() > 0,
            "Should have recorded requests"
        );
    }

    /// Test concurrent cache operations
    #[tokio::test]
    async fn test_concurrent_cache_operations() {
        let config = CacheConfig {
            enabled: true,
            max_size: 1024 * 1024, // 1MB
            default_ttl: 3600,
            policies: vec![],
            enable_etag: false,
            key_prefix: None,
            enable_metrics: true,
        };

        let cache = std::sync::Arc::new(InMemoryCache::new(config));

        // Spawn multiple tasks doing different operations
        let mut handles = vec![];

        // Writer tasks
        for i in 0..5 {
            let cache_clone = cache.clone();
            let handle = tokio::spawn(async move {
                for j in 0..50 {
                    let key = format!("writer-{}-key-{}", i, j);
                    let entry = create_test_entry(&format!("data-{}-{}", i, j), 300);
                    cache_clone.put(key, entry).await.unwrap();
                }
            });
            handles.push(handle);
        }

        // Reader tasks
        for i in 0..5 {
            let cache_clone = cache.clone();
            let handle = tokio::spawn(async move {
                for j in 0..50 {
                    let key = format!("writer-{}-key-{}", i % 5, j);
                    let _ = cache_clone.get(&key).await;
                }
            });
            handles.push(handle);
        }

        // Cleanup task
        let cache_clone = cache.clone();
        let cleanup_handle = tokio::spawn(async move {
        for _i in 0..10 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                cache_clone.clear().await;
            }
        });
        handles.push(cleanup_handle);

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.expect("Task should complete successfully");
        }

        // Cache should still be functional
        let test_entry = create_test_entry("final test", 300);
        let result = cache.put("final-test".to_string(), test_entry).await;
        assert!(
            result.is_ok(),
            "Cache should still work after concurrent operations"
        );
    }

    /// Test cache key edge cases
    #[tokio::test]
    async fn test_cache_key_edge_cases() {
        let config = CacheConfig {
            enabled: true,
            max_size: 1024,
            default_ttl: 3600,
            policies: vec![],
            enable_etag: false,
            key_prefix: None,
            enable_metrics: true,
        };

        let cache = InMemoryCache::new(config);

        // Test various key formats
        let test_cases = vec![
            ("", "empty key"),
            ("a", "single character"),
            (
                "very-long-key-with-many-characters-and-special-symbols-123-!@#$%^&*()",
                "long key with special chars",
            ),
            ("key with spaces", "key with spaces"),
            ("key\nwith\nnewlines", "key with newlines"),
            ("key\twith\ttabs", "key with tabs"),
            ("普通话", "unicode key"),
            ("🚀🌟💫", "emoji key"),
        ];

        for (key, description) in test_cases {
            let entry = create_test_entry(&format!("data for {}", description), 300);
            let result = cache.put(key.to_string(), entry).await;
            assert!(result.is_ok(), "Failed to store entry with {}", description);

            let retrieved = cache.get(key).await;
            assert!(
                retrieved.is_some(),
                "Failed to retrieve entry with {}",
                description
            );
        }
    }

    /// Test cache disabled state
    #[tokio::test]
    async fn test_cache_disabled_operations() {
        let config = CacheConfig {
            enabled: false, // Disabled cache
            max_size: 1024,
            default_ttl: 3600,
            policies: vec![],
            enable_etag: false,
            key_prefix: None,
            enable_metrics: true,
        };

        let cache = InMemoryCache::new(config);

        // All operations should be no-ops when disabled
        let entry = create_test_entry("test data", 300);
        let result = cache.put("test-key".to_string(), entry).await;
        assert!(result.is_ok(), "Put should succeed even when disabled");

        let retrieved = cache.get("test-key").await;
        assert!(
            retrieved.is_none(),
            "Get should return None when cache is disabled"
        );

        let contains = cache.contains_key("test-key").await;
        assert!(
            !contains,
            "Contains should return false when cache is disabled"
        );

        let keys = cache.keys().await;
        assert!(
            keys.is_empty(),
            "Keys should be empty when cache is disabled"
        );

        // Stats should still work
        let stats = cache.stats().await;
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 1); // The get call above should count as a miss
    }

    /// Test cache metrics accuracy under various conditions
    #[tokio::test]
    async fn test_cache_metrics_accuracy() {
        let config = CacheConfig {
            enabled: true,
            max_size: 1024,
            default_ttl: 3600,
            policies: vec![],
            enable_etag: false,
            key_prefix: None,
            enable_metrics: true,
        };

        let cache = InMemoryCache::new(config);

        // Initial state
        let stats = cache.stats().await;
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);

        // Add some entries
        for i in 0..5 {
            let entry = create_test_entry(&format!("data-{}", i), 300);
            cache.put(format!("key-{}", i), entry).await.unwrap();
        }

        // Test hits and misses
        let _ = cache.get("key-1").await; // Hit
        let _ = cache.get("key-2").await; // Hit
        let _ = cache.get("nonexistent").await; // Miss
        let _ = cache.get("also-missing").await; // Miss

        let stats = cache.stats().await;
        assert_eq!(stats.hits, 2, "Should have 2 hits");
        assert_eq!(stats.misses, 2, "Should have 2 misses");

        let metrics = cache.get_metrics().await;
        assert_eq!(metrics.hit_ratio(), 0.5, "Hit ratio should be 50%");
        assert_eq!(metrics.total_requests(), 4, "Total requests should be 4");
    }
}
