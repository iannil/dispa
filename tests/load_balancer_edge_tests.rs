use dispa::balancer::load_balancer::LoadBalancer;
use dispa::config::{
    HealthCheckConfig, LoadBalancingConfig, LoadBalancingType, Target, TargetConfig,
};
// no extra imports needed

/// Test load balancer edge cases and boundary conditions
mod load_balancer_edge_tests {
    use super::*;

    /// Test load balancer with empty target list
    #[tokio::test]
    async fn test_empty_targets_list() {
        let config = TargetConfig {
            targets: vec![], // Empty targets
            load_balancing: LoadBalancingConfig {
                algorithm: LoadBalancingType::RoundRobin,
                lb_type: LoadBalancingType::RoundRobin,
                sticky_sessions: None,
            },
            health_check: HealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
        };

        let load_balancer = LoadBalancer::new(config);

        // Should return None when no targets available
        let target = load_balancer.get_target().await;
        assert!(target.is_none(), "Should return None for empty targets");

        // Healthy targets should also be empty
        let healthy_targets = load_balancer.get_healthy_targets().await;
        assert!(healthy_targets.is_empty(), "Should have no healthy targets");
    }

    /// Test load balancer with single target
    #[tokio::test]
    async fn test_single_target_all_algorithms() {
        let single_target = Target {
            name: "single-target".to_string(),
            address: "http://localhost:8000".to_string(),
            url: "http://localhost:8000".to_string(),
            weight: Some(1.0),
            timeout: Some(30),
        };

        let algorithms = vec![
            LoadBalancingType::RoundRobin,
            LoadBalancingType::Random,
            LoadBalancingType::WeightedRoundRobin,
            LoadBalancingType::LeastConnections,
        ];

        for algorithm in algorithms {
            let config = TargetConfig {
                targets: vec![single_target.clone()],
                load_balancing: LoadBalancingConfig {
                    algorithm: algorithm.clone(),
                    lb_type: algorithm.clone(),
                    sticky_sessions: None,
                },
                health_check: HealthCheckConfig {
                    enabled: false,
                    ..Default::default()
                },
            };

            let load_balancer = LoadBalancer::new(config);

            // Should always return the single target
            for _ in 0..5 {
                let target = load_balancer.get_target().await;
                assert!(target.is_some(), "Should return target for {:?}", algorithm);
                assert_eq!(target.unwrap().name, "single-target");
            }
        }
    }

    /// Test weighted round robin with extreme weights
    #[tokio::test]
    async fn test_weighted_extreme_weights() {
        let targets = vec![
            Target {
                name: "heavy-target".to_string(),
                address: "http://localhost:8001".to_string(),
                url: "http://localhost:8001".to_string(),
                weight: Some(1000.0), // Very high weight
                timeout: Some(30),
            },
            Target {
                name: "light-target".to_string(),
                address: "http://localhost:8002".to_string(),
                url: "http://localhost:8002".to_string(),
                weight: Some(1.0), // Very low weight
                timeout: Some(30),
            },
        ];

        let config = TargetConfig {
            targets,
            load_balancing: LoadBalancingConfig {
                algorithm: LoadBalancingType::WeightedRoundRobin,
                lb_type: LoadBalancingType::WeightedRoundRobin,
                sticky_sessions: None,
            },
            health_check: HealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
        };

        let load_balancer = LoadBalancer::new(config);

        // Collect selections over many iterations
        let mut heavy_count = 0;
        let mut light_count = 0;
        let total_selections = 1001;

        for _ in 0..total_selections {
            if let Some(target) = load_balancer.get_target().await {
                match target.name.as_str() {
                    "heavy-target" => heavy_count += 1,
                    "light-target" => light_count += 1,
                    _ => panic!("Unexpected target name"),
                }
            }
        }

        // Heavy target should be selected much more frequently
        // Allowing some margin for randomness in implementation
        assert!(
            heavy_count > light_count * 50,
            "Heavy target should be selected much more: {} vs {}",
            heavy_count,
            light_count
        );
    }

    /// Test load balancer with zero weight targets
    #[tokio::test]
    async fn test_zero_weight_targets() {
        let targets = vec![
            Target {
                name: "normal-target".to_string(),
                address: "http://localhost:8001".to_string(),
                url: "http://localhost:8001".to_string(),
                weight: Some(1.0),
                timeout: Some(30),
            },
            Target {
                name: "zero-weight-target".to_string(),
                address: "http://localhost:8002".to_string(),
                url: "http://localhost:8002".to_string(),
                weight: Some(0.0), // Zero weight
                timeout: Some(30),
            },
        ];

        let config = TargetConfig {
            targets,
            load_balancing: LoadBalancingConfig {
                algorithm: LoadBalancingType::WeightedRoundRobin,
                lb_type: LoadBalancingType::WeightedRoundRobin,
                sticky_sessions: None,
            },
            health_check: HealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
        };

        let load_balancer = LoadBalancer::new(config);

        // Should never select zero-weight target
        for _ in 0..50 {
            if let Some(target) = load_balancer.get_target().await {
                assert_ne!(
                    target.name, "zero-weight-target",
                    "Zero weight target should not be selected"
                );
            }
        }
    }

    /// Test rapid concurrent target selection
    #[tokio::test]
    async fn test_concurrent_target_selection() {
        let targets = vec![
            Target {
                name: "target-1".to_string(),
                address: "http://localhost:8001".to_string(),
                url: "http://localhost:8001".to_string(),
                weight: Some(1.0),
                timeout: Some(30),
            },
            Target {
                name: "target-2".to_string(),
                address: "http://localhost:8002".to_string(),
                url: "http://localhost:8002".to_string(),
                weight: Some(1.0),
                timeout: Some(30),
            },
        ];

        let config = TargetConfig {
            targets,
            load_balancing: LoadBalancingConfig {
                algorithm: LoadBalancingType::RoundRobin,
                lb_type: LoadBalancingType::RoundRobin,
                sticky_sessions: None,
            },
            health_check: HealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
        };

        let load_balancer = std::sync::Arc::new(LoadBalancer::new(config));

        // Spawn multiple concurrent tasks selecting targets
        let mut handles = vec![];
        for _ in 0..10 {
            let lb = load_balancer.clone();
            let handle = tokio::spawn(async move {
                for _ in 0..100 {
                    lb.get_target().await;
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.expect("Task should complete successfully");
        }

        // Load balancer should still be functional
        let target = load_balancer.get_target().await;
        assert!(
            target.is_some(),
            "Load balancer should still work after concurrent access"
        );
    }
}
