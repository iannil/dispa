use super::state::{ConnectionStats, WeightedRoundRobinState};
use crate::config::Target;
use std::collections::HashMap;

/// Load balancing algorithms implementation
pub struct LoadBalancingAlgorithms;

impl LoadBalancingAlgorithms {
    /// Round robin selection algorithm
    pub fn round_robin_select(targets: &[Target], current_index: &mut usize) -> Option<Target> {
        if targets.is_empty() {
            return None;
        }

        *current_index = (*current_index + 1) % targets.len();
        Some(targets[*current_index].clone())
    }

    /// Weighted round robin selection algorithm (smooth)
    pub fn weighted_round_robin_select(
        targets: &[Target],
        all_targets: &[Target],
        state: &mut WeightedRoundRobinState,
    ) -> Option<Target> {
        if targets.is_empty() {
            return None;
        }

        if targets.len() == 1 {
            return Some(targets[0].clone());
        }

        let mut max_weight = -1;
        let mut selected_index = 0;

        // Calculate total weight for proper normalization
        let total_weight: i32 = targets
            .iter()
            .map(|target| target.weight.unwrap_or(1.0) as i32)
            .sum();

        // Find target index mapping
        let target_indices: Vec<usize> = targets
            .iter()
            .filter_map(|target| all_targets.iter().position(|t| t.name == target.name))
            .collect();

        // Ensure state arrays are properly sized
        if state.current_weights.len() < all_targets.len() {
            state.current_weights.resize(all_targets.len(), 0);
        }

        // Find the target with the highest current weight
        for (i, &original_index) in target_indices.iter().enumerate() {
            if original_index >= all_targets.len() {
                continue; // Skip invalid indices
            }

            let weight = targets[i].weight.unwrap_or(1.0) as i32;
            state.current_weights[original_index] += weight;

            if state.current_weights[original_index] > max_weight {
                max_weight = state.current_weights[original_index];
                selected_index = i;
            }
        }

        // Decrease the selected target's current weight by total weight
        if let Some(&original_index) = target_indices.get(selected_index) {
            if original_index < state.current_weights.len() {
                state.current_weights[original_index] -= total_weight;
            }
        }

        targets.get(selected_index).cloned()
    }

    /// Random selection algorithm
    pub fn random_select(targets: &[Target]) -> Option<Target> {
        if targets.is_empty() {
            return None;
        }

        use rand::Rng;
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..targets.len());
        Some(targets[index].clone())
    }

    /// Least connections selection algorithm
    pub fn least_connections_select(
        targets: &[Target],
        connection_stats: &HashMap<String, ConnectionStats>,
    ) -> Option<Target> {
        if targets.is_empty() {
            return None;
        }

        let mut min_connections = u32::MAX;
        let mut selected_target = None;

        for target in targets {
            let connections = connection_stats
                .get(&target.name)
                .map(|s| s.active_connections)
                .unwrap_or(0);

            if connections < min_connections {
                min_connections = connections;
                selected_target = Some(target.clone());
            }
        }

        selected_target
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Target;

    fn create_test_target(name: &str, weight: Option<f64>) -> Target {
        Target {
            name: name.to_string(),
            url: format!("http://test-{}.com", name),
            address: format!("test-{}.com:80", name),
            weight,
            timeout: Some(30),
        }
    }

    #[test]
    fn test_round_robin_algorithm() {
        let targets = vec![
            create_test_target("server1", None),
            create_test_target("server2", None),
            create_test_target("server3", None),
        ];

        let mut index = 0;

        let selected1 = LoadBalancingAlgorithms::round_robin_select(&targets, &mut index).unwrap();
        let selected2 = LoadBalancingAlgorithms::round_robin_select(&targets, &mut index).unwrap();
        let selected3 = LoadBalancingAlgorithms::round_robin_select(&targets, &mut index).unwrap();
        let selected4 = LoadBalancingAlgorithms::round_robin_select(&targets, &mut index).unwrap();

        assert_eq!(selected1.name, "server2"); // Index starts at 0, increments to 1
        assert_eq!(selected2.name, "server3"); // Index 2
        assert_eq!(selected3.name, "server1"); // Index 0 (wrapped)
        assert_eq!(selected4.name, "server2"); // Index 1
    }

    #[test]
    fn test_random_algorithm() {
        let targets = vec![
            create_test_target("server1", None),
            create_test_target("server2", None),
            create_test_target("server3", None),
        ];

        // Test that random selection returns valid targets
        for _ in 0..10 {
            let selected = LoadBalancingAlgorithms::random_select(&targets).unwrap();
            assert!(targets.iter().any(|t| t.name == selected.name));
        }
    }

    #[test]
    fn test_least_connections_algorithm() {
        let targets = vec![
            create_test_target("server1", None),
            create_test_target("server2", None),
            create_test_target("server3", None),
        ];

        let mut stats = HashMap::new();
        stats.insert(
            "server1".to_string(),
            ConnectionStats {
                active_connections: 5,
                ..Default::default()
            },
        );
        stats.insert(
            "server2".to_string(),
            ConnectionStats {
                active_connections: 2, // Least connections
                ..Default::default()
            },
        );
        stats.insert(
            "server3".to_string(),
            ConnectionStats {
                active_connections: 8,
                ..Default::default()
            },
        );

        let selected = LoadBalancingAlgorithms::least_connections_select(&targets, &stats).unwrap();
        assert_eq!(selected.name, "server2");
    }

    #[test]
    fn test_empty_targets() {
        let targets = vec![];
        let mut index = 0;
        let stats = HashMap::new();
        let mut state = WeightedRoundRobinState::new(0, 0);

        assert!(LoadBalancingAlgorithms::round_robin_select(&targets, &mut index).is_none());
        assert!(LoadBalancingAlgorithms::random_select(&targets).is_none());
        assert!(LoadBalancingAlgorithms::least_connections_select(&targets, &stats).is_none());
        assert!(LoadBalancingAlgorithms::weighted_round_robin_select(
            &targets, &targets, &mut state
        )
        .is_none());
    }
}
