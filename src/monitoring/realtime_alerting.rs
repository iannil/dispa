//! Real-time monitoring and alerting system
//!
//! This module provides comprehensive monitoring and alerting capabilities:
//! - Real-time metrics collection and aggregation
//! - Customizable alerting rules and thresholds
//! - Multiple notification channels (email, slack, webhook, etc.)
//! - Performance anomaly detection
//! - Service health dashboards and SLA monitoring

// Backend type available when needed
// HTTP types available when needed
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
// Atomic types available when needed
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, RwLock};
use tokio::time::interval;
use tracing::{error, info};

/// Real-time monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealTimeMonitoringConfig {
    /// Enable real-time monitoring
    pub enabled: bool,
    /// Metrics collection interval (seconds)
    pub collection_interval: u64,
    /// Metrics retention period (hours)
    pub retention_hours: u64,
    /// Alert configuration
    pub alerting: AlertConfig,
    /// Dashboard configuration
    pub dashboard: DashboardConfig,
    /// SLA monitoring
    pub sla_monitoring: SlaMonitoringConfig,
    /// Anomaly detection
    pub anomaly_detection: AnomalyDetectionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable alerting
    pub enabled: bool,
    /// Alert rules
    pub rules: Vec<AlertRule>,
    /// Notification channels
    pub channels: Vec<NotificationChannel>,
    /// Default severity for unmatched alerts
    pub default_severity: AlertSeverity,
    /// Alert aggregation window (seconds)
    pub aggregation_window: u64,
    /// Maximum alerts per minute
    pub rate_limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Rule ID
    pub id: String,
    /// Rule name
    pub name: String,
    /// Metric to monitor
    pub metric: String,
    /// Threshold value
    pub threshold: f64,
    /// Comparison operator (gt, lt, eq, ne, gte, lte)
    pub operator: String,
    /// Evaluation window (seconds)
    pub window: u64,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert description template
    pub description: String,
    /// Notification channels for this rule
    pub channels: Vec<String>,
    /// Enable/disable rule
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannel {
    /// Channel ID
    pub id: String,
    /// Channel type (email, slack, webhook, teams, discord)
    pub channel_type: String,
    /// Channel configuration
    pub config: HashMap<String, String>,
    /// Enable/disable channel
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Enable dashboard
    pub enabled: bool,
    /// Dashboard refresh interval (seconds)
    pub refresh_interval: u64,
    /// Charts configuration
    pub charts: Vec<ChartConfig>,
    /// Custom dashboard widgets
    pub widgets: Vec<WidgetConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartConfig {
    /// Chart ID
    pub id: String,
    /// Chart title
    pub title: String,
    /// Chart type (line, bar, pie, gauge)
    pub chart_type: String,
    /// Metrics to display
    pub metrics: Vec<String>,
    /// Time range (minutes)
    pub time_range: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetConfig {
    /// Widget ID
    pub id: String,
    /// Widget type
    pub widget_type: String,
    /// Widget configuration
    pub config: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaMonitoringConfig {
    /// Enable SLA monitoring
    pub enabled: bool,
    /// SLA targets
    pub targets: Vec<SlaTarget>,
    /// Measurement window (hours)
    pub window_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaTarget {
    /// Target name
    pub name: String,
    /// Service/endpoint pattern
    pub service_pattern: String,
    /// Availability target (percentage)
    pub availability_target: f64,
    /// Response time target (milliseconds)
    pub response_time_target: f64,
    /// Error rate target (percentage)
    pub error_rate_target: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetectionConfig {
    /// Enable anomaly detection
    pub enabled: bool,
    /// Algorithm (statistical, ml, hybrid)
    pub algorithm: String,
    /// Sensitivity (1-10)
    pub sensitivity: u8,
    /// Learning period (hours)
    pub learning_period: u64,
}

/// Real-time metrics collector
pub struct RealTimeMonitor {
    config: RealTimeMonitoringConfig,
    metrics_store: Arc<MetricsStore>,
    alert_manager: Arc<AlertManager>,
    dashboard: Arc<Dashboard>,
    sla_monitor: Arc<SlaMonitor>,
    anomaly_detector: Arc<AnomalyDetector>,
    event_bus: broadcast::Sender<MonitoringEvent>,
}

/// Metrics storage and aggregation
struct MetricsStore {
    current_metrics: Arc<RwLock<HashMap<String, MetricValue>>>,
    historical_metrics: Arc<RwLock<Vec<TimestampedMetrics>>>,
    retention_hours: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricValue {
    value: f64,
    timestamp: SystemTime,
    labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
struct TimestampedMetrics {
    timestamp: SystemTime,
    metrics: HashMap<String, MetricValue>,
}

impl MetricsStore {
    fn new(retention_hours: u64) -> Self {
        Self {
            current_metrics: Arc::new(RwLock::new(HashMap::new())),
            historical_metrics: Arc::new(RwLock::new(Vec::new())),
            retention_hours,
        }
    }

    async fn record_metric(&self, name: String, value: f64, labels: HashMap<String, String>) {
        let metric = MetricValue {
            value,
            timestamp: SystemTime::now(),
            labels,
        };

        let mut current = self.current_metrics.write().await;
        current.insert(name, metric);
    }

    async fn snapshot_metrics(&self) {
        let current = self.current_metrics.read().await.clone();
        let snapshot = TimestampedMetrics {
            timestamp: SystemTime::now(),
            metrics: current,
        };

        let mut historical = self.historical_metrics.write().await;
        historical.push(snapshot);

        // Clean up old metrics
        let retention_duration = Duration::from_secs(self.retention_hours * 3600);
        let cutoff = SystemTime::now() - retention_duration;

        historical.retain(|snapshot| snapshot.timestamp > cutoff);
    }

    async fn get_current_metrics(&self) -> HashMap<String, MetricValue> {
        self.current_metrics.read().await.clone()
    }

    async fn get_historical_metrics(&self, hours: u64) -> Vec<TimestampedMetrics> {
        let since = SystemTime::now() - Duration::from_secs(hours * 3600);
        let historical = self.historical_metrics.read().await;

        historical
            .iter()
            .filter(|snapshot| snapshot.timestamp > since)
            .cloned()
            .collect()
    }

    async fn get_metric_series(&self, metric_name: &str, hours: u64) -> Vec<(SystemTime, f64)> {
        let historical = self.get_historical_metrics(hours).await;
        let mut series = Vec::new();

        for snapshot in historical {
            if let Some(metric) = snapshot.metrics.get(metric_name) {
                series.push((snapshot.timestamp, metric.value));
            }
        }

        series
    }
}

/// Alert management system
struct AlertManager {
    config: AlertConfig,
    alert_state: Arc<RwLock<HashMap<String, AlertState>>>,
    notification_channels: HashMap<String, NotificationSender>,
    alert_history: Arc<RwLock<Vec<AlertEvent>>>,
}

#[derive(Debug, Clone)]
struct AlertState {
    active: bool,
    first_triggered: SystemTime,
    last_triggered: SystemTime,
    trigger_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertEvent {
    rule_id: String,
    rule_name: String,
    severity: AlertSeverity,
    description: String,
    metric_value: f64,
    threshold: f64,
    timestamp: SystemTime,
    resolved: bool,
}

enum NotificationSender {
    Email {
        #[allow(dead_code)]
        config: HashMap<String, String>,
    },
    Webhook {
        config: HashMap<String, String>,
        client: reqwest::Client,
    },
}

impl NotificationSender {
    async fn send_alert(&self, alert: &AlertEvent) -> Result<(), String> {
        match self {
            NotificationSender::Email { config: _ } => {
                // Email notification implementation
                info!(
                    "Sending email alert: {} - {}",
                    alert.rule_name, alert.description
                );
                // In a real implementation, integrate with email service
                Ok(())
            }
            NotificationSender::Webhook { config, client } => {
                if let Some(url) = config.get("url") {
                    let payload = serde_json::json!({
                        "rule_id": alert.rule_id,
                        "rule_name": alert.rule_name,
                        "severity": alert.severity,
                        "description": alert.description,
                        "metric_value": alert.metric_value,
                        "timestamp": alert.timestamp.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                    });

                    match client.post(url).json(&payload).send().await {
                        Ok(response) => {
                            if response.status().is_success() {
                                info!("Webhook alert sent successfully");
                                Ok(())
                            } else {
                                Err(format!("Webhook failed with status: {}", response.status()))
                            }
                        }
                        Err(e) => Err(format!("Webhook request failed: {}", e)),
                    }
                } else {
                    Err("Webhook URL not configured".to_string())
                }
            }
        }
    }
}

impl AlertManager {
    fn new(config: AlertConfig) -> Self {
        let mut notification_channels: HashMap<String, NotificationSender> = HashMap::new();

        for channel in &config.channels {
            if !channel.enabled {
                continue;
            }

            let sender = match channel.channel_type.as_str() {
                "email" => NotificationSender::Email {
                    config: channel.config.clone(),
                },
                "webhook" => NotificationSender::Webhook {
                    config: channel.config.clone(),
                    client: reqwest::Client::new(),
                },
                _ => continue,
            };

            notification_channels.insert(channel.id.clone(), sender);
        }

        Self {
            config,
            alert_state: Arc::new(RwLock::new(HashMap::new())),
            notification_channels,
            alert_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    async fn evaluate_rules(&self, metrics: &HashMap<String, MetricValue>) {
        for rule in &self.config.rules {
            if !rule.enabled {
                continue;
            }

            if let Some(metric) = metrics.get(&rule.metric) {
                let triggered = self.evaluate_rule(rule, metric.value);

                if triggered {
                    self.handle_alert_trigger(rule, metric.value).await;
                } else {
                    self.handle_alert_resolve(&rule.id).await;
                }
            }
        }
    }

    fn evaluate_rule(&self, rule: &AlertRule, value: f64) -> bool {
        match rule.operator.as_str() {
            "gt" => value > rule.threshold,
            "lt" => value < rule.threshold,
            "eq" => (value - rule.threshold).abs() < f64::EPSILON,
            "ne" => (value - rule.threshold).abs() > f64::EPSILON,
            "gte" => value >= rule.threshold,
            "lte" => value <= rule.threshold,
            _ => false,
        }
    }

    async fn handle_alert_trigger(&self, rule: &AlertRule, metric_value: f64) {
        let mut state = self.alert_state.write().await;
        let alert_state = state.entry(rule.id.clone()).or_insert_with(|| AlertState {
            active: false,
            first_triggered: SystemTime::now(),
            last_triggered: SystemTime::now(),
            trigger_count: 0,
        });

        alert_state.last_triggered = SystemTime::now();
        alert_state.trigger_count += 1;

        if !alert_state.active {
            alert_state.active = true;
            alert_state.first_triggered = SystemTime::now();

            let alert_event = AlertEvent {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: rule.severity.clone(),
                description: rule.description.clone(),
                metric_value,
                threshold: rule.threshold,
                timestamp: SystemTime::now(),
                resolved: false,
            };

            // Send notifications
            for channel_id in &rule.channels {
                if let Some(sender) = self.notification_channels.get(channel_id) {
                    if let Err(e) = sender.send_alert(&alert_event).await {
                        error!("Failed to send alert via {}: {}", channel_id, e);
                    }
                }
            }

            // Store in history
            let mut history = self.alert_history.write().await;
            history.push(alert_event);
        }
    }

    async fn handle_alert_resolve(&self, rule_id: &str) {
        let mut state = self.alert_state.write().await;
        if let Some(alert_state) = state.get_mut(rule_id) {
            if alert_state.active {
                alert_state.active = false;

                // Create resolved alert event
                let resolved_event = AlertEvent {
                    rule_id: rule_id.to_string(),
                    rule_name: "Resolved".to_string(),
                    severity: AlertSeverity::Info,
                    description: format!("Alert {} has been resolved", rule_id),
                    metric_value: 0.0,
                    threshold: 0.0,
                    timestamp: SystemTime::now(),
                    resolved: true,
                };

                let mut history = self.alert_history.write().await;
                history.push(resolved_event);
            }
        }
    }

    async fn get_active_alerts(&self) -> Vec<String> {
        let state = self.alert_state.read().await;
        state
            .iter()
            .filter_map(|(id, state)| if state.active { Some(id.clone()) } else { None })
            .collect()
    }

    async fn get_alert_history(&self, hours: u64) -> Vec<AlertEvent> {
        let since = SystemTime::now() - Duration::from_secs(hours * 3600);
        let history = self.alert_history.read().await;

        history
            .iter()
            .filter(|event| event.timestamp > since)
            .cloned()
            .collect()
    }
}

/// Real-time dashboard
struct Dashboard {
    config: DashboardConfig,
}

impl Dashboard {
    fn new(config: DashboardConfig) -> Self {
        Self { config }
    }

    async fn generate_dashboard_data(
        &self,
        metrics_store: &MetricsStore,
    ) -> Result<DashboardData, String> {
        let mut charts = Vec::new();

        for chart_config in &self.config.charts {
            let mut chart_data = Vec::new();

            for metric_name in &chart_config.metrics {
                let series = metrics_store
                    .get_metric_series(metric_name, chart_config.time_range / 60)
                    .await;

                chart_data.push(ChartSeries {
                    name: metric_name.clone(),
                    data: series
                        .into_iter()
                        .map(|(timestamp, value)| DataPoint { timestamp, value })
                        .collect(),
                });
            }

            charts.push(ChartData {
                id: chart_config.id.clone(),
                title: chart_config.title.clone(),
                chart_type: chart_config.chart_type.clone(),
                series: chart_data,
            });
        }

        Ok(DashboardData {
            charts,
            last_updated: SystemTime::now(),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardData {
    charts: Vec<ChartData>,
    last_updated: SystemTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChartData {
    id: String,
    title: String,
    chart_type: String,
    series: Vec<ChartSeries>,
}

#[derive(Debug, Clone, Serialize)]
struct ChartSeries {
    name: String,
    data: Vec<DataPoint>,
}

#[derive(Debug, Clone, Serialize)]
struct DataPoint {
    timestamp: SystemTime,
    value: f64,
}

/// SLA monitoring
struct SlaMonitor {
    config: SlaMonitoringConfig,
    sla_metrics: Arc<RwLock<HashMap<String, SlaMetrics>>>,
}

#[derive(Debug, Clone)]
struct SlaMetrics {
    total_requests: u64,
    successful_requests: u64,
    total_response_time: f64,
    last_updated: SystemTime,
}

impl SlaMonitor {
    fn new(config: SlaMonitoringConfig) -> Self {
        Self {
            config,
            sla_metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn record_request(&self, service: &str, success: bool, response_time: f64) {
        let mut metrics = self.sla_metrics.write().await;
        let sla_metric = metrics
            .entry(service.to_string())
            .or_insert_with(|| SlaMetrics {
                total_requests: 0,
                successful_requests: 0,
                total_response_time: 0.0,
                last_updated: SystemTime::now(),
            });

        sla_metric.total_requests += 1;
        if success {
            sla_metric.successful_requests += 1;
        }
        sla_metric.total_response_time += response_time;
        sla_metric.last_updated = SystemTime::now();
    }

    async fn get_sla_report(&self) -> SlaReport {
        let metrics = self.sla_metrics.read().await;
        let mut services = Vec::new();

        for target in &self.config.targets {
            if let Some(metric) = metrics.get(&target.service_pattern) {
                let availability = if metric.total_requests > 0 {
                    (metric.successful_requests as f64 / metric.total_requests as f64) * 100.0
                } else {
                    0.0
                };

                let avg_response_time = if metric.total_requests > 0 {
                    metric.total_response_time / metric.total_requests as f64
                } else {
                    0.0
                };

                let error_rate = if metric.total_requests > 0 {
                    ((metric.total_requests - metric.successful_requests) as f64
                        / metric.total_requests as f64)
                        * 100.0
                } else {
                    0.0
                };

                services.push(SlaServiceReport {
                    service: target.name.clone(),
                    availability,
                    avg_response_time,
                    error_rate,
                    availability_target: target.availability_target,
                    response_time_target: target.response_time_target,
                    error_rate_target: target.error_rate_target,
                    meets_sla: availability >= target.availability_target
                        && avg_response_time <= target.response_time_target
                        && error_rate <= target.error_rate_target,
                });
            }
        }

        SlaReport {
            window_hours: self.config.window_hours,
            services,
            generated_at: SystemTime::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SlaReport {
    window_hours: u64,
    services: Vec<SlaServiceReport>,
    generated_at: SystemTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct SlaServiceReport {
    service: String,
    availability: f64,
    avg_response_time: f64,
    error_rate: f64,
    availability_target: f64,
    response_time_target: f64,
    error_rate_target: f64,
    meets_sla: bool,
}

/// Anomaly detection
struct AnomalyDetector {
    config: AnomalyDetectionConfig,
    baselines: Arc<RwLock<HashMap<String, MetricBaseline>>>,
}

#[derive(Debug, Clone)]
struct MetricBaseline {
    mean: f64,
    std_dev: f64,
    sample_count: u64,
    last_updated: SystemTime,
}

impl AnomalyDetector {
    fn new(config: AnomalyDetectionConfig) -> Self {
        Self {
            config,
            baselines: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn update_baseline(&self, metric_name: &str, value: f64) {
        let mut baselines = self.baselines.write().await;
        let baseline = baselines
            .entry(metric_name.to_string())
            .or_insert_with(|| MetricBaseline {
                mean: value,
                std_dev: 0.0,
                sample_count: 0,
                last_updated: SystemTime::now(),
            });

        // Update running statistics
        baseline.sample_count += 1;
        let delta = value - baseline.mean;
        baseline.mean += delta / baseline.sample_count as f64;

        if baseline.sample_count > 1 {
            let delta2 = value - baseline.mean;
            baseline.std_dev = ((baseline.std_dev.powi(2) * (baseline.sample_count - 1) as f64
                + delta * delta2)
                / baseline.sample_count as f64)
                .sqrt();
        }

        baseline.last_updated = SystemTime::now();
    }

    async fn detect_anomaly(&self, metric_name: &str, value: f64) -> bool {
        if !self.config.enabled {
            return false;
        }

        let baselines = self.baselines.read().await;
        if let Some(baseline) = baselines.get(metric_name) {
            if baseline.sample_count < 10 {
                return false; // Not enough data for anomaly detection
            }

            let threshold_multiplier = match self.config.sensitivity {
                1..=3 => 3.0,
                4..=6 => 2.5,
                7..=8 => 2.0,
                9..=10 => 1.5,
                _ => 2.0,
            };

            let upper_bound = baseline.mean + threshold_multiplier * baseline.std_dev;
            let lower_bound = baseline.mean - threshold_multiplier * baseline.std_dev;

            return value > upper_bound || value < lower_bound;
        }

        false
    }
}

/// Monitoring events
#[derive(Debug, Clone)]
pub enum MonitoringEvent {
    MetricUpdated {
        name: String,
        value: f64,
        timestamp: SystemTime,
    },
    AlertTriggered {
        rule_id: String,
        severity: AlertSeverity,
    },
    AlertResolved {
        rule_id: String,
    },
    AnomalyDetected {
        metric: String,
        value: f64,
        baseline: f64,
    },
    SlaViolation {
        service: String,
        metric: String,
        target: f64,
        actual: f64,
    },
}

impl RealTimeMonitor {
    pub fn new(config: RealTimeMonitoringConfig) -> Self {
        let (event_bus, _) = broadcast::channel(1000);

        Self {
            metrics_store: Arc::new(MetricsStore::new(config.retention_hours)),
            alert_manager: Arc::new(AlertManager::new(config.alerting.clone())),
            dashboard: Arc::new(Dashboard::new(config.dashboard.clone())),
            sla_monitor: Arc::new(SlaMonitor::new(config.sla_monitoring.clone())),
            anomaly_detector: Arc::new(AnomalyDetector::new(config.anomaly_detection.clone())),
            config,
            event_bus,
        }
    }

    pub async fn start(&self) {
        info!("Starting real-time monitoring system");

        // Start metrics collection loop
        let metrics_store = Arc::clone(&self.metrics_store);
        let collection_interval = self.config.collection_interval;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(collection_interval));
            loop {
                interval.tick().await;
                metrics_store.snapshot_metrics().await;
            }
        });

        // Start alert evaluation loop
        let alert_manager = Arc::clone(&self.alert_manager);
        let metrics_store_for_alerts = Arc::clone(&self.metrics_store);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30)); // Check alerts every 30 seconds
            loop {
                interval.tick().await;
                let metrics = metrics_store_for_alerts.get_current_metrics().await;
                alert_manager.evaluate_rules(&metrics).await;
            }
        });
    }

    pub async fn record_metric(&self, name: String, value: f64, labels: HashMap<String, String>) {
        self.metrics_store
            .record_metric(name.clone(), value, labels)
            .await;

        // Update anomaly detection baseline
        self.anomaly_detector.update_baseline(&name, value).await;

        // Check for anomalies
        if self.anomaly_detector.detect_anomaly(&name, value).await {
            let _ = self.event_bus.send(MonitoringEvent::AnomalyDetected {
                metric: name,
                value,
                baseline: 0.0, // Would get actual baseline in real implementation
            });
        }
    }

    pub async fn record_request(&self, service: &str, success: bool, response_time: f64) {
        self.sla_monitor
            .record_request(service, success, response_time)
            .await;
    }

    pub async fn get_dashboard_data(&self) -> Result<DashboardData, String> {
        self.dashboard
            .generate_dashboard_data(&self.metrics_store)
            .await
    }

    pub async fn get_sla_report(&self) -> SlaReport {
        self.sla_monitor.get_sla_report().await
    }

    pub async fn get_active_alerts(&self) -> Vec<String> {
        self.alert_manager.get_active_alerts().await
    }

    pub async fn get_alert_history(&self, hours: u64) -> Vec<AlertEvent> {
        self.alert_manager.get_alert_history(hours).await
    }

    pub async fn get_current_metrics(&self) -> HashMap<String, MetricValue> {
        self.metrics_store.get_current_metrics().await
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<MonitoringEvent> {
        self.event_bus.subscribe()
    }
}

impl Default for RealTimeMonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            collection_interval: 30,
            retention_hours: 24,
            alerting: AlertConfig {
                enabled: true,
                rules: vec![
                    AlertRule {
                        id: "high_error_rate".to_string(),
                        name: "High Error Rate".to_string(),
                        metric: "error_rate".to_string(),
                        threshold: 5.0,
                        operator: "gt".to_string(),
                        window: 300,
                        severity: AlertSeverity::Critical,
                        description: "Error rate exceeded 5%".to_string(),
                        channels: vec!["default".to_string()],
                        enabled: true,
                    },
                    AlertRule {
                        id: "high_response_time".to_string(),
                        name: "High Response Time".to_string(),
                        metric: "avg_response_time".to_string(),
                        threshold: 1000.0,
                        operator: "gt".to_string(),
                        window: 300,
                        severity: AlertSeverity::High,
                        description: "Average response time exceeded 1 second".to_string(),
                        channels: vec!["default".to_string()],
                        enabled: true,
                    },
                ],
                channels: vec![NotificationChannel {
                    id: "default".to_string(),
                    channel_type: "webhook".to_string(),
                    config: HashMap::new(),
                    enabled: true,
                }],
                default_severity: AlertSeverity::Medium,
                aggregation_window: 300,
                rate_limit: 10,
            },
            dashboard: DashboardConfig {
                enabled: true,
                refresh_interval: 30,
                charts: vec![
                    ChartConfig {
                        id: "requests_per_second".to_string(),
                        title: "Requests per Second".to_string(),
                        chart_type: "line".to_string(),
                        metrics: vec!["rps".to_string()],
                        time_range: 60,
                    },
                    ChartConfig {
                        id: "response_time".to_string(),
                        title: "Response Time".to_string(),
                        chart_type: "line".to_string(),
                        metrics: vec!["avg_response_time".to_string()],
                        time_range: 60,
                    },
                ],
                widgets: Vec::new(),
            },
            sla_monitoring: SlaMonitoringConfig {
                enabled: true,
                targets: vec![SlaTarget {
                    name: "API Service".to_string(),
                    service_pattern: "api".to_string(),
                    availability_target: 99.9,
                    response_time_target: 500.0,
                    error_rate_target: 1.0,
                }],
                window_hours: 24,
            },
            anomaly_detection: AnomalyDetectionConfig {
                enabled: true,
                algorithm: "statistical".to_string(),
                sensitivity: 5,
                learning_period: 24,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_real_time_monitor_creation() {
        let config = RealTimeMonitoringConfig::default();
        let monitor = RealTimeMonitor::new(config);

        assert!(monitor.config.enabled);
    }

    #[tokio::test]
    async fn test_metrics_store() {
        let store = MetricsStore::new(1);

        let mut labels = HashMap::new();
        labels.insert("service".to_string(), "test".to_string());

        store
            .record_metric("test_metric".to_string(), 42.0, labels)
            .await;

        let metrics = store.get_current_metrics().await;
        assert!(metrics.contains_key("test_metric"));
        assert_eq!(metrics["test_metric"].value, 42.0);
    }

    #[tokio::test]
    async fn test_alert_rule_evaluation() {
        let rule = AlertRule {
            id: "test_rule".to_string(),
            name: "Test Rule".to_string(),
            metric: "test_metric".to_string(),
            threshold: 50.0,
            operator: "gt".to_string(),
            window: 60,
            severity: AlertSeverity::High,
            description: "Test alert".to_string(),
            channels: vec!["test".to_string()],
            enabled: true,
        };

        let config = AlertConfig {
            enabled: true,
            rules: vec![rule.clone()],
            channels: Vec::new(),
            default_severity: AlertSeverity::Medium,
            aggregation_window: 300,
            rate_limit: 10,
        };

        let manager = AlertManager::new(config);

        assert!(manager.evaluate_rule(&rule, 60.0)); // 60 > 50
        assert!(!manager.evaluate_rule(&rule, 40.0)); // 40 < 50
    }

    #[tokio::test]
    async fn test_anomaly_detection() {
        let config = AnomalyDetectionConfig {
            enabled: true,
            algorithm: "statistical".to_string(),
            sensitivity: 5,
            learning_period: 24,
        };

        let detector = AnomalyDetector::new(config);

        // Build baseline with normal values
        for i in 0..20 {
            detector
                .update_baseline("test_metric", 50.0 + (i % 5) as f64)
                .await;
        }

        // Test anomaly detection
        assert!(detector.detect_anomaly("test_metric", 100.0).await); // Should be anomalous
        assert!(!detector.detect_anomaly("test_metric", 52.0).await); // Should be normal
    }

    #[tokio::test]
    async fn test_sla_monitoring() {
        let config = SlaMonitoringConfig {
            enabled: true,
            targets: vec![SlaTarget {
                name: "Test Service".to_string(),
                service_pattern: "test".to_string(),
                availability_target: 99.0,
                response_time_target: 1000.0,
                error_rate_target: 2.0,
            }],
            window_hours: 1,
        };

        let monitor = SlaMonitor::new(config);

        // Record some requests
        monitor.record_request("test", true, 500.0).await;
        monitor.record_request("test", true, 600.0).await;
        monitor.record_request("test", false, 800.0).await;

        let report = monitor.get_sla_report().await;
        assert_eq!(report.services.len(), 1);

        let service_report = &report.services[0];
        assert_eq!(service_report.service, "Test Service");
        assert!((service_report.availability - 66.67).abs() < 0.1); // 2/3 success rate
    }
}
