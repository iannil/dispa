//! Advanced security features and DDoS protection
//!
//! This module provides enhanced security capabilities including:
//! - Advanced rate limiting with sliding windows
//! - DDoS detection and mitigation
//! - IP reputation scoring and geolocation blocking
//! - Web Application Firewall (WAF) rules
//! - Bot detection and CAPTCHA challenges
//! - Threat intelligence integration

use hyper::{Body, HeaderMap, Method, Request};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
// IP address types available when needed
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
// Sleep function available when needed

/// Advanced security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedSecurityConfig {
    /// Enable advanced security features
    pub enabled: bool,
    /// Rate limiting configuration
    pub rate_limiting: RateLimitConfig,
    /// DDoS protection settings
    pub ddos_protection: DdosProtectionConfig,
    /// IP reputation configuration
    pub ip_reputation: IpReputationConfig,
    /// WAF rules configuration
    pub waf_rules: WafConfig,
    /// Bot detection settings
    pub bot_detection: BotDetectionConfig,
    /// Threat intelligence configuration
    pub threat_intelligence: ThreatIntelConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,
    /// Global rate limit (requests per second)
    pub global_rps: u32,
    /// Per-IP rate limit (requests per second)
    pub per_ip_rps: u32,
    /// Per-endpoint rate limit
    pub per_endpoint_rps: HashMap<String, u32>,
    /// Sliding window size (seconds)
    pub window_size: u32,
    /// Burst allowance
    pub burst_size: u32,
    /// Rate limit algorithm (sliding_window, token_bucket, fixed_window)
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosProtectionConfig {
    /// Enable DDoS protection
    pub enabled: bool,
    /// Detection threshold (requests per second)
    pub detection_threshold: u32,
    /// Mitigation strategies
    pub mitigation_strategies: Vec<String>,
    /// Auto-ban duration (seconds)
    pub auto_ban_duration: u32,
    /// Challenge mode (captcha, javascript_challenge, etc.)
    pub challenge_mode: String,
    /// Whitelist of trusted IPs
    pub whitelist: Vec<String>,
    /// Geographic blocking
    pub geo_blocking: GeoBlockingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoBlockingConfig {
    /// Enable geographic blocking
    pub enabled: bool,
    /// Blocked countries (ISO 3166-1 alpha-2 codes)
    pub blocked_countries: Vec<String>,
    /// Allowed countries (if specified, only these are allowed)
    pub allowed_countries: Vec<String>,
    /// Block known VPN/proxy IPs
    pub block_vpn_proxy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputationConfig {
    /// Enable IP reputation scoring
    pub enabled: bool,
    /// Reputation providers
    pub providers: Vec<String>,
    /// Reputation threshold (0-100, higher is more suspicious)
    pub threshold: u8,
    /// Cache TTL for reputation data
    pub cache_ttl: u32,
    /// Local reputation database
    pub local_db_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    /// Enable WAF rules
    pub enabled: bool,
    /// Rule sets to load
    pub rule_sets: Vec<String>,
    /// Custom rules
    pub custom_rules: Vec<WafRule>,
    /// Paranoia level (1-4)
    pub paranoia_level: u8,
    /// Block mode (block, log, challenge)
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafRule {
    /// Rule ID
    pub id: String,
    /// Rule name
    pub name: String,
    /// Pattern to match
    pub pattern: String,
    /// Pattern type (regex, contains, exact)
    pub pattern_type: String,
    /// Target (uri, header, body, query)
    pub target: String,
    /// Action (block, log, score)
    pub action: String,
    /// Severity (1-5)
    pub severity: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotDetectionConfig {
    /// Enable bot detection
    pub enabled: bool,
    /// User agent analysis
    pub user_agent_analysis: bool,
    /// Behavioral analysis
    pub behavioral_analysis: bool,
    /// JavaScript challenge
    pub js_challenge: bool,
    /// CAPTCHA challenge threshold
    pub captcha_threshold: u8,
    /// Known bot patterns
    pub bot_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    /// Enable threat intelligence
    pub enabled: bool,
    /// Intelligence providers
    pub providers: Vec<ThreatProvider>,
    /// Update interval (seconds)
    pub update_interval: u32,
    /// API keys for providers
    pub api_keys: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatProvider {
    /// Provider name
    pub name: String,
    /// Provider URL
    pub url: String,
    /// Feed type (json, csv, xml)
    pub feed_type: String,
    /// Weight (0-100)
    pub weight: u8,
}

/// Advanced security manager
pub struct AdvancedSecurityManager {
    config: AdvancedSecurityConfig,
    rate_limiter: Arc<AdvancedRateLimiter>,
    ddos_detector: Arc<DdosDetector>,
    ip_reputation: Arc<IpReputationSystem>,
    waf: Arc<WebApplicationFirewall>,
    bot_detector: Arc<BotDetector>,
    threat_intel: Arc<ThreatIntelligence>,
    stats: Arc<SecurityStats>,
}

#[derive(Debug)]
struct SecurityStats {
    requests_processed: AtomicU64,
    requests_blocked: AtomicU64,
    rate_limited: AtomicU64,
    ddos_attacks_detected: AtomicU64,
    waf_blocks: AtomicU64,
    bot_challenges: AtomicU64,
    reputation_blocks: AtomicU64,
    geo_blocks: AtomicU64,
}

impl SecurityStats {
    fn new() -> Self {
        Self {
            requests_processed: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            ddos_attacks_detected: AtomicU64::new(0),
            waf_blocks: AtomicU64::new(0),
            bot_challenges: AtomicU64::new(0),
            reputation_blocks: AtomicU64::new(0),
            geo_blocks: AtomicU64::new(0),
        }
    }

    pub fn get_metrics(&self) -> SecurityMetrics {
        SecurityMetrics {
            requests_processed: self.requests_processed.load(Ordering::Relaxed),
            requests_blocked: self.requests_blocked.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            ddos_attacks_detected: self.ddos_attacks_detected.load(Ordering::Relaxed),
            waf_blocks: self.waf_blocks.load(Ordering::Relaxed),
            bot_challenges: self.bot_challenges.load(Ordering::Relaxed),
            reputation_blocks: self.reputation_blocks.load(Ordering::Relaxed),
            geo_blocks: self.geo_blocks.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityMetrics {
    pub requests_processed: u64,
    pub requests_blocked: u64,
    pub rate_limited: u64,
    pub ddos_attacks_detected: u64,
    pub waf_blocks: u64,
    pub bot_challenges: u64,
    pub reputation_blocks: u64,
    pub geo_blocks: u64,
}

impl SecurityMetrics {
    pub fn block_ratio(&self) -> f64 {
        if self.requests_processed == 0 {
            0.0
        } else {
            self.requests_blocked as f64 / self.requests_processed as f64
        }
    }
}

/// Security assessment result
#[derive(Debug, Clone)]
pub struct SecurityAssessment {
    pub allowed: bool,
    pub reason: String,
    pub score: u8,
    pub actions: Vec<SecurityAction>,
    pub challenge: Option<ChallengeType>,
}

#[derive(Debug, Clone)]
pub enum SecurityAction {
    Allow,
    Block,
    RateLimit,
    Challenge(ChallengeType),
    Log(String),
}

#[derive(Debug, Clone)]
pub enum ChallengeType {
    Captcha,
    JavascriptChallenge,
    InteractiveChallenge,
}

/// Advanced rate limiter with sliding windows
struct AdvancedRateLimiter {
    config: RateLimitConfig,
    windows: Arc<RwLock<HashMap<String, SlidingWindow>>>,
}

#[derive(Debug, Clone)]
struct SlidingWindow {
    requests: Vec<Instant>,
    last_cleanup: Instant,
}

impl AdvancedRateLimiter {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            windows: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn check_rate_limit(&self, key: &str, limit: u32) -> bool {
        if !self.config.enabled {
            return true;
        }

        let mut windows = self.windows.write().await;
        let window = windows
            .entry(key.to_string())
            .or_insert_with(|| SlidingWindow {
                requests: Vec::new(),
                last_cleanup: Instant::now(),
            });

        let now = Instant::now();
        let window_start = now - Duration::from_secs(self.config.window_size as u64);

        // Remove old requests
        window.requests.retain(|&req_time| req_time >= window_start);

        // Check if rate limit is exceeded
        if window.requests.len() >= limit as usize {
            return false;
        }

        // Add current request
        window.requests.push(now);
        true
    }

    async fn check_global_rate_limit(&self) -> bool {
        self.check_rate_limit("global", self.config.global_rps)
            .await
    }

    async fn check_ip_rate_limit(&self, ip: &str) -> bool {
        let key = format!("ip:{}", ip);
        self.check_rate_limit(&key, self.config.per_ip_rps).await
    }

    async fn check_endpoint_rate_limit(&self, endpoint: &str) -> bool {
        if let Some(&limit) = self.config.per_endpoint_rps.get(endpoint) {
            let key = format!("endpoint:{}", endpoint);
            self.check_rate_limit(&key, limit).await
        } else {
            true
        }
    }
}

/// DDoS detection and mitigation
struct DdosDetector {
    config: DdosProtectionConfig,
    attack_state: Arc<RwLock<AttackState>>,
    banned_ips: Arc<RwLock<HashMap<String, Instant>>>,
}

#[derive(Debug, Clone)]
struct AttackState {
    under_attack: bool,
    attack_start: Option<Instant>,
    request_counts: HashMap<String, u32>,
    last_reset: Instant,
}

impl DdosDetector {
    fn new(config: DdosProtectionConfig) -> Self {
        Self {
            config,
            attack_state: Arc::new(RwLock::new(AttackState {
                under_attack: false,
                attack_start: None,
                request_counts: HashMap::new(),
                last_reset: Instant::now(),
            })),
            banned_ips: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn detect_attack(&self, ip: &str) -> bool {
        if !self.config.enabled {
            return false;
        }

        // Check if IP is whitelisted
        if self.config.whitelist.contains(&ip.to_string()) {
            return false;
        }

        let mut state = self.attack_state.write().await;
        let now = Instant::now();

        // Reset counters every minute
        if now.duration_since(state.last_reset) >= Duration::from_secs(60) {
            state.request_counts.clear();
            state.last_reset = now;
        }

        // Count requests per IP
        let count = state.request_counts.entry(ip.to_string()).or_insert(0);
        *count += 1;

        // Check if threshold is exceeded
        if *count > self.config.detection_threshold {
            // Ban the IP
            let mut banned = self.banned_ips.write().await;
            banned.insert(ip.to_string(), now);

            // Mark as under attack
            if !state.under_attack {
                state.under_attack = true;
                state.attack_start = Some(now);
            }

            return true;
        }

        false
    }

    async fn is_ip_banned(&self, ip: &str) -> bool {
        let banned = self.banned_ips.read().await;
        if let Some(&ban_time) = banned.get(ip) {
            let ban_duration = Duration::from_secs(self.config.auto_ban_duration as u64);
            return Instant::now().duration_since(ban_time) < ban_duration;
        }
        false
    }

    async fn is_under_attack(&self) -> bool {
        let state = self.attack_state.read().await;
        state.under_attack
    }
}

/// IP reputation system
struct IpReputationSystem {
    config: IpReputationConfig,
    reputation_cache: Arc<RwLock<HashMap<String, ReputationScore>>>,
}

#[derive(Debug, Clone)]
struct ReputationScore {
    score: u8,
    last_updated: SystemTime,
    sources: Vec<String>,
}

impl IpReputationSystem {
    fn new(config: IpReputationConfig) -> Self {
        Self {
            config,
            reputation_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn get_reputation(&self, ip: &str) -> u8 {
        if !self.config.enabled {
            return 0; // No reputation concerns
        }

        let cache = self.reputation_cache.read().await;
        if let Some(score) = cache.get(ip) {
            let cache_age = SystemTime::now()
                .duration_since(score.last_updated)
                .unwrap_or(Duration::MAX);

            if cache_age.as_secs() < self.config.cache_ttl as u64 {
                return score.score;
            }
        }

        // In a real implementation, this would query reputation APIs
        // For now, return a mock score based on IP pattern
        self.mock_reputation_lookup(ip).await
    }

    async fn mock_reputation_lookup(&self, ip: &str) -> u8 {
        // Simple mock implementation
        if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("127.") {
            return 0; // Private IPs are safe
        }

        // Simulate reputation lookup
        if ip.contains("suspicious") {
            return 80; // High suspicion
        }

        20 // Default low suspicion
    }

    async fn is_suspicious(&self, ip: &str) -> bool {
        let reputation = self.get_reputation(ip).await;
        reputation > self.config.threshold
    }
}

/// Web Application Firewall
struct WebApplicationFirewall {
    config: WafConfig,
    rules: Vec<WafRule>,
}

impl WebApplicationFirewall {
    fn new(config: WafConfig) -> Self {
        Self {
            rules: config.custom_rules.clone(),
            config,
        }
    }

    async fn check_request(&self, request: &Request<Body>) -> WafResult {
        if !self.config.enabled {
            return WafResult {
                blocked: false,
                rule_id: None,
                reason: "WAF disabled".to_string(),
                severity: 0,
            };
        }

        let uri = request.uri().to_string();
        let headers = request.headers();
        let method = request.method();

        // Check common attack patterns
        for rule in &self.rules {
            if self.rule_matches(rule, &uri, headers, method) {
                return WafResult {
                    blocked: rule.action == "block",
                    rule_id: Some(rule.id.clone()),
                    reason: format!("WAF rule triggered: {}", rule.name),
                    severity: rule.severity,
                };
            }
        }

        // Check built-in rules
        if self.check_sql_injection(&uri) {
            return WafResult {
                blocked: true,
                rule_id: Some("sql_injection".to_string()),
                reason: "SQL injection attempt detected".to_string(),
                severity: 5,
            };
        }

        if self.check_xss(&uri) {
            return WafResult {
                blocked: true,
                rule_id: Some("xss".to_string()),
                reason: "XSS attempt detected".to_string(),
                severity: 4,
            };
        }

        WafResult {
            blocked: false,
            rule_id: None,
            reason: "Request passed WAF checks".to_string(),
            severity: 0,
        }
    }

    fn rule_matches(
        &self,
        rule: &WafRule,
        uri: &str,
        _headers: &HeaderMap,
        method: &Method,
    ) -> bool {
        let target_value = match rule.target.as_str() {
            "uri" => uri,
            "method" => method.as_str(),
            _ => return false,
        };

        match rule.pattern_type.as_str() {
            "regex" => {
                if let Ok(re) = regex::Regex::new(&rule.pattern) {
                    re.is_match(target_value)
                } else {
                    false
                }
            }
            "contains" => target_value.contains(&rule.pattern),
            "exact" => target_value == rule.pattern,
            _ => false,
        }
    }

    fn check_sql_injection(&self, uri: &str) -> bool {
        let sql_patterns = [
            "union select",
            "drop table",
            "delete from",
            "insert into",
            "update set",
            "exec(",
            "execute(",
            "char(",
            "varchar(",
            "1=1",
            "1' or '1'='1",
            "or 1=1",
            "' or 1=1 --",
        ];

        let uri_lower = uri.to_lowercase();
        sql_patterns
            .iter()
            .any(|pattern| uri_lower.contains(pattern))
    }

    fn check_xss(&self, uri: &str) -> bool {
        let xss_patterns = [
            "<script",
            "javascript:",
            "onload=",
            "onerror=",
            "onclick=",
            "<iframe",
            "<object",
            "<embed",
            "vbscript:",
            "expression(",
        ];

        let uri_lower = uri.to_lowercase();
        xss_patterns
            .iter()
            .any(|pattern| uri_lower.contains(pattern))
    }
}

#[derive(Debug, Clone)]
struct WafResult {
    blocked: bool,
    rule_id: Option<String>,
    reason: String,
    severity: u8,
}

/// Bot detection system
struct BotDetector {
    config: BotDetectionConfig,
    behavior_tracker: Arc<RwLock<HashMap<String, BehaviorPattern>>>,
}

#[derive(Debug, Clone)]
struct BehaviorPattern {
    request_intervals: Vec<Duration>,
    user_agents: Vec<String>,
    request_patterns: Vec<String>,
    score: u8,
    last_updated: Instant,
}

impl BotDetector {
    fn new(config: BotDetectionConfig) -> Self {
        Self {
            config,
            behavior_tracker: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn analyze_request(&self, ip: &str, user_agent: Option<&str>, uri: &str) -> BotAnalysis {
        if !self.config.enabled {
            return BotAnalysis {
                is_bot: false,
                confidence: 0,
                reason: "Bot detection disabled".to_string(),
                challenge_required: false,
            };
        }

        let mut total_score = 0u8;
        let mut reasons = Vec::new();

        // User agent analysis
        if self.config.user_agent_analysis {
            if let Some(ua) = user_agent {
                let ua_score = self.analyze_user_agent(ua);
                total_score += ua_score;
                if ua_score > 30 {
                    reasons.push("Suspicious user agent pattern".to_string());
                }
            }
        }

        // Behavioral analysis
        if self.config.behavioral_analysis {
            let behavior_score = self.analyze_behavior(ip, uri).await;
            total_score += behavior_score;
            if behavior_score > 40 {
                reasons.push("Bot-like behavior detected".to_string());
            }
        }

        let is_bot = total_score > 60;
        let challenge_required = total_score > self.config.captcha_threshold;

        BotAnalysis {
            is_bot,
            confidence: total_score,
            reason: reasons.join("; "),
            challenge_required,
        }
    }

    fn analyze_user_agent(&self, user_agent: &str) -> u8 {
        // Check against known bot patterns
        for pattern in &self.config.bot_patterns {
            if user_agent.to_lowercase().contains(&pattern.to_lowercase()) {
                return 80; // High bot probability
            }
        }

        // Check for suspicious patterns
        let suspicious_patterns = [
            "bot", "crawler", "spider", "scraper", "wget", "curl", "python", "requests", "urllib",
            "httplib", "headless",
        ];

        for pattern in &suspicious_patterns {
            if user_agent.to_lowercase().contains(pattern) {
                return 70;
            }
        }

        // Check for missing or minimal user agent
        if user_agent.len() < 10 {
            return 50;
        }

        0 // Looks like a normal user agent
    }

    async fn analyze_behavior(&self, ip: &str, _uri: &str) -> u8 {
        let mut tracker = self.behavior_tracker.write().await;
        let now = Instant::now();

        let pattern = tracker
            .entry(ip.to_string())
            .or_insert_with(|| BehaviorPattern {
                request_intervals: Vec::new(),
                user_agents: Vec::new(),
                request_patterns: Vec::new(),
                score: 0,
                last_updated: now,
            });

        // Calculate request interval
        let interval = now.duration_since(pattern.last_updated);
        pattern.request_intervals.push(interval);
        pattern.last_updated = now;

        // Keep only recent intervals (last 10 requests)
        if pattern.request_intervals.len() > 10 {
            pattern.request_intervals.remove(0);
        }

        // Analyze request timing patterns
        if pattern.request_intervals.len() > 3 {
            let avg_interval = pattern
                .request_intervals
                .iter()
                .sum::<Duration>()
                .as_millis()
                / pattern.request_intervals.len() as u128;

            // Very regular intervals suggest automation
            if avg_interval < 100 {
                return 60; // Very fast requests
            }

            // Check for too-regular patterns
            let variance = self.calculate_variance(&pattern.request_intervals);
            if variance < 10.0 {
                return 50; // Too regular timing
            }
        }

        0
    }

    fn calculate_variance(&self, intervals: &[Duration]) -> f64 {
        if intervals.len() < 2 {
            return 0.0;
        }

        let mean = intervals.iter().sum::<Duration>().as_millis() as f64 / intervals.len() as f64;
        let variance = intervals
            .iter()
            .map(|interval| {
                let diff = interval.as_millis() as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / intervals.len() as f64;

        variance.sqrt()
    }
}

#[derive(Debug, Clone)]
struct BotAnalysis {
    is_bot: bool,
    confidence: u8,
    reason: String,
    challenge_required: bool,
}

/// Threat intelligence system
struct ThreatIntelligence {
    config: ThreatIntelConfig,
    threat_data: Arc<RwLock<HashMap<String, ThreatInfo>>>,
}

#[derive(Debug, Clone)]
struct ThreatInfo {
    threat_type: String,
    severity: u8,
    sources: Vec<String>,
    last_updated: SystemTime,
}

impl ThreatIntelligence {
    fn new(config: ThreatIntelConfig) -> Self {
        Self {
            config,
            threat_data: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn check_threat(&self, ip: &str) -> Option<ThreatInfo> {
        if !self.config.enabled {
            return None;
        }

        let threats = self.threat_data.read().await;
        threats.get(ip).cloned()
    }

    async fn update_threat_data(&self) {
        // In a real implementation, this would fetch from threat intelligence APIs
        // For now, this is a placeholder
        tracing::info!("Updating threat intelligence data...");
    }
}

impl AdvancedSecurityManager {
    pub fn new(config: AdvancedSecurityConfig) -> Self {
        Self {
            rate_limiter: Arc::new(AdvancedRateLimiter::new(config.rate_limiting.clone())),
            ddos_detector: Arc::new(DdosDetector::new(config.ddos_protection.clone())),
            ip_reputation: Arc::new(IpReputationSystem::new(config.ip_reputation.clone())),
            waf: Arc::new(WebApplicationFirewall::new(config.waf_rules.clone())),
            bot_detector: Arc::new(BotDetector::new(config.bot_detection.clone())),
            threat_intel: Arc::new(ThreatIntelligence::new(config.threat_intelligence.clone())),
            stats: Arc::new(SecurityStats::new()),
            config,
        }
    }

    pub async fn assess_request(
        &self,
        request: &Request<Body>,
        client_ip: &str,
    ) -> SecurityAssessment {
        self.stats
            .requests_processed
            .fetch_add(1, Ordering::Relaxed);

        let mut score = 0u8;
        let mut reasons = Vec::new();
        let mut actions = Vec::new();
        let mut challenge = None;

        // Rate limiting check
        if !self.rate_limiter.check_global_rate_limit().await
            || !self.rate_limiter.check_ip_rate_limit(client_ip).await
        {
            self.stats.rate_limited.fetch_add(1, Ordering::Relaxed);
            self.stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
            return SecurityAssessment {
                allowed: false,
                reason: "Rate limit exceeded".to_string(),
                score: 100,
                actions: vec![SecurityAction::Block],
                challenge: None,
            };
        }

        // DDoS detection
        if self.ddos_detector.detect_attack(client_ip).await {
            self.stats
                .ddos_attacks_detected
                .fetch_add(1, Ordering::Relaxed);
            self.stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
            score += 80;
            reasons.push("DDoS attack detected".to_string());
            actions.push(SecurityAction::Block);
        }

        // IP reputation check
        if self.ip_reputation.is_suspicious(client_ip).await {
            self.stats.reputation_blocks.fetch_add(1, Ordering::Relaxed);
            score += 60;
            reasons.push("Suspicious IP reputation".to_string());
            actions.push(SecurityAction::Challenge(ChallengeType::Captcha));
            challenge = Some(ChallengeType::Captcha);
        }

        // WAF analysis
        let waf_result = self.waf.check_request(request).await;
        if waf_result.blocked {
            self.stats.waf_blocks.fetch_add(1, Ordering::Relaxed);
            self.stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
            score += waf_result.severity * 10;
            reasons.push(waf_result.reason);
            actions.push(SecurityAction::Block);
        }

        // Bot detection
        let user_agent = request
            .headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok());
        let bot_analysis = self
            .bot_detector
            .analyze_request(client_ip, user_agent, request.uri().path())
            .await;

        if bot_analysis.is_bot {
            score += bot_analysis.confidence;
            reasons.push(bot_analysis.reason);

            if bot_analysis.challenge_required {
                self.stats.bot_challenges.fetch_add(1, Ordering::Relaxed);
                challenge = Some(ChallengeType::JavascriptChallenge);
                actions.push(SecurityAction::Challenge(
                    ChallengeType::JavascriptChallenge,
                ));
            }
        }

        // Threat intelligence check
        if let Some(threat_info) = self.threat_intel.check_threat(client_ip).await {
            score += threat_info.severity * 10;
            reasons.push(format!("Known threat: {}", threat_info.threat_type));
            actions.push(SecurityAction::Block);
        }

        let allowed = score < 80 && !actions.iter().any(|a| matches!(a, SecurityAction::Block));

        if !allowed {
            self.stats.requests_blocked.fetch_add(1, Ordering::Relaxed);
        }

        SecurityAssessment {
            allowed,
            reason: if reasons.is_empty() {
                "Request allowed".to_string()
            } else {
                reasons.join("; ")
            },
            score,
            actions,
            challenge,
        }
    }

    pub fn get_metrics(&self) -> SecurityMetrics {
        self.stats.get_metrics()
    }

    pub async fn is_under_ddos_attack(&self) -> bool {
        self.ddos_detector.is_under_attack().await
    }

    pub async fn start_background_tasks(&self) {
        let threat_intel = Arc::clone(&self.threat_intel);
        let update_interval = self.config.threat_intelligence.update_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(update_interval as u64));
            loop {
                interval.tick().await;
                threat_intel.update_threat_data().await;
            }
        });
    }
}

impl Default for AdvancedSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_limiting: RateLimitConfig {
                enabled: true,
                global_rps: 1000,
                per_ip_rps: 10,
                per_endpoint_rps: HashMap::new(),
                window_size: 60,
                burst_size: 20,
                algorithm: "sliding_window".to_string(),
            },
            ddos_protection: DdosProtectionConfig {
                enabled: true,
                detection_threshold: 100,
                mitigation_strategies: vec!["rate_limit".to_string(), "challenge".to_string()],
                auto_ban_duration: 300,
                challenge_mode: "captcha".to_string(),
                whitelist: Vec::new(),
                geo_blocking: GeoBlockingConfig {
                    enabled: false,
                    blocked_countries: Vec::new(),
                    allowed_countries: Vec::new(),
                    block_vpn_proxy: false,
                },
            },
            ip_reputation: IpReputationConfig {
                enabled: true,
                providers: vec!["local".to_string()],
                threshold: 70,
                cache_ttl: 3600,
                local_db_path: None,
            },
            waf_rules: WafConfig {
                enabled: true,
                rule_sets: vec!["owasp".to_string()],
                custom_rules: Vec::new(),
                paranoia_level: 2,
                mode: "block".to_string(),
            },
            bot_detection: BotDetectionConfig {
                enabled: true,
                user_agent_analysis: true,
                behavioral_analysis: true,
                js_challenge: true,
                captcha_threshold: 60,
                bot_patterns: vec![
                    "bot".to_string(),
                    "crawler".to_string(),
                    "spider".to_string(),
                ],
            },
            threat_intelligence: ThreatIntelConfig {
                enabled: true,
                providers: Vec::new(),
                update_interval: 3600,
                api_keys: HashMap::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Method;

    #[tokio::test]
    async fn test_advanced_security_manager_creation() {
        let config = AdvancedSecurityConfig::default();
        let security_manager = AdvancedSecurityManager::new(config);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let assessment = security_manager.assess_request(&request, "127.0.0.1").await;
        assert!(assessment.allowed);
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let config = RateLimitConfig {
            enabled: true,
            global_rps: 2,
            per_ip_rps: 1,
            per_endpoint_rps: HashMap::new(),
            window_size: 1,
            burst_size: 1,
            algorithm: "sliding_window".to_string(),
        };

        let limiter = AdvancedRateLimiter::new(config);

        // First request should pass
        assert!(limiter.check_ip_rate_limit("127.0.0.1").await);

        // Second request within window should fail
        assert!(!limiter.check_ip_rate_limit("127.0.0.1").await);
    }

    #[tokio::test]
    async fn test_waf_rules() {
        let config = WafConfig {
            enabled: true,
            rule_sets: Vec::new(),
            custom_rules: vec![WafRule {
                id: "test_rule".to_string(),
                name: "Test Rule".to_string(),
                pattern: "admin".to_string(),
                pattern_type: "contains".to_string(),
                target: "uri".to_string(),
                action: "block".to_string(),
                severity: 3,
            }],
            paranoia_level: 2,
            mode: "block".to_string(),
        };

        let waf = WebApplicationFirewall::new(config);

        let request = Request::builder()
            .method(Method::GET)
            .uri("/admin/users")
            .body(Body::empty())
            .unwrap();

        let result = waf.check_request(&request).await;
        assert!(result.blocked);
        assert_eq!(result.rule_id, Some("test_rule".to_string()));
    }

    #[tokio::test]
    async fn test_bot_detection() {
        let config = BotDetectionConfig {
            enabled: true,
            user_agent_analysis: true,
            behavioral_analysis: true,
            js_challenge: true,
            captcha_threshold: 50,
            bot_patterns: vec!["bot".to_string()],
        };

        let detector = BotDetector::new(config);

        // Test with bot user agent
        let analysis = detector
            .analyze_request("127.0.0.1", Some("TestBot/1.0"), "/")
            .await;
        assert!(analysis.is_bot);
        assert!(analysis.confidence > 50);
    }

    #[tokio::test]
    async fn test_security_metrics() {
        let stats = SecurityStats::new();
        stats.requests_processed.store(100, Ordering::Relaxed);
        stats.requests_blocked.store(20, Ordering::Relaxed);

        let metrics = stats.get_metrics();
        assert_eq!(metrics.requests_processed, 100);
        assert_eq!(metrics.requests_blocked, 20);
        assert_eq!(metrics.block_ratio(), 0.2);
    }
}
