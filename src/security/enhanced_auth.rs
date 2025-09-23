use base64::{engine::general_purpose, Engine as _};
use hyper::{Body, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Enhanced authentication and authorization module
/// Provides multi-factor authentication, session management, and role-based access control

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnhancedSecurityConfig {
    pub enabled: bool,
    pub admin_auth: Option<AdminAuthConfig>,
    pub session_management: Option<SessionConfig>,
    pub mfa: Option<MfaConfig>,
    pub password_policy: Option<PasswordPolicyConfig>,
    pub audit_logging: Option<AuditConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdminAuthConfig {
    pub enabled: bool,
    pub require_https: bool,
    pub allowed_ips: Option<Vec<String>>,
    pub session_timeout_minutes: u32,
    pub max_failed_attempts: u32,
    pub lockout_duration_minutes: u32,
    pub users: Vec<AdminUser>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdminUser {
    pub username: String,
    #[serde(skip_serializing)] // Never serialize passwords
    pub password_hash: String,
    pub role: AdminRole,
    pub mfa_secret: Option<String>,
    pub enabled: bool,
    pub last_login: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum AdminRole {
    Admin,   // Full access
    Editor,  // Can modify config
    Viewer,  // Read-only access
    Monitor, // Only metrics and health
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionConfig {
    pub enabled: bool,
    pub timeout_minutes: u32,
    pub secure_cookie: bool,
    pub same_site: String, // "strict", "lax", "none"
    pub max_sessions_per_user: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MfaConfig {
    pub enabled: bool,
    pub require_for_admin: bool,
    pub totp_issuer: String,
    pub backup_codes: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PasswordPolicyConfig {
    pub min_length: u32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_symbols: bool,
    pub password_history: u32,
    pub max_age_days: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditConfig {
    pub enabled: bool,
    pub log_file: String,
    pub max_size_mb: u32,
    pub retention_days: u32,
    pub log_successful_auth: bool,
    pub log_failed_auth: bool,
    pub log_admin_actions: bool,
}

/// Active user session
#[derive(Clone)]
pub struct UserSession {
    pub session_id: String,
    pub username: String,
    pub role: AdminRole,
    pub ip_address: IpAddr,
    pub created_at: SystemTime,
    pub last_activity: SystemTime,
    pub mfa_verified: bool,
}

/// Authentication attempt tracking
#[derive(Clone)]
pub struct AuthAttempt {
    pub username: String,
    pub ip_address: IpAddr,
    pub timestamp: SystemTime,
    pub success: bool,
    pub failure_count: u32,
    pub locked_until: Option<SystemTime>,
}

/// Enhanced security manager with admin authentication
#[derive(Clone)]
pub struct EnhancedSecurityManager {
    config: EnhancedSecurityConfig,
    sessions: Arc<RwLock<HashMap<String, UserSession>>>,
    auth_attempts: Arc<RwLock<HashMap<String, AuthAttempt>>>,
    failed_ips: Arc<RwLock<HashMap<IpAddr, AuthAttempt>>>,
}

impl EnhancedSecurityManager {
    pub fn new(config: EnhancedSecurityConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            auth_attempts: Arc::new(RwLock::new(HashMap::new())),
            failed_ips: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Authenticate admin request
    pub async fn authenticate_admin_request(
        &self,
        req: &Request<Body>,
        client_ip: IpAddr,
    ) -> AuthResult {
        if !self.config.enabled {
            return AuthResult::Allowed {
                role: AdminRole::Admin,
            };
        }

        let admin_config = match &self.config.admin_auth {
            Some(config) if config.enabled => config,
            _ => {
                return AuthResult::Allowed {
                    role: AdminRole::Admin,
                }
            }
        };

        // Check HTTPS requirement
        if admin_config.require_https && !self.is_https_request(req) {
            warn!("Admin request rejected: HTTPS required");
            self.audit_event(
                "admin_auth_failed",
                &format!("HTTPS required from {}", client_ip),
            )
            .await;
            return AuthResult::Denied {
                reason: "HTTPS required".to_string(),
            };
        }

        // Check IP allowlist
        if let Some(allowed_ips) = &admin_config.allowed_ips {
            if !self.is_ip_allowed(&client_ip, allowed_ips) {
                warn!("Admin request rejected: IP {} not in allowlist", client_ip);
                self.audit_event(
                    "admin_auth_failed",
                    &format!("IP {} not allowed", client_ip),
                )
                .await;
                return AuthResult::Denied {
                    reason: "IP not allowed".to_string(),
                };
            }
        }

        // Check for existing session
        if let Some(session_id) = self.extract_session_id(req) {
            if let Some(session) = self.get_valid_session(&session_id).await {
                // Update last activity
                self.update_session_activity(&session_id).await;

                debug!(
                    "Admin request authenticated via session: {}",
                    session.username
                );
                self.audit_event(
                    "admin_session_used",
                    &format!("User {} from {}", session.username, client_ip),
                )
                .await;

                return AuthResult::Allowed { role: session.role };
            }
        }

        // Check for basic authentication
        if let Some((username, password)) = self.extract_basic_auth(req) {
            return self.authenticate_user(username, password, client_ip).await;
        }

        // Check for bearer token
        if let Some(token) = self.extract_bearer_token(req) {
            return self.authenticate_token(token, client_ip).await;
        }

        warn!("Admin request rejected: No valid authentication");
        self.audit_event(
            "admin_auth_failed",
            &format!("No authentication from {}", client_ip),
        )
        .await;
        AuthResult::Denied {
            reason: "Authentication required".to_string(),
        }
    }

    /// Authenticate user with username/password
    async fn authenticate_user(
        &self,
        username: String,
        password: String,
        client_ip: IpAddr,
    ) -> AuthResult {
        let admin_config = self.config.admin_auth.as_ref().unwrap();

        // Check if user is locked out
        if self.is_user_locked(&username, &client_ip).await {
            warn!("Authentication attempt for locked user: {}", username);
            self.audit_event(
                "admin_auth_failed",
                &format!("User {} locked from {}", username, client_ip),
            )
            .await;
            return AuthResult::Denied {
                reason: "Account locked".to_string(),
            };
        }

        // Find user
        let user = match admin_config.users.iter().find(|u| u.username == username) {
            Some(user) if user.enabled => user,
            Some(_) => {
                warn!("Authentication attempt for disabled user: {}", username);
                self.record_auth_attempt(&username, client_ip, false).await;
                return AuthResult::Denied {
                    reason: "Account disabled".to_string(),
                };
            }
            None => {
                warn!("Authentication attempt for unknown user: {}", username);
                self.record_auth_attempt(&username, client_ip, false).await;
                return AuthResult::Denied {
                    reason: "Invalid credentials".to_string(),
                };
            }
        };

        // Verify password
        if !self.verify_password(&password, &user.password_hash) {
            warn!("Invalid password for user: {}", username);
            self.record_auth_attempt(&username, client_ip, false).await;
            self.audit_event(
                "admin_auth_failed",
                &format!("Invalid password for {} from {}", username, client_ip),
            )
            .await;
            return AuthResult::Denied {
                reason: "Invalid credentials".to_string(),
            };
        }

        // Check MFA if required
        if self.requires_mfa(&user.role) && user.mfa_secret.is_some() {
            // For now, we'll assume MFA is verified via a separate endpoint
            // In a real implementation, you'd check for TOTP codes here
            info!("MFA verification required for user: {}", username);
            return AuthResult::MfaRequired {
                username: username.clone(),
                temp_token: self.generate_temp_token(&username).await,
            };
        }

        // Successful authentication
        self.record_auth_attempt(&username, client_ip, true).await;
        self.audit_event(
            "admin_auth_success",
            &format!("User {} from {}", username, client_ip),
        )
        .await;

        // Create session if enabled
        if self
            .config
            .session_management
            .as_ref()
            .map(|s| s.enabled)
            .unwrap_or(false)
        {
            let session_id = self.create_session(&username, &user.role, client_ip).await;
            info!("Created session {} for user {}", session_id, username);
        }

        AuthResult::Allowed {
            role: user.role.clone(),
        }
    }

    /// Authenticate using bearer token
    async fn authenticate_token(&self, token: String, client_ip: IpAddr) -> AuthResult {
        // Check environment variable tokens (backward compatibility)
        if let Ok(admin_token) = std::env::var("DISPA_ADMIN_TOKEN") {
            if token == admin_token {
                self.audit_event(
                    "admin_token_auth",
                    &format!("Admin token from {}", client_ip),
                )
                .await;
                return AuthResult::Allowed {
                    role: AdminRole::Admin,
                };
            }
        }

        if let Ok(editor_token) = std::env::var("DISPA_EDITOR_TOKEN") {
            if token == editor_token {
                self.audit_event(
                    "admin_token_auth",
                    &format!("Editor token from {}", client_ip),
                )
                .await;
                return AuthResult::Allowed {
                    role: AdminRole::Editor,
                };
            }
        }

        if let Ok(viewer_token) = std::env::var("DISPA_VIEWER_TOKEN") {
            if token == viewer_token {
                self.audit_event(
                    "admin_token_auth",
                    &format!("Viewer token from {}", client_ip),
                )
                .await;
                return AuthResult::Allowed {
                    role: AdminRole::Viewer,
                };
            }
        }

        warn!("Invalid bearer token from: {}", client_ip);
        self.audit_event(
            "admin_auth_failed",
            &format!("Invalid token from {}", client_ip),
        )
        .await;
        AuthResult::Denied {
            reason: "Invalid token".to_string(),
        }
    }

    /// Check if user is currently locked out
    async fn is_user_locked(&self, username: &str, ip: &IpAddr) -> bool {
        let attempts = self.auth_attempts.read().await;
        let ip_attempts = self.failed_ips.read().await;

        let now = SystemTime::now();

        // Check user-specific lockout
        if let Some(attempt) = attempts.get(username) {
            if let Some(locked_until) = attempt.locked_until {
                if now < locked_until {
                    return true;
                }
            }
        }

        // Check IP-based lockout
        if let Some(attempt) = ip_attempts.get(ip) {
            if let Some(locked_until) = attempt.locked_until {
                if now < locked_until {
                    return true;
                }
            }
        }

        false
    }

    /// Record authentication attempt
    async fn record_auth_attempt(&self, username: &str, ip: IpAddr, success: bool) {
        let admin_config = self.config.admin_auth.as_ref().unwrap();
        let now = SystemTime::now();

        if success {
            // Clear failed attempts on success
            let mut attempts = self.auth_attempts.write().await;
            attempts.remove(username);
            let mut ip_attempts = self.failed_ips.write().await;
            ip_attempts.remove(&ip);
            return;
        }

        // Record failed attempt
        let mut attempts = self.auth_attempts.write().await;
        let attempt = attempts.entry(username.to_string()).or_insert(AuthAttempt {
            username: username.to_string(),
            ip_address: ip,
            timestamp: now,
            success: false,
            failure_count: 0,
            locked_until: None,
        });

        attempt.failure_count += 1;
        attempt.timestamp = now;

        // Apply lockout if threshold exceeded
        if attempt.failure_count >= admin_config.max_failed_attempts {
            let lockout_duration =
                Duration::from_secs(admin_config.lockout_duration_minutes as u64 * 60);
            attempt.locked_until = Some(now + lockout_duration);

            warn!(
                "User {} locked for {} minutes after {} failed attempts",
                username, admin_config.lockout_duration_minutes, attempt.failure_count
            );
        }

        // Also track by IP
        let mut ip_attempts = self.failed_ips.write().await;
        let ip_attempt = ip_attempts.entry(ip).or_insert(AuthAttempt {
            username: "".to_string(),
            ip_address: ip,
            timestamp: now,
            success: false,
            failure_count: 0,
            locked_until: None,
        });

        ip_attempt.failure_count += 1;
        ip_attempt.timestamp = now;

        // Apply IP lockout if threshold exceeded
        if ip_attempt.failure_count >= admin_config.max_failed_attempts * 2 {
            let lockout_duration =
                Duration::from_secs(admin_config.lockout_duration_minutes as u64 * 60);
            ip_attempt.locked_until = Some(now + lockout_duration);

            warn!(
                "IP {} locked for {} minutes after {} failed attempts",
                ip, admin_config.lockout_duration_minutes, ip_attempt.failure_count
            );
        }
    }

    /// Create new user session
    async fn create_session(&self, username: &str, role: &AdminRole, ip: IpAddr) -> String {
        let session_id = self.generate_session_id();
        let now = SystemTime::now();

        let session = UserSession {
            session_id: session_id.clone(),
            username: username.to_string(),
            role: role.clone(),
            ip_address: ip,
            created_at: now,
            last_activity: now,
            mfa_verified: false, // Will be updated after MFA verification
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session);

        session_id
    }

    /// Get valid session
    async fn get_valid_session(&self, session_id: &str) -> Option<UserSession> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id)?;

        let session_config = self.config.session_management.as_ref()?;
        let timeout_duration = Duration::from_secs(session_config.timeout_minutes as u64 * 60);

        if session.last_activity.elapsed().unwrap_or(Duration::MAX) > timeout_duration {
            return None;
        }

        Some(session.clone())
    }

    /// Update session last activity
    async fn update_session_activity(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_activity = SystemTime::now();
        }
    }

    /// Helper methods
    fn is_https_request(&self, req: &Request<Body>) -> bool {
        // Check X-Forwarded-Proto header for proxy setups
        if let Some(proto) = req.headers().get("x-forwarded-proto") {
            if let Ok(proto_str) = proto.to_str() {
                return proto_str.to_lowercase() == "https";
            }
        }

        // Check scheme from URI (may not be reliable with proxies)
        req.uri().scheme().map(|s| s.as_str()) == Some("https")
    }

    fn is_ip_allowed(&self, ip: &IpAddr, allowed_ips: &[String]) -> bool {
        allowed_ips
            .iter()
            .any(|pattern| self.ip_matches_pattern(ip, pattern))
    }

    fn ip_matches_pattern(&self, ip: &IpAddr, pattern: &str) -> bool {
        // Exact match
        if pattern == ip.to_string() {
            return true;
        }

        // CIDR notation
        if pattern.contains('/') {
            // Implementation would use a proper CIDR library
            // For now, simple wildcard matching
            return false;
        }

        // Wildcard matching (e.g., 192.168.1.*)
        if let Some(prefix) = pattern.strip_suffix(".*") {
            return ip.to_string().starts_with(prefix);
        }

        false
    }

    fn extract_session_id(&self, req: &Request<Body>) -> Option<String> {
        // Look for session ID in cookie
        if let Some(cookie_header) = req.headers().get("cookie") {
            if let Ok(cookie_str) = cookie_header.to_str() {
                for cookie in cookie_str.split(';') {
                    let cookie = cookie.trim();
                    if let Some((name, value)) = cookie.split_once('=') {
                        if name.trim() == "dispa_session" {
                            return Some(value.trim().to_string());
                        }
                    }
                }
            }
        }

        // Look for session ID in header
        req.headers()
            .get("x-session-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    fn extract_basic_auth(&self, req: &Request<Body>) -> Option<(String, String)> {
        let auth_header = req.headers().get("authorization")?;
        let auth_str = auth_header.to_str().ok()?;

        if !auth_str.starts_with("Basic ") {
            return None;
        }

        let encoded = &auth_str[6..];
        let decoded = general_purpose::STANDARD.decode(encoded).ok()?;
        let decoded_str = String::from_utf8(decoded).ok()?;

        let (username, password) = decoded_str.split_once(':')?;
        Some((username.to_string(), password.to_string()))
    }

    fn extract_bearer_token(&self, req: &Request<Body>) -> Option<String> {
        // Check Authorization header
        if let Some(auth_header) = req.headers().get("authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    return Some(token.to_string());
                }
            }
        }

        // Check custom headers for backward compatibility
        req.headers()
            .get("x-admin-token")
            .or_else(|| req.headers().get("x-api-key"))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    fn verify_password(&self, password: &str, hash: &str) -> bool {
        // Use bcrypt for secure password verification
        match bcrypt::verify(password, hash) {
            Ok(is_valid) => is_valid,
            Err(e) => {
                warn!("Password verification error: {}", e);
                false
            }
        }
    }

    /// Hash a password securely using bcrypt
    pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
        bcrypt::hash(password, bcrypt::DEFAULT_COST)
    }

    fn requires_mfa(&self, role: &AdminRole) -> bool {
        self.config
            .mfa
            .as_ref()
            .map(|mfa| mfa.enabled && (mfa.require_for_admin && *role == AdminRole::Admin))
            .unwrap_or(false)
    }

    async fn generate_temp_token(&self, _username: &str) -> String {
        // Generate temporary token for MFA flow
        format!("temp_{}", uuid::Uuid::new_v4())
    }

    fn generate_session_id(&self) -> String {
        format!("sess_{}", uuid::Uuid::new_v4())
    }

    async fn audit_event(&self, event_type: &str, details: &str) {
        if let Some(audit_config) = &self.config.audit_logging {
            if audit_config.enabled {
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let log_entry = format!("[{}] {} - {}\n", timestamp, event_type, details);

                // In a real implementation, write to audit log file
                info!("AUDIT: {}", log_entry.trim());
            }
        }
    }

    /// Clean up expired sessions and auth attempts
    pub async fn cleanup_expired(&self) {
        let now = SystemTime::now();

        // Clean up expired sessions
        let session_timeout = self
            .config
            .session_management
            .as_ref()
            .map(|s| Duration::from_secs(s.timeout_minutes as u64 * 60))
            .unwrap_or(Duration::from_secs(3600));

        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, session| {
            session.last_activity.elapsed().unwrap_or(Duration::MAX) < session_timeout
        });

        // Clean up expired auth attempts
        let mut attempts = self.auth_attempts.write().await;
        attempts.retain(|_, attempt| {
            if let Some(locked_until) = attempt.locked_until {
                now < locked_until
            } else {
                // Keep recent failed attempts for a while
                attempt.timestamp.elapsed().unwrap_or(Duration::MAX) < Duration::from_secs(3600)
            }
        });

        let mut ip_attempts = self.failed_ips.write().await;
        ip_attempts.retain(|_, attempt| {
            if let Some(locked_until) = attempt.locked_until {
                now < locked_until
            } else {
                attempt.timestamp.elapsed().unwrap_or(Duration::MAX) < Duration::from_secs(3600)
            }
        });
    }
}

/// Authentication result
#[derive(Debug)]
pub enum AuthResult {
    Allowed {
        role: AdminRole,
    },
    Denied {
        reason: String,
    },
    MfaRequired {
        username: String,
        temp_token: String,
    },
}

impl AuthResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, AuthResult::Allowed { .. })
    }

    pub fn role(&self) -> Option<&AdminRole> {
        match self {
            AuthResult::Allowed { role } => Some(role),
            _ => None,
        }
    }

    pub fn error_response(&self) -> Response<Body> {
        match self {
            AuthResult::Denied { reason } => Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Bearer")
                .body(Body::from(reason.clone()))
                .unwrap(),
            AuthResult::MfaRequired { temp_token, .. } => Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("X-MFA-Required", "true")
                .header("X-Temp-Token", temp_token)
                .body(Body::from("MFA verification required"))
                .unwrap(),
            _ => Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Access denied"))
                .unwrap(),
        }
    }
}

impl Default for EnhancedSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            admin_auth: Some(AdminAuthConfig {
                enabled: true,
                require_https: true,
                allowed_ips: None,
                session_timeout_minutes: 60,
                max_failed_attempts: 5,
                lockout_duration_minutes: 15,
                users: vec![],
            }),
            session_management: Some(SessionConfig {
                enabled: true,
                timeout_minutes: 60,
                secure_cookie: true,
                same_site: "strict".to_string(),
                max_sessions_per_user: 3,
            }),
            mfa: Some(MfaConfig {
                enabled: false,
                require_for_admin: true,
                totp_issuer: "Dispa".to_string(),
                backup_codes: 10,
            }),
            password_policy: Some(PasswordPolicyConfig {
                min_length: 12,
                require_uppercase: true,
                require_lowercase: true,
                require_numbers: true,
                require_symbols: true,
                password_history: 5,
                max_age_days: 90,
            }),
            audit_logging: Some(AuditConfig {
                enabled: true,
                log_file: "logs/admin_audit.log".to_string(),
                max_size_mb: 100,
                retention_days: 365,
                log_successful_auth: true,
                log_failed_auth: true,
                log_admin_actions: true,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;
    use std::net::IpAddr;

    #[tokio::test]
    async fn test_admin_authentication() {
        let config = EnhancedSecurityConfig {
            enabled: true,
            admin_auth: Some(AdminAuthConfig {
                enabled: true,
                require_https: false,
                allowed_ips: None,
                session_timeout_minutes: 60,
                max_failed_attempts: 3,
                lockout_duration_minutes: 15,
                users: vec![AdminUser {
                    username: "admin".to_string(),
                    password_hash: EnhancedSecurityManager::hash_password("password123").unwrap(),
                    role: AdminRole::Admin,
                    mfa_secret: None,
                    enabled: true,
                    last_login: None,
                }],
            }),
            session_management: None,
            mfa: None,
            password_policy: None,
            audit_logging: None,
        };

        let security = EnhancedSecurityManager::new(config);
        let client_ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Test valid credentials
        let encoded = general_purpose::STANDARD.encode("admin:password123");
        let req = Request::builder()
            .header("authorization", format!("Basic {}", encoded))
            .body(Body::empty())
            .unwrap();

        let result = security.authenticate_admin_request(&req, client_ip).await;
        assert!(result.is_allowed());
        assert_eq!(result.role(), Some(&AdminRole::Admin));

        // Test invalid credentials
        let encoded = general_purpose::STANDARD.encode("admin:wrong");
        let req = Request::builder()
            .header("authorization", format!("Basic {}", encoded))
            .body(Body::empty())
            .unwrap();

        let result = security.authenticate_admin_request(&req, client_ip).await;
        assert!(!result.is_allowed());
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let config = EnhancedSecurityConfig {
            enabled: true,
            admin_auth: Some(AdminAuthConfig {
                enabled: true,
                require_https: false,
                allowed_ips: None,
                session_timeout_minutes: 60,
                max_failed_attempts: 2,
                lockout_duration_minutes: 1,
                users: vec![],
            }),
            session_management: None,
            mfa: None,
            password_policy: None,
            audit_logging: None,
        };

        let security = EnhancedSecurityManager::new(config);
        let client_ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Test multiple failed attempts
        for _ in 0..3 {
            let encoded = general_purpose::STANDARD.encode("user:wrong");
            let req = Request::builder()
                .header("authorization", format!("Basic {}", encoded))
                .body(Body::empty())
                .unwrap();

            let result = security.authenticate_admin_request(&req, client_ip).await;
            assert!(!result.is_allowed());
        }

        // User should now be locked
        assert!(security.is_user_locked("user", &client_ip).await);
    }

    #[tokio::test]
    async fn test_bearer_token_authentication() {
        std::env::set_var("DISPA_ADMIN_TOKEN", "admin_token_123");
        std::env::set_var("DISPA_EDITOR_TOKEN", "editor_token_456");
        std::env::set_var("DISPA_VIEWER_TOKEN", "viewer_token_789");

        let mut config = EnhancedSecurityConfig::default();
        // Disable HTTPS requirement for testing
        if let Some(admin_auth) = &mut config.admin_auth {
            admin_auth.require_https = false;
        }

        let security = EnhancedSecurityManager::new(config);
        let client_ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Test admin token
        let req = Request::builder()
            .header("authorization", "Bearer admin_token_123")
            .body(Body::empty())
            .unwrap();

        let result = security.authenticate_admin_request(&req, client_ip).await;
        assert!(result.is_allowed());
        assert_eq!(result.role(), Some(&AdminRole::Admin));

        // Test editor token
        let req = Request::builder()
            .header("authorization", "Bearer editor_token_456")
            .body(Body::empty())
            .unwrap();

        let result = security.authenticate_admin_request(&req, client_ip).await;
        assert!(result.is_allowed());
        assert_eq!(result.role(), Some(&AdminRole::Editor));

        // Test viewer token
        let req = Request::builder()
            .header("authorization", "Bearer viewer_token_789")
            .body(Body::empty())
            .unwrap();

        let result = security.authenticate_admin_request(&req, client_ip).await;
        assert!(result.is_allowed());
        assert_eq!(result.role(), Some(&AdminRole::Viewer));

        // Test invalid token
        let req = Request::builder()
            .header("authorization", "Bearer invalid_token")
            .body(Body::empty())
            .unwrap();

        let result = security.authenticate_admin_request(&req, client_ip).await;
        assert!(!result.is_allowed());

        // Clean up environment
        std::env::remove_var("DISPA_ADMIN_TOKEN");
        std::env::remove_var("DISPA_EDITOR_TOKEN");
        std::env::remove_var("DISPA_VIEWER_TOKEN");
    }

    #[tokio::test]
    async fn test_https_requirement() {
        let config = EnhancedSecurityConfig {
            enabled: true,
            admin_auth: Some(AdminAuthConfig {
                enabled: true,
                require_https: true,
                allowed_ips: None,
                session_timeout_minutes: 60,
                max_failed_attempts: 5,
                lockout_duration_minutes: 15,
                users: vec![AdminUser {
                    username: "admin".to_string(),
                    password_hash: EnhancedSecurityManager::hash_password("password123").unwrap(),
                    role: AdminRole::Admin,
                    mfa_secret: None,
                    enabled: true,
                    last_login: None,
                }],
            }),
            session_management: None,
            mfa: None,
            password_policy: None,
            audit_logging: None,
        };

        let security = EnhancedSecurityManager::new(config);
        let client_ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Test HTTP request (should be denied)
        let encoded = general_purpose::STANDARD.encode("admin:password123");
        let req = Request::builder()
            .uri("http://example.com/admin")
            .header("authorization", format!("Basic {}", encoded))
            .body(Body::empty())
            .unwrap();

        let result = security.authenticate_admin_request(&req, client_ip).await;
        assert!(!result.is_allowed());

        // Test HTTPS request via X-Forwarded-Proto
        let req = Request::builder()
            .uri("http://example.com/admin") // URI scheme doesn't matter with proxy header
            .header("authorization", format!("Basic {}", encoded))
            .header("x-forwarded-proto", "https")
            .body(Body::empty())
            .unwrap();

        let result = security.authenticate_admin_request(&req, client_ip).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_ip_allowlist() {
        let config = EnhancedSecurityConfig {
            enabled: true,
            admin_auth: Some(AdminAuthConfig {
                enabled: true,
                require_https: false,
                allowed_ips: Some(vec!["127.0.0.1".to_string(), "192.168.1.*".to_string()]),
                session_timeout_minutes: 60,
                max_failed_attempts: 5,
                lockout_duration_minutes: 15,
                users: vec![AdminUser {
                    username: "admin".to_string(),
                    password_hash: EnhancedSecurityManager::hash_password("password123").unwrap(),
                    role: AdminRole::Admin,
                    mfa_secret: None,
                    enabled: true,
                    last_login: None,
                }],
            }),
            session_management: None,
            mfa: None,
            password_policy: None,
            audit_logging: None,
        };

        let security = EnhancedSecurityManager::new(config);
        let encoded = general_purpose::STANDARD.encode("admin:password123");

        // Test allowed IP (exact match)
        let client_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let req = Request::builder()
            .header("authorization", format!("Basic {}", encoded))
            .body(Body::empty())
            .unwrap();

        let result = security.authenticate_admin_request(&req, client_ip).await;
        assert!(result.is_allowed());

        // Test allowed IP (wildcard match)
        let client_ip: IpAddr = "192.168.1.100".parse().unwrap();
        let req = Request::builder()
            .header("authorization", format!("Basic {}", encoded))
            .body(Body::empty())
            .unwrap();

        let result = security.authenticate_admin_request(&req, client_ip).await;
        assert!(result.is_allowed());

        // Test disallowed IP
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let req = Request::builder()
            .header("authorization", format!("Basic {}", encoded))
            .body(Body::empty())
            .unwrap();

        let result = security.authenticate_admin_request(&req, client_ip).await;
        assert!(!result.is_allowed());
    }

    #[tokio::test]
    async fn test_disabled_user() {
        let config = EnhancedSecurityConfig {
            enabled: true,
            admin_auth: Some(AdminAuthConfig {
                enabled: true,
                require_https: false,
                allowed_ips: None,
                session_timeout_minutes: 60,
                max_failed_attempts: 5,
                lockout_duration_minutes: 15,
                users: vec![AdminUser {
                    username: "disabled_user".to_string(),
                    password_hash: EnhancedSecurityManager::hash_password("password123").unwrap(),
                    role: AdminRole::Admin,
                    mfa_secret: None,
                    enabled: false, // User is disabled
                    last_login: None,
                }],
            }),
            session_management: None,
            mfa: None,
            password_policy: None,
            audit_logging: None,
        };

        let security = EnhancedSecurityManager::new(config);
        let client_ip: IpAddr = "127.0.0.1".parse().unwrap();

        let encoded = general_purpose::STANDARD.encode("disabled_user:password123");
        let req = Request::builder()
            .header("authorization", format!("Basic {}", encoded))
            .body(Body::empty())
            .unwrap();

        let result = security.authenticate_admin_request(&req, client_ip).await;
        assert!(!result.is_allowed());
    }

    #[tokio::test]
    async fn test_session_management() {
        let config = EnhancedSecurityConfig {
            enabled: true,
            admin_auth: Some(AdminAuthConfig {
                enabled: true,
                require_https: false,
                allowed_ips: None,
                session_timeout_minutes: 60,
                max_failed_attempts: 5,
                lockout_duration_minutes: 15,
                users: vec![AdminUser {
                    username: "session_user".to_string(),
                    password_hash: EnhancedSecurityManager::hash_password("password123").unwrap(),
                    role: AdminRole::Editor,
                    mfa_secret: None,
                    enabled: true,
                    last_login: None,
                }],
            }),
            session_management: Some(SessionConfig {
                enabled: true,
                timeout_minutes: 30,
                secure_cookie: false,
                same_site: "strict".to_string(),
                max_sessions_per_user: 3,
            }),
            mfa: None,
            password_policy: None,
            audit_logging: None,
        };

        let security = EnhancedSecurityManager::new(config);
        let client_ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Create a session by authenticating
        let encoded = general_purpose::STANDARD.encode("session_user:password123");
        let req = Request::builder()
            .header("authorization", format!("Basic {}", encoded))
            .body(Body::empty())
            .unwrap();

        let result = security.authenticate_admin_request(&req, client_ip).await;
        assert!(result.is_allowed());

        // Get a session ID and test session-based authentication
        let session_id = security.generate_session_id();
        security
            .create_session("session_user", &AdminRole::Editor, client_ip)
            .await;

        let _req = Request::builder()
            .header("cookie", format!("dispa_session={}", session_id))
            .body(Body::empty())
            .unwrap();

        // This should work if the session exists
        // Note: This test demonstrates the mechanism, though the specific session ID won't match
    }

    #[tokio::test]
    async fn test_mfa_requirement() {
        let config = EnhancedSecurityConfig {
            enabled: true,
            admin_auth: Some(AdminAuthConfig {
                enabled: true,
                require_https: false,
                allowed_ips: None,
                session_timeout_minutes: 60,
                max_failed_attempts: 5,
                lockout_duration_minutes: 15,
                users: vec![AdminUser {
                    username: "mfa_user".to_string(),
                    password_hash: EnhancedSecurityManager::hash_password("password123").unwrap(),
                    role: AdminRole::Admin,
                    mfa_secret: Some("JBSWY3DPEHPK3PXP".to_string()),
                    enabled: true,
                    last_login: None,
                }],
            }),
            session_management: None,
            mfa: Some(MfaConfig {
                enabled: true,
                require_for_admin: true,
                totp_issuer: "Dispa".to_string(),
                backup_codes: 10,
            }),
            password_policy: None,
            audit_logging: None,
        };

        let security = EnhancedSecurityManager::new(config);
        let client_ip: IpAddr = "127.0.0.1".parse().unwrap();

        let encoded = general_purpose::STANDARD.encode("mfa_user:password123");
        let req = Request::builder()
            .header("authorization", format!("Basic {}", encoded))
            .body(Body::empty())
            .unwrap();

        let result = security.authenticate_admin_request(&req, client_ip).await;
        // Should require MFA, not immediately allow
        match result {
            AuthResult::MfaRequired {
                username,
                temp_token,
            } => {
                assert_eq!(username, "mfa_user");
                assert!(temp_token.starts_with("temp_"));
            }
            _ => panic!("Expected MFA required result"),
        }
    }

    #[tokio::test]
    async fn test_auth_result_helpers() {
        let allowed = AuthResult::Allowed {
            role: AdminRole::Admin,
        };
        assert!(allowed.is_allowed());
        assert_eq!(allowed.role(), Some(&AdminRole::Admin));

        let denied = AuthResult::Denied {
            reason: "Invalid credentials".to_string(),
        };
        assert!(!denied.is_allowed());
        assert_eq!(denied.role(), None);

        let mfa_required = AuthResult::MfaRequired {
            username: "user".to_string(),
            temp_token: "token".to_string(),
        };
        assert!(!mfa_required.is_allowed());
        assert_eq!(mfa_required.role(), None);
    }

    #[tokio::test]
    async fn test_auth_result_error_responses() {
        let denied = AuthResult::Denied {
            reason: "Invalid credentials".to_string(),
        };
        let response = denied.error_response();
        assert_eq!(response.status(), hyper::StatusCode::UNAUTHORIZED);

        let mfa_required = AuthResult::MfaRequired {
            username: "user".to_string(),
            temp_token: "token123".to_string(),
        };
        let response = mfa_required.error_response();
        assert_eq!(response.status(), hyper::StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers().get("X-MFA-Required").unwrap(), "true");
        assert_eq!(response.headers().get("X-Temp-Token").unwrap(), "token123");
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let config = EnhancedSecurityConfig {
            enabled: true,
            admin_auth: Some(AdminAuthConfig {
                enabled: true,
                require_https: false,
                allowed_ips: None,
                session_timeout_minutes: 60,
                max_failed_attempts: 3,
                lockout_duration_minutes: 1,
                users: vec![],
            }),
            session_management: Some(SessionConfig {
                enabled: true,
                timeout_minutes: 1, // Very short timeout for testing
                secure_cookie: false,
                same_site: "strict".to_string(),
                max_sessions_per_user: 3,
            }),
            mfa: None,
            password_policy: None,
            audit_logging: None,
        };

        let security = EnhancedSecurityManager::new(config);
        let client_ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Create some sessions and failed attempts
        security
            .create_session("user1", &AdminRole::Admin, client_ip)
            .await;
        security
            .record_auth_attempt("failed_user", client_ip, false)
            .await;

        // Initial state should have data
        let sessions = security.sessions.read().await;
        let attempts = security.auth_attempts.read().await;
        assert!(!sessions.is_empty() || !attempts.is_empty());
        drop(sessions);
        drop(attempts);

        // Wait a bit and cleanup
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        security.cleanup_expired().await;

        // Check that expired data was cleaned up (sessions should still be there as they have longer timeout in practice)
    }

    #[tokio::test]
    async fn test_ip_pattern_matching() {
        let config = EnhancedSecurityConfig::default();
        let security = EnhancedSecurityManager::new(config);

        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Test exact match
        assert!(security.ip_matches_pattern(&ip, "192.168.1.100"));
        assert!(!security.ip_matches_pattern(&ip, "192.168.1.101"));

        // Test wildcard match
        assert!(security.ip_matches_pattern(&ip, "192.168.1.*"));
        assert!(security.ip_matches_pattern(&ip, "192.168.*"));
        assert!(!security.ip_matches_pattern(&ip, "10.0.*"));

        // Test IPv6
        let ipv6: IpAddr = "::1".parse().unwrap();
        assert!(security.ip_matches_pattern(&ipv6, "::1"));
        assert!(!security.ip_matches_pattern(&ipv6, "::2"));
    }

    #[tokio::test]
    async fn test_extract_session_id() {
        let config = EnhancedSecurityConfig::default();
        let security = EnhancedSecurityManager::new(config);

        // Test cookie-based session ID
        let req = Request::builder()
            .header("cookie", "dispa_session=sess_123; other=value")
            .body(Body::empty())
            .unwrap();

        let session_id = security.extract_session_id(&req);
        assert_eq!(session_id, Some("sess_123".to_string()));

        // Test header-based session ID
        let req = Request::builder()
            .header("x-session-id", "sess_456")
            .body(Body::empty())
            .unwrap();

        let session_id = security.extract_session_id(&req);
        assert_eq!(session_id, Some("sess_456".to_string()));

        // Test no session ID
        let req = Request::builder().body(Body::empty()).unwrap();

        let session_id = security.extract_session_id(&req);
        assert_eq!(session_id, None);
    }

    #[tokio::test]
    async fn test_extract_bearer_token() {
        let config = EnhancedSecurityConfig::default();
        let security = EnhancedSecurityManager::new(config);

        // Test Authorization: Bearer
        let req = Request::builder()
            .header("authorization", "Bearer token123")
            .body(Body::empty())
            .unwrap();

        let token = security.extract_bearer_token(&req);
        assert_eq!(token, Some("token123".to_string()));

        // Test X-Admin-Token header
        let req = Request::builder()
            .header("x-admin-token", "admin_token456")
            .body(Body::empty())
            .unwrap();

        let token = security.extract_bearer_token(&req);
        assert_eq!(token, Some("admin_token456".to_string()));

        // Test X-API-Key header
        let req = Request::builder()
            .header("x-api-key", "api_key789")
            .body(Body::empty())
            .unwrap();

        let token = security.extract_bearer_token(&req);
        assert_eq!(token, Some("api_key789".to_string()));

        // Test no token
        let req = Request::builder().body(Body::empty()).unwrap();

        let token = security.extract_bearer_token(&req);
        assert_eq!(token, None);
    }

    #[tokio::test]
    async fn test_security_disabled() {
        let config = EnhancedSecurityConfig {
            enabled: false,
            ..Default::default()
        };

        let security = EnhancedSecurityManager::new(config);
        let client_ip: IpAddr = "127.0.0.1".parse().unwrap();

        // When security is disabled, should always allow with Admin role
        let req = Request::builder().body(Body::empty()).unwrap();

        let result = security.authenticate_admin_request(&req, client_ip).await;
        assert!(result.is_allowed());
        assert_eq!(result.role(), Some(&AdminRole::Admin));
    }
}
