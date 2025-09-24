use serde::{Deserialize, Serialize};

/// Enhanced security configuration
///
/// Provides comprehensive security features including:
/// - Multi-factor authentication (MFA)
/// - Session management with configurable timeouts
/// - Role-based access control (RBAC)
/// - Password policies and account lockout
/// - IP whitelisting and geo-blocking
/// - Rate limiting and DDoS protection
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

impl Default for EnhancedSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            admin_auth: None,
            session_management: None,
            mfa: None,
            password_policy: None,
            audit_logging: None,
        }
    }
}

impl Default for AdminAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            require_https: true,
            allowed_ips: None,
            session_timeout_minutes: 30,
            max_failed_attempts: 3,
            lockout_duration_minutes: 15,
            users: vec![],
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_minutes: 60,
            secure_cookie: true,
            same_site: "strict".to_string(),
            max_sessions_per_user: 5,
        }
    }
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            require_for_admin: true,
            totp_issuer: "Dispa".to_string(),
            backup_codes: 10,
        }
    }
}

impl Default for PasswordPolicyConfig {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_symbols: false,
            password_history: 5,
            max_age_days: 90,
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_file: "audit.log".to_string(),
            max_size_mb: 100,
            retention_days: 90,
            log_successful_auth: false,
            log_failed_auth: true,
            log_admin_actions: true,
        }
    }
}
