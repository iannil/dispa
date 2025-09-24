use crate::security::auth::{
    audit::AuditLogger,
    auth_core::{AuthCore, AuthResult},
    config::*,
    mfa::MfaValidator,
    session::{SessionManager, UserSession},
};
use hyper::{Body, Request};
use std::net::IpAddr;
use tracing::{debug, info, warn};

/// Enhanced security manager that coordinates all security components
#[derive(Clone)]
pub struct EnhancedSecurityManager {
    config: EnhancedSecurityConfig,
    auth_core: AuthCore,
    session_manager: SessionManager,
    mfa_validator: MfaValidator,
    audit_logger: AuditLogger,
}

impl EnhancedSecurityManager {
    pub fn new(config: EnhancedSecurityConfig) -> Self {
        let auth_core = AuthCore::new(config.admin_auth.clone());
        let session_manager = SessionManager::new(config.session_management.clone());
        let mfa_validator = MfaValidator::new(config.mfa.clone());
        let audit_logger = AuditLogger::new(config.audit_logging.clone());

        Self {
            config,
            auth_core,
            session_manager,
            mfa_validator,
            audit_logger,
        }
    }

    /// Authenticate admin request - main entry point
    pub async fn authenticate_admin_request(
        &self,
        req: &Request<Body>,
        client_ip: IpAddr,
    ) -> AuthResult {
        if !self.config.enabled {
            return AuthResult::Allowed {
                role: AdminRole::Admin,
                session_id: None,
            };
        }

        // Check for existing session first
        if let Some(token) = self.auth_core.extract_bearer_token(req) {
            if let Some(session) = self.session_manager.get_valid_session(&token).await {
                // Update activity and return success
                self.session_manager.update_session_activity(&token).await;

                self.audit_logger
                    .log_successful_auth(&session.username, &client_ip.to_string(), "session")
                    .await;

                return AuthResult::Allowed {
                    role: session.role,
                    session_id: Some(token),
                };
            }

            // If it's a temp token for MFA, handle it
            if token.starts_with("temp_") {
                return AuthResult::MfaRequired {
                    temp_token: token,
                    username: "unknown".to_string(), // Extract from token in real impl
                };
            }
        }

        // Try Basic auth
        if let Some((username, password)) = self.auth_core.extract_basic_auth(req) {
            return self.authenticate_user_credentials(username, password, client_ip).await;
        }

        // No authentication provided
        AuthResult::Denied {
            reason: "Authentication required".to_string(),
        }
    }

    /// Authenticate user with credentials
    async fn authenticate_user_credentials(
        &self,
        username: String,
        password: String,
        client_ip: IpAddr,
    ) -> AuthResult {
        // Check if user or IP is locked out
        if self.session_manager.is_user_locked(&username, &client_ip).await {
            self.audit_logger
                .log_security_alert("LOCKED_OUT_ATTEMPT", &format!("user={} ip={}", username, client_ip))
                .await;

            return AuthResult::Denied {
                reason: "Account temporarily locked".to_string(),
            };
        }

        // Attempt authentication
        let dummy_request = Request::builder().body(Body::empty())
            .expect("Creating dummy request should not fail");

        let auth_result = self.auth_core
            .authenticate_user(&dummy_request, username.clone(), password, client_ip)
            .await;

        // Record the attempt
        let success = auth_result.is_allowed() || matches!(auth_result, AuthResult::MfaRequired { .. });
        self.session_manager
            .record_auth_attempt(&username, client_ip, success)
            .await;

        // Log the result
        match &auth_result {
            AuthResult::Allowed { role, .. } => {
                self.audit_logger
                    .log_successful_auth(&username, &client_ip.to_string(), "basic")
                    .await;

                // Create session
                let session_id = self.session_manager
                    .create_session(&username, role, client_ip)
                    .await;

                AuthResult::Allowed {
                    role: role.clone(),
                    session_id: Some(session_id),
                }
            }
            AuthResult::MfaRequired { temp_token, .. } => {
                self.audit_logger
                    .log_mfa_event(&username, "MFA_REQUIRED", true)
                    .await;

                auth_result
            }
            AuthResult::Denied { reason } => {
                self.audit_logger
                    .log_failed_auth(&username, &client_ip.to_string(), reason)
                    .await;

                auth_result
            }
            AuthResult::RateLimited { .. } => {
                self.audit_logger
                    .log_security_alert("RATE_LIMITED", &format!("user={} ip={}", username, client_ip))
                    .await;

                auth_result
            }
        }
    }

    /// Verify MFA code for temporary token
    pub async fn verify_mfa(&self, temp_token: &str, code: &str, client_ip: IpAddr) -> AuthResult {
        // In a real implementation, you'd:
        // 1. Extract username from temp token
        // 2. Get user's MFA secret
        // 3. Verify the TOTP code
        // 4. Create a full session on success

        // For now, return a placeholder
        if self.mfa_validator.verify_totp("dummy_secret", code) {
            self.audit_logger
                .log_mfa_event("extracted_username", "TOTP_VERIFIED", true)
                .await;

            AuthResult::Allowed {
                role: AdminRole::Admin, // Would be extracted from token
                session_id: Some("new_session_id".to_string()),
            }
        } else {
            self.audit_logger
                .log_mfa_event("extracted_username", "TOTP_FAILED", false)
                .await;

            AuthResult::Denied {
                reason: "Invalid MFA code".to_string(),
            }
        }
    }

    /// Logout and invalidate session
    pub async fn logout(&self, session_id: &str) {
        if let Some(session) = self.session_manager.get_valid_session(session_id).await {
            self.session_manager.remove_session(session_id).await;

            self.audit_logger
                .log_session_event(&session.username, session_id, "LOGOUT")
                .await;

            info!("User {} logged out", session.username);
        }
    }

    /// Get current session information
    pub async fn get_session(&self, session_id: &str) -> Option<UserSession> {
        self.session_manager.get_valid_session(session_id).await
    }

    /// Perform periodic cleanup
    pub async fn cleanup_expired(&self) {
        self.session_manager.cleanup_expired().await;

        if let Err(e) = self.audit_logger.cleanup_old_logs().await {
            warn!("Failed to cleanup old audit logs: {}", e);
        }

        debug!("Completed security cleanup tasks");
    }

    /// Generate new TOTP secret for user
    pub fn generate_mfa_secret(&self) -> String {
        self.mfa_validator.generate_totp_secret()
    }

    /// Generate QR code data for MFA setup
    pub fn generate_mfa_qr_data(&self, username: &str, secret: &str) -> String {
        self.mfa_validator.generate_qr_data(username, secret)
    }

    /// Hash password for storage
    pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
        AuthCore::hash_password(password)
    }

    /// Check if the manager is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Log admin action
    pub async fn log_admin_action(&self, username: &str, action: &str, target: Option<&str>) {
        self.audit_logger.log_admin_action(username, action, target).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_config() -> EnhancedSecurityConfig {
        EnhancedSecurityConfig {
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
                    password_hash: AuthCore::hash_password("password123")
                        .expect("Password hashing should work"),
                    role: AdminRole::Admin,
                    mfa_secret: None,
                    enabled: true,
                    last_login: None,
                }],
            }),
            session_management: Some(SessionConfig::default()),
            mfa: Some(MfaConfig::default()),
            password_policy: Some(PasswordPolicyConfig::default()),
            audit_logging: None, // Disable for tests
        }
    }

    #[tokio::test]
    async fn test_disabled_security() {
        let config = EnhancedSecurityConfig {
            enabled: false,
            ..Default::default()
        };
        let manager = EnhancedSecurityManager::new(config);
        let client_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let req = Request::builder().body(Body::empty())
            .expect("Creating request should not fail");

        let result = manager.authenticate_admin_request(&req, client_ip).await;

        assert!(result.is_allowed());
        assert_eq!(result.role(), Some(&AdminRole::Admin));
    }

    #[tokio::test]
    async fn test_missing_authentication() {
        let config = create_test_config();
        let manager = EnhancedSecurityManager::new(config);
        let client_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let req = Request::builder().body(Body::empty())
            .expect("Creating request should not fail");

        let result = manager.authenticate_admin_request(&req, client_ip).await;

        assert!(!result.is_allowed());
        assert!(matches!(result, AuthResult::Denied { .. }));
    }

    #[tokio::test]
    async fn test_password_hashing() {
        let password = "test123";
        let hash = EnhancedSecurityManager::hash_password(password)
            .expect("Password hashing should work");

        assert!(bcrypt::verify(password, &hash).expect("Verification should work"));
        assert!(!bcrypt::verify("wrong", &hash).expect("Verification should work"));
    }

    #[test]
    fn test_manager_creation() {
        let config = create_test_config();
        let manager = EnhancedSecurityManager::new(config);

        assert!(manager.is_enabled());
    }
}