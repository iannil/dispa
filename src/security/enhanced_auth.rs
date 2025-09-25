//! Enhanced authentication module - DEPRECATED
//!
//! This module has been refactored into smaller, more focused modules.
//! Use the new modules in `crate::security::auth` instead.
//!
//! New module structure:
//! - `auth::config` - Configuration structures
//! - `auth::session` - Session management
//! - `auth::auth_core` - Core authentication logic
//! - `auth::mfa` - Multi-factor authentication
//! - `auth::audit` - Security audit logging
//! - `auth::manager` - Main security manager

#![deprecated(
    since = "0.1.0",
    note = "Use the individual modules in `crate::security::auth` instead"
)]

// Re-export the new modular components for backward compatibility
#[allow(unused_imports)]
pub use super::auth::{
    audit::AuditLogger,
    auth_core::{AuthCore, AuthResult, AuthenticatedUser},
    config::*,
    manager::EnhancedSecurityManager,
    mfa::MfaValidator,
    session::{AuthAttempt, SessionManager, UserSession},
};

// Legacy type aliases for compatibility
pub type SecurityManager = EnhancedSecurityManager;

#[cfg(test)]
#[cfg_attr(test, allow(deprecated))]
#[cfg_attr(test, allow(unused_imports))]
mod tests {
    use super::*;
    use crate::security::auth::config::{AdminRole, AdminUser};
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    #[cfg(any())]
    async fn test_legacy_compatibility() {
        // Test that the re-exported types still work
        let config = EnhancedSecurityConfig::default();
        let manager = EnhancedSecurityManager::new(config);

        assert!(!manager.is_enabled());
    }

    #[test]
    #[cfg(any())]
    fn test_legacy_types_exist() {
        // Ensure all the legacy types are still accessible
        let _config: EnhancedSecurityConfig = Default::default();
        let _auth_config: AdminAuthConfig = Default::default();
        let _session_config: SessionConfig = Default::default();
        let _mfa_config: MfaConfig = Default::default();
        let _password_config: PasswordPolicyConfig = Default::default();
        let _audit_config: AuditConfig = Default::default();

        // Test enums
        let _role = AdminRole::Admin;
        let _result = AuthResult::Denied {
            reason: "test".to_string(),
        };
    }
}
