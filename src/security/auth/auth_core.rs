use crate::security::auth::config::{AdminAuthConfig, AdminRole};
use base64::{engine::general_purpose, Engine as _};
use hyper::{Body, Request, Response, StatusCode};
use std::net::IpAddr;
use tracing::{debug, warn};

/// Authentication result
#[derive(Debug, Clone, PartialEq)]
pub enum AuthResult {
    /// Authentication successful
    Allowed {
        role: AdminRole,
        session_id: Option<String>,
    },
    /// Authentication failed
    Denied { reason: String },
    /// MFA verification required
    MfaRequired {
        temp_token: String,
        username: String,
    },
    /// Rate limited
    RateLimited { retry_after: u64 },
}

/// Authenticated user information
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub username: String,
    pub role: AdminRole,
    pub session_id: Option<String>,
}

impl AuthResult {
    /// Check if authentication was successful
    pub fn is_allowed(&self) -> bool {
        matches!(self, AuthResult::Allowed { .. })
    }

    /// Get the role if authentication was successful
    pub fn role(&self) -> Option<&AdminRole> {
        match self {
            AuthResult::Allowed { role, .. } => Some(role),
            _ => None,
        }
    }

    /// Convert to HTTP error response
    pub fn error_response(&self) -> Response<Body> {
        match self {
            AuthResult::Denied { reason } => Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Bearer")
                .body(Body::from(reason.clone()))
                .expect("Creating UNAUTHORIZED response with valid values should not fail"),
            AuthResult::MfaRequired { temp_token, .. } => Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Bearer")
                .header("X-Temp-Token", temp_token)
                .body(Body::from("MFA verification required"))
                .expect("Creating MFA response with valid values should not fail"),
            AuthResult::RateLimited { retry_after } => Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Retry-After", retry_after.to_string())
                .body(Body::from("Rate limited"))
                .expect("Creating rate limited response with valid values should not fail"),
            AuthResult::Allowed { .. } => Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .expect("Creating OK response should not fail"),
        }
    }
}

/// Core authentication functionality
#[derive(Clone)]
pub struct AuthCore {
    config: Option<AdminAuthConfig>,
}

impl AuthCore {
    pub fn new(config: Option<AdminAuthConfig>) -> Self {
        Self { config }
    }

    /// Authenticate a user with credentials
    pub async fn authenticate_user(
        &self,
        req: &Request<Body>,
        username: String,
        password: String,
        client_ip: IpAddr,
    ) -> AuthResult {
        let admin_config = match self.config.as_ref() {
            Some(config) => config,
            None => {
                return AuthResult::Denied {
                    reason: "Admin authentication not configured".to_string(),
                };
            }
        };

        // Check HTTPS requirement
        if admin_config.require_https {
            // In a real implementation, you'd check the actual protocol
            // For now, we'll assume it's checked at the HTTP server level
        }

        // Check allowed IPs
        if let Some(ref allowed_ips) = admin_config.allowed_ips {
            let client_ip_str = client_ip.to_string();
            if !allowed_ips
                .iter()
                .any(|ip| self.ip_matches(ip, &client_ip_str))
            {
                warn!("Authentication attempt from disallowed IP: {}", client_ip);
                return AuthResult::Denied {
                    reason: "IP not allowed".to_string(),
                };
            }
        }

        // Find user
        let user = match admin_config.users.iter().find(|u| u.username == username) {
            Some(user) => user,
            None => {
                debug!("User not found: {}", username);
                return AuthResult::Denied {
                    reason: "Invalid credentials".to_string(),
                };
            }
        };

        // Check if user is enabled
        if !user.enabled {
            warn!("Disabled user attempted login: {}", username);
            return AuthResult::Denied {
                reason: "Account disabled".to_string(),
            };
        }

        // Verify password
        match bcrypt::verify(&password, &user.password_hash) {
            Ok(valid) => {
                if valid {
                    // Check if MFA is required
                    if user.mfa_secret.is_some() {
                        let temp_token = self.generate_temp_token(&username).await;
                        return AuthResult::MfaRequired {
                            temp_token,
                            username: username.clone(),
                        };
                    }

                    AuthResult::Allowed {
                        role: user.role.clone(),
                        session_id: None, // Will be set by session manager
                    }
                } else {
                    debug!("Invalid password for user: {}", username);
                    AuthResult::Denied {
                        reason: "Invalid credentials".to_string(),
                    }
                }
            }
            Err(e) => {
                warn!("Password verification error for user {}: {}", username, e);
                AuthResult::Denied {
                    reason: "Authentication error".to_string(),
                }
            }
        }
    }

    /// Authenticate using Bearer token (session)
    pub async fn authenticate_token(&self, token: String, client_ip: IpAddr) -> AuthResult {
        // This will be handled by the session manager
        // For now, return a placeholder
        if token.starts_with("sess_") {
            // Session token - should be handled by SessionManager
            AuthResult::Denied {
                reason: "Session validation not implemented in this module".to_string(),
            }
        } else if token.starts_with("temp_") {
            // Temporary token for MFA
            AuthResult::MfaRequired {
                temp_token: token,
                username: "unknown".to_string(), // Should be extracted from token
            }
        } else {
            AuthResult::Denied {
                reason: "Invalid token format".to_string(),
            }
        }
    }

    /// Extract Basic auth credentials from request
    pub fn extract_basic_auth(&self, req: &Request<Body>) -> Option<(String, String)> {
        let auth_header = req.headers().get("authorization")?;
        let auth_str = auth_header.to_str().ok()?;

        if !auth_str.starts_with("Basic ") {
            return None;
        }

        let encoded = auth_str.strip_prefix("Basic ")?;
        let decoded = general_purpose::STANDARD.decode(encoded).ok()?;
        let credentials = String::from_utf8(decoded).ok()?;

        let mut parts = credentials.splitn(2, ':');
        let username = parts.next()?.to_string();
        let password = parts.next()?.to_string();

        Some((username, password))
    }

    /// Extract Bearer token from request
    pub fn extract_bearer_token(&self, req: &Request<Body>) -> Option<String> {
        let auth_header = req.headers().get("authorization")?;
        let auth_str = auth_header.to_str().ok()?;

        if !auth_str.starts_with("Bearer ") {
            return None;
        }

        auth_str.strip_prefix("Bearer ").map(|s| s.to_string())
    }

    /// Hash a password using bcrypt
    pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
        bcrypt::hash(password, bcrypt::DEFAULT_COST)
    }

    /// Generate a temporary token for MFA
    async fn generate_temp_token(&self, username: &str) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let token_part: String = (0..16)
            .map(|_| rng.gen_range(0..16))
            .map(|n| format!("{:x}", n))
            .collect();

        format!("temp_{}_{}", username, token_part)
    }

    /// Check if an IP matches a pattern (supports CIDR notation)
    fn ip_matches(&self, pattern: &str, ip: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        // Simple string match for now - in a real implementation,
        // you'd want to support CIDR notation properly
        pattern == ip
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::auth::config::{AdminRole, AdminUser};

    #[test]
    fn test_auth_result_is_allowed() {
        let allowed = AuthResult::Allowed {
            role: AdminRole::Admin,
            session_id: None,
        };
        assert!(allowed.is_allowed());

        let denied = AuthResult::Denied {
            reason: "Invalid credentials".to_string(),
        };
        assert!(!denied.is_allowed());
    }

    #[test]
    fn test_password_hashing() {
        let password = "test123";
        let hash = AuthCore::hash_password(password).expect("Password hashing should work");

        assert!(bcrypt::verify(password, &hash).expect("Verification should work"));
        assert!(!bcrypt::verify("wrong", &hash).expect("Verification should work"));
    }
}
