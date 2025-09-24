use crate::security::auth::config::{AdminRole, SessionConfig};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info};

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

/// Session manager for handling user sessions
#[derive(Clone)]
pub struct SessionManager {
    config: Option<SessionConfig>,
    sessions: Arc<RwLock<HashMap<String, UserSession>>>,
    auth_attempts: Arc<RwLock<HashMap<String, AuthAttempt>>>,
    failed_ips: Arc<RwLock<HashMap<IpAddr, AuthAttempt>>>,
}

impl SessionManager {
    pub fn new(config: Option<SessionConfig>) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            auth_attempts: Arc::new(RwLock::new(HashMap::new())),
            failed_ips: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new session for authenticated user
    pub async fn create_session(&self, username: &str, role: &AdminRole, ip: IpAddr) -> String {
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

        info!("Created new session for user: {}", username);
        session_id
    }

    /// Get a valid session if it exists and hasn't expired
    pub async fn get_valid_session(&self, session_id: &str) -> Option<UserSession> {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(session_id) {
            if self.is_session_valid(session) {
                return Some(session.clone());
            }
        }
        None
    }

    /// Update session activity timestamp
    pub async fn update_session_activity(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_activity = SystemTime::now();
            debug!("Updated activity for session: {}", session_id);
        }
    }

    /// Remove a session
    pub async fn remove_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(session_id).is_some() {
            info!("Removed session: {}", session_id);
        }
    }

    /// Check if a user is locked out
    pub async fn is_user_locked(&self, username: &str, ip: &IpAddr) -> bool {
        // Check username-based lockout
        if let Some(attempt) = self.auth_attempts.read().await.get(username) {
            if let Some(locked_until) = attempt.locked_until {
                if SystemTime::now() < locked_until {
                    debug!("User {} is locked until {:?}", username, locked_until);
                    return true;
                }
            }
        }

        // Check IP-based lockout
        if let Some(attempt) = self.failed_ips.read().await.get(ip) {
            if let Some(locked_until) = attempt.locked_until {
                if SystemTime::now() < locked_until {
                    debug!("IP {} is locked until {:?}", ip, locked_until);
                    return true;
                }
            }
        }

        false
    }

    /// Record an authentication attempt
    pub async fn record_auth_attempt(&self, username: &str, ip: IpAddr, success: bool) {
        let now = SystemTime::now();

        // Record attempt by username
        {
            let mut attempts = self.auth_attempts.write().await;
            let attempt = attempts.entry(username.to_string()).or_insert(AuthAttempt {
                username: username.to_string(),
                ip_address: ip,
                timestamp: now,
                success: false,
                failure_count: 0,
                locked_until: None,
            });

            if success {
                // Reset failure count on successful authentication
                attempt.failure_count = 0;
                attempt.success = true;
                attempt.locked_until = None;
            } else {
                attempt.failure_count += 1;
                attempt.success = false;
                attempt.timestamp = now;

                // Apply lockout if max attempts reached
                if let Some(config) = &self.config {
                    if attempt.failure_count >= 3 {
                        // Use a default max attempts if not in session config
                        let lockout_duration = Duration::from_secs(15 * 60); // 15 minutes default
                        attempt.locked_until = Some(now + lockout_duration);
                        info!("User {} locked out until {:?}", username, attempt.locked_until);
                    }
                }
            }
        }

        // Record attempt by IP
        if !success {
            let mut ip_attempts = self.failed_ips.write().await;
            let attempt = ip_attempts.entry(ip).or_insert(AuthAttempt {
                username: username.to_string(),
                ip_address: ip,
                timestamp: now,
                success: false,
                failure_count: 0,
                locked_until: None,
            });

            attempt.failure_count += 1;
            attempt.timestamp = now;

            // Apply IP-based lockout
            if attempt.failure_count >= 5 {
                // More lenient for IP-based lockout
                let lockout_duration = Duration::from_secs(30 * 60); // 30 minutes
                attempt.locked_until = Some(now + lockout_duration);
                info!("IP {} locked out until {:?}", ip, attempt.locked_until);
            }
        }
    }

    /// Clean up expired sessions and lockouts
    pub async fn cleanup_expired(&self) {
        let now = SystemTime::now();

        // Clean up expired sessions
        {
            let mut sessions = self.sessions.write().await;
            sessions.retain(|_, session| self.is_session_valid(session));
            info!("Cleaned up expired sessions, {} remaining", sessions.len());
        }

        // Clean up expired lockouts
        {
            let mut attempts = self.auth_attempts.write().await;
            attempts.retain(|_, attempt| {
                if let Some(locked_until) = attempt.locked_until {
                    now < locked_until
                } else {
                    true
                }
            });
        }

        {
            let mut ip_attempts = self.failed_ips.write().await;
            ip_attempts.retain(|_, attempt| {
                if let Some(locked_until) = attempt.locked_until {
                    now < locked_until
                } else {
                    true
                }
            });
        }
    }

    /// Check if a session is still valid (not expired)
    fn is_session_valid(&self, session: &UserSession) -> bool {
        if let Some(config) = &self.config {
            let timeout = Duration::from_secs(config.timeout_minutes as u64 * 60);
            SystemTime::now()
                .duration_since(session.last_activity)
                .map(|elapsed| elapsed < timeout)
                .unwrap_or(false)
        } else {
            // Default 1 hour timeout if no config
            let timeout = Duration::from_secs(3600);
            SystemTime::now()
                .duration_since(session.last_activity)
                .map(|elapsed| elapsed < timeout)
                .unwrap_or(false)
        }
    }

    /// Generate a secure session ID
    fn generate_session_id(&self) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789";
        let mut rng = rand::thread_rng();

        let session_id: String = (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();

        format!("sess_{}", session_id)
    }
}