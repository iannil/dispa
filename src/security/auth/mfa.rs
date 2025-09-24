use crate::security::auth::config::MfaConfig;
use tracing::{debug, warn};

/// Multi-factor authentication validator
#[derive(Clone)]
pub struct MfaValidator {
    config: Option<MfaConfig>,
}

impl MfaValidator {
    pub fn new(config: Option<MfaConfig>) -> Self {
        Self { config }
    }

    /// Verify TOTP code
    pub fn verify_totp(&self, secret: &str, code: &str) -> bool {
        if self.config.is_none() {
            return true; // MFA disabled
        }

        // In a real implementation, you'd use a proper TOTP library
        // For now, we'll implement a simple validation
        if code.len() != 6 {
            return false;
        }

        // Mock validation - in production, use a proper TOTP implementation
        // like the `totp-lite` or `google-authenticator` crate
        self.validate_totp_code(secret, code)
    }

    /// Generate backup codes for a user
    pub fn generate_backup_codes(&self) -> Vec<String> {
        let config = match &self.config {
            Some(config) => config,
            None => return vec![], // MFA disabled
        };

        let mut codes = Vec::new();
        for _ in 0..config.backup_codes {
            codes.push(self.generate_backup_code());
        }
        codes
    }

    /// Verify a backup code
    pub fn verify_backup_code(&self, user_codes: &mut Vec<String>, provided_code: &str) -> bool {
        if let Some(pos) = user_codes.iter().position(|code| code == provided_code) {
            user_codes.remove(pos); // Use the code (single use)
            debug!("Backup code verified and consumed");
            true
        } else {
            debug!("Invalid backup code provided");
            false
        }
    }

    /// Generate QR code data for TOTP setup
    pub fn generate_qr_data(&self, username: &str, secret: &str) -> String {
        let issuer = self
            .config
            .as_ref()
            .map(|c| c.totp_issuer.as_str())
            .unwrap_or("Dispa");

        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}",
            issuer, username, secret, issuer
        )
    }

    /// Generate a new TOTP secret
    pub fn generate_totp_secret(&self) -> String {
        use rand::Rng;
        const BASE32_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut rng = rand::thread_rng();

        (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..BASE32_CHARS.len());
                BASE32_CHARS[idx] as char
            })
            .collect()
    }

    /// Check if MFA is required for admin role
    pub fn is_mfa_required_for_admin(&self) -> bool {
        self.config
            .as_ref()
            .map(|c| c.require_for_admin)
            .unwrap_or(false)
    }

    /// Validate TOTP code against secret
    fn validate_totp_code(&self, secret: &str, code: &str) -> bool {
        // Simplified TOTP validation
        // In production, use a proper library like `totp-lite`

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time calculation should not fail")
            .as_secs();

        // TOTP uses 30-second windows
        let time_window = current_time / 30;

        // Check current window and adjacent windows (to account for clock skew)
        for window_offset in -1..=1i64 {
            let test_window = (time_window as i64 + window_offset) as u64;
            let expected_code = self.generate_totp_for_window(secret, test_window);

            if expected_code == code {
                debug!("TOTP code validated for window offset: {}", window_offset);
                return true;
            }
        }

        warn!("TOTP code validation failed");
        false
    }

    /// Generate TOTP code for a specific time window
    fn generate_totp_for_window(&self, secret: &str, window: u64) -> String {
        // Simplified TOTP generation
        // In production, implement proper HMAC-SHA1 based TOTP

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        secret.hash(&mut hasher);
        window.hash(&mut hasher);
        let hash = hasher.finish();

        // Generate 6-digit code
        format!("{:06}", hash % 1_000_000)
    }

    /// Generate a secure backup code
    fn generate_backup_code(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Generate 8-character alphanumeric code
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let code: String = (0..8)
            .map(|_| {
                let idx = rng.gen_range(0..CHARS.len());
                CHARS[idx] as char
            })
            .collect();

        // Format as XXX-XXX-XX for readability
        format!("{}-{}-{}", &code[0..3], &code[3..6], &code[6..8])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfa_disabled() {
        let mfa = MfaValidator::new(None);
        assert!(mfa.verify_totp("secret", "123456"));
    }

    #[test]
    fn test_backup_code_generation() {
        let config = MfaConfig {
            enabled: true,
            require_for_admin: true,
            totp_issuer: "Test".to_string(),
            backup_codes: 5,
        };
        let mfa = MfaValidator::new(Some(config));

        let codes = mfa.generate_backup_codes();
        assert_eq!(codes.len(), 5);

        // Check format
        for code in codes {
            assert_eq!(code.len(), 10); // XXX-XXX-XX format
            assert!(code.chars().nth(3) == Some('-'));
            assert!(code.chars().nth(7) == Some('-'));
        }
    }

    #[test]
    fn test_backup_code_consumption() {
        let mfa = MfaValidator::new(None);
        let mut codes = vec!["ABC-DEF-12".to_string(), "GHI-JKL-34".to_string()];

        // Valid code should be consumed
        assert!(mfa.verify_backup_code(&mut codes, "ABC-DEF-12"));
        assert_eq!(codes.len(), 1);
        assert_eq!(codes[0], "GHI-JKL-34");

        // Same code should no longer work
        assert!(!mfa.verify_backup_code(&mut codes, "ABC-DEF-12"));
        assert_eq!(codes.len(), 1);
    }

    #[test]
    fn test_qr_data_generation() {
        let config = MfaConfig {
            enabled: true,
            require_for_admin: true,
            totp_issuer: "TestApp".to_string(),
            backup_codes: 10,
        };
        let mfa = MfaValidator::new(Some(config));

        let qr_data = mfa.generate_qr_data("testuser", "TESTSECRET123");
        assert!(qr_data.contains("otpauth://totp/"));
        assert!(qr_data.contains("TestApp"));
        assert!(qr_data.contains("testuser"));
        assert!(qr_data.contains("TESTSECRET123"));
    }

    #[test]
    fn test_secret_generation() {
        let mfa = MfaValidator::new(None);
        let secret = mfa.generate_totp_secret();

        assert_eq!(secret.len(), 32);
        assert!(secret
            .chars()
            .all(|c| "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(c)));
    }
}
