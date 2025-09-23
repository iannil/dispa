#![allow(dead_code)]
use crate::error::{DispaError, DispaResult};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use rustls_pemfile::{certs, private_key};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// TLS configuration for the proxy server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS support
    pub enabled: bool,
    /// Path to the certificate file (PEM format)
    pub cert_path: Option<String>,
    /// Path to the private key file (PEM format)
    pub key_path: Option<String>,
    /// Port to bind for HTTPS traffic
    pub port: u16,
    /// SNI (Server Name Indication) support
    pub sni_enabled: bool,
    /// Multiple certificate configurations for SNI
    pub certificates: Option<Vec<CertificateConfig>>,
    /// TLS version constraints
    pub min_version: Option<TlsVersion>,
    pub max_version: Option<TlsVersion>,
    /// Client certificate authentication
    pub client_auth: Option<ClientAuthConfig>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: None,
            key_path: None,
            port: 8443,
            sni_enabled: false,
            certificates: None,
            min_version: Some(TlsVersion::V1_2),
            max_version: Some(TlsVersion::V1_3),
            client_auth: None,
        }
    }
}

/// Individual certificate configuration for SNI support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfig {
    /// Domain name this certificate covers
    pub domain: String,
    /// Path to the certificate file (PEM format)
    pub cert_path: String,
    /// Path to the private key file (PEM format)
    pub key_path: String,
    /// Whether this certificate supports wildcard domains
    pub wildcard: bool,
}

/// TLS version enumeration
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TlsVersion {
    #[serde(rename = "1.2")]
    V1_2,
    #[serde(rename = "1.3")]
    V1_3,
}

/// Client certificate authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAuthConfig {
    /// Require client certificates
    pub required: bool,
    /// Path to CA certificate file for client verification
    pub ca_cert_path: String,
    /// Client certificate revocation list (optional)
    pub crl_path: Option<String>,
}

/// TLS manager for handling SSL/TLS operations
pub struct TlsManager {
    config: TlsConfig,
    server_config: Option<Arc<ServerConfig>>,
    acceptor: Option<TlsAcceptor>,
}

impl TlsManager {
    /// Create a new TLS manager
    pub fn new(config: TlsConfig) -> Self {
        Self {
            config,
            server_config: None,
            acceptor: None,
        }
    }

    /// Initialize TLS configuration
    pub async fn initialize(&mut self) -> DispaResult<()> {
        if !self.config.enabled {
            debug!("TLS is disabled");
            return Ok(());
        }

        info!("Initializing TLS configuration");

        // Create server configuration
        let server_config = self.create_server_config().await?;
        let acceptor = TlsAcceptor::from(server_config.clone());

        self.server_config = Some(server_config);
        self.acceptor = Some(acceptor);

        info!(
            port = self.config.port,
            "TLS configuration initialized successfully"
        );
        Ok(())
    }

    /// Create rustls ServerConfig
    async fn create_server_config(&self) -> DispaResult<Arc<ServerConfig>> {
        if self.config.sni_enabled && self.config.certificates.is_some() {
            self.create_sni_server_config().await
        } else {
            self.create_single_server_config().await
        }
    }

    /// Create server config for single certificate
    async fn create_single_server_config(&self) -> DispaResult<Arc<ServerConfig>> {
        let cert_path = self
            .config
            .cert_path
            .as_ref()
            .ok_or_else(|| DispaError::config("Certificate path not provided".to_string()))?;
        let key_path = self
            .config
            .key_path
            .as_ref()
            .ok_or_else(|| DispaError::config("Private key path not provided".to_string()))?;

        let (certs, key) = self.load_certificate_and_key(cert_path, key_path).await?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| DispaError::tls(format!("Failed to create TLS config: {}", e)))?;

        Ok(Arc::new(config))
    }

    /// Create server config with SNI support for multiple certificates
    async fn create_sni_server_config(&self) -> DispaResult<Arc<ServerConfig>> {
        let certificates =
            self.config.certificates.as_ref().ok_or_else(|| {
                DispaError::config("No certificates provided for SNI".to_string())
            })?;

        if certificates.is_empty() {
            return Err(DispaError::config(
                "At least one certificate required for SNI".to_string(),
            ));
        }

        // Load the first certificate as the default
        let default_cert = &certificates[0];
        let (default_certs, default_key) = self
            .load_certificate_and_key(&default_cert.cert_path, &default_cert.key_path)
            .await?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(default_certs, default_key)
            .map_err(|e| DispaError::tls(format!("Failed to create default TLS config: {}", e)))?;

        // Note: Multiple-certificate SNI would require a custom certificate resolver
        // and is not yet implemented in this simplified configuration.
        warn!("SNI support with multiple certificates is not yet fully implemented");

        Ok(Arc::new(config))
    }

    /// Load certificate and private key from files
    async fn load_certificate_and_key(
        &self,
        cert_path: &str,
        key_path: &str,
    ) -> DispaResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        debug!(cert_path = %cert_path, key_path = %key_path, "Loading certificate and key");

        // Load certificate
        let cert_file = File::open(cert_path).map_err(|e| {
            DispaError::io(format!(
                "Failed to open certificate file {}: {}",
                cert_path, e
            ))
        })?;
        let mut cert_reader = BufReader::new(cert_file);
        let cert_chain = certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| DispaError::tls(format!("Failed to parse certificate: {}", e)))?;

        // Load private key
        let key_file = File::open(key_path).map_err(|e| {
            DispaError::io(format!(
                "Failed to open private key file {}: {}",
                key_path, e
            ))
        })?;
        let mut key_reader = BufReader::new(key_file);
        let private_key = private_key(&mut key_reader)
            .map_err(|e| DispaError::tls(format!("Failed to parse private key: {}", e)))?
            .ok_or_else(|| DispaError::tls("No private keys found in key file".to_string()))?;

        debug!("Certificate and key loaded successfully");
        Ok((cert_chain, private_key))
    }

    /// Get the TLS acceptor
    pub fn acceptor(&self) -> Option<&TlsAcceptor> {
        self.acceptor.as_ref()
    }

    /// Check if TLS is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the TLS port
    pub fn port(&self) -> u16 {
        self.config.port
    }

    /// Validate certificate files exist and are readable
    pub async fn validate_certificates(&self) -> DispaResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        debug!("Validating TLS certificate files");

        if self.config.sni_enabled && self.config.certificates.is_some() {
            // Validate all SNI certificates
            let certificates = self.config.certificates.as_ref().unwrap();
            for cert_config in certificates {
                self.validate_certificate_files(&cert_config.cert_path, &cert_config.key_path)
                    .await?;
                debug!(domain = %cert_config.domain, "Certificate files validated");
            }
        } else {
            // Validate single certificate
            let cert_path =
                self.config.cert_path.as_ref().ok_or_else(|| {
                    DispaError::config("Certificate path not provided".to_string())
                })?;
            let key_path =
                self.config.key_path.as_ref().ok_or_else(|| {
                    DispaError::config("Private key path not provided".to_string())
                })?;

            self.validate_certificate_files(cert_path, key_path).await?;
        }

        info!("All TLS certificate files validated successfully");
        Ok(())
    }

    /// Validate individual certificate files
    async fn validate_certificate_files(&self, cert_path: &str, key_path: &str) -> DispaResult<()> {
        // Check if certificate file exists and is readable
        if !Path::new(cert_path).exists() {
            return Err(DispaError::config(format!(
                "Certificate file does not exist: {}",
                cert_path
            )));
        }

        if !Path::new(key_path).exists() {
            return Err(DispaError::config(format!(
                "Private key file does not exist: {}",
                key_path
            )));
        }

        // Try to load and parse the files
        let (certs, _key) = self.load_certificate_and_key(cert_path, key_path).await?;

        if certs.is_empty() {
            return Err(DispaError::config(format!(
                "No certificates found in file: {}",
                cert_path
            )));
        }

        debug!(cert_path = %cert_path, key_path = %key_path, cert_count = certs.len(), "Certificate files are valid");
        Ok(())
    }

    /// Get SNI domain for a given hostname
    pub fn get_sni_domain(&self, hostname: &str) -> Option<String> {
        if !self.config.sni_enabled || self.config.certificates.is_none() {
            return None;
        }

        let certificates = self.config.certificates.as_ref().unwrap();

        // First, try exact match
        for cert_config in certificates {
            if cert_config.domain == hostname {
                return Some(cert_config.domain.clone());
            }
        }

        // Then, try wildcard match
        for cert_config in certificates {
            if cert_config.wildcard && cert_config.domain.starts_with("*.") {
                let base_domain = &cert_config.domain[2..]; // Remove "*."
                                                            // Check if hostname ends with the base domain and has exactly one more label
                if hostname.ends_with(base_domain) && hostname.len() > base_domain.len() {
                    let prefix = &hostname[..hostname.len() - base_domain.len()];
                    // Ensure there's exactly one label before the base domain (no additional dots)
                    if prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.') {
                        return Some(cert_config.domain.clone());
                    }
                }
            }
        }

        None
    }

    /// Get server configuration
    pub fn server_config(&self) -> Option<&Arc<ServerConfig>> {
        self.server_config.as_ref()
    }
}

/// TLS certificate information
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub domains: Vec<String>,
}

impl TlsConfig {
    /// Validate TLS configuration
    pub fn validate(&self) -> DispaResult<()> {
        if !self.enabled {
            return Ok(());
        }

        if self.sni_enabled {
            if self.certificates.is_none() || self.certificates.as_ref().unwrap().is_empty() {
                return Err(DispaError::config(
                    "SNI enabled but no certificates provided".to_string(),
                ));
            }
        } else if self.cert_path.is_none() || self.key_path.is_none() {
            return Err(DispaError::config(
                "TLS enabled but certificate or key path not provided".to_string(),
            ));
        }

        if self.port == 0 {
            return Err(DispaError::config("Invalid TLS port: 0".to_string()));
        }

        // Validate certificate configurations
        if let Some(certificates) = &self.certificates {
            for cert_config in certificates {
                if cert_config.domain.is_empty() {
                    return Err(DispaError::config(
                        "Certificate domain cannot be empty".to_string(),
                    ));
                }
                if cert_config.cert_path.is_empty() || cert_config.key_path.is_empty() {
                    return Err(DispaError::config(
                        "Certificate or key path cannot be empty".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Create TLS configuration for development/testing
    pub fn development() -> Self {
        Self {
            enabled: true,
            cert_path: Some("certs/localhost.crt".to_string()),
            key_path: Some("certs/localhost.key".to_string()),
            port: 8443,
            sni_enabled: false,
            certificates: None,
            min_version: Some(TlsVersion::V1_2),
            max_version: Some(TlsVersion::V1_3),
            client_auth: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[allow(dead_code)]
    fn create_test_certificate() -> (NamedTempFile, NamedTempFile) {
        // Create a dummy certificate (not valid, just for testing file loading)
        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(b"-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----\n").unwrap();

        // Create a dummy private key
        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(b"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC\n-----END PRIVATE KEY-----\n").unwrap();

        (cert_file, key_file)
    }

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();

        assert!(!config.enabled);
        assert_eq!(config.port, 8443);
        assert!(!config.sni_enabled);
        assert!(config.cert_path.is_none());
        assert!(config.key_path.is_none());
        assert!(config.certificates.is_none());
    }

    #[test]
    fn test_tls_config_development() {
        let config = TlsConfig::development();

        assert!(config.enabled);
        assert_eq!(config.port, 8443);
        assert!(!config.sni_enabled);
        assert_eq!(config.cert_path, Some("certs/localhost.crt".to_string()));
        assert_eq!(config.key_path, Some("certs/localhost.key".to_string()));
    }

    #[test]
    fn test_tls_config_validation_disabled() {
        let config = TlsConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_tls_config_validation_enabled_missing_paths() {
        let config = TlsConfig {
            enabled: true,
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_tls_config_validation_enabled_with_paths() {
        let config = TlsConfig {
            enabled: true,
            cert_path: Some("cert.pem".to_string()),
            key_path: Some("key.pem".to_string()),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_tls_config_validation_sni_enabled_no_certificates() {
        let config = TlsConfig {
            enabled: true,
            sni_enabled: true,
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_tls_config_validation_sni_enabled_with_certificates() {
        let config = TlsConfig {
            enabled: true,
            sni_enabled: true,
            certificates: Some(vec![CertificateConfig {
                domain: "example.com".to_string(),
                cert_path: "example.crt".to_string(),
                key_path: "example.key".to_string(),
                wildcard: false,
            }]),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_tls_config_validation_invalid_port() {
        let config = TlsConfig {
            enabled: true,
            port: 0,
            cert_path: Some("cert.pem".to_string()),
            key_path: Some("key.pem".to_string()),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tls_manager_creation() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let config = TlsConfig::default();
            let manager = TlsManager::new(config);
            assert!(!manager.is_enabled());
            assert_eq!(manager.port(), 8443);
            assert!(manager.acceptor().is_none());
        })
        .await
        .expect("test_tls_manager_creation timed out");
    }

    #[tokio::test]
    async fn test_tls_manager_disabled_initialization() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let config = TlsConfig::default();
            let mut manager = TlsManager::new(config);
            let result = manager.initialize().await;
            assert!(result.is_ok());
            assert!(manager.acceptor().is_none());
        })
        .await
        .expect("test_tls_manager_disabled_initialization timed out");
    }

    #[test]
    fn test_certificate_config_validation() {
        let cert_config = CertificateConfig {
            domain: "example.com".to_string(),
            cert_path: "example.crt".to_string(),
            key_path: "example.key".to_string(),
            wildcard: false,
        };

        assert_eq!(cert_config.domain, "example.com");
        assert!(!cert_config.wildcard);
    }

    #[test]
    fn test_client_auth_config() {
        let client_auth = ClientAuthConfig {
            required: true,
            ca_cert_path: "ca.crt".to_string(),
            crl_path: Some("revoked.crl".to_string()),
        };

        assert!(client_auth.required);
        assert_eq!(client_auth.ca_cert_path, "ca.crt");
        assert_eq!(client_auth.crl_path, Some("revoked.crl".to_string()));
    }

    #[test]
    fn test_sni_domain_matching() {
        let config = TlsConfig {
            sni_enabled: true,
            certificates: Some(vec![
                CertificateConfig {
                    domain: "example.com".to_string(),
                    cert_path: "example.crt".to_string(),
                    key_path: "example.key".to_string(),
                    wildcard: false,
                },
                CertificateConfig {
                    domain: "*.api.example.com".to_string(),
                    cert_path: "api.crt".to_string(),
                    key_path: "api.key".to_string(),
                    wildcard: true,
                },
            ]),
            ..Default::default()
        };

        let manager = TlsManager::new(config);

        // Test exact match
        assert_eq!(
            manager.get_sni_domain("example.com"),
            Some("example.com".to_string())
        );

        // Test wildcard match
        assert_eq!(
            manager.get_sni_domain("v1.api.example.com"),
            Some("*.api.example.com".to_string())
        );

        // Test no match
        assert_eq!(manager.get_sni_domain("other.com"), None);
    }

    #[test]
    fn test_tls_version_serialization() {
        let v12 = TlsVersion::V1_2;
        let v13 = TlsVersion::V1_3;

        // Test that we can create versions
        assert!(matches!(v12, TlsVersion::V1_2));
        assert!(matches!(v13, TlsVersion::V1_3));
    }

    #[tokio::test]
    async fn test_certificate_file_validation_missing_files() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let config = TlsConfig {
                enabled: true,
                cert_path: Some("nonexistent.crt".to_string()),
                key_path: Some("nonexistent.key".to_string()),
                ..Default::default()
            };

            let manager = TlsManager::new(config);
            let result = manager.validate_certificates().await;
            assert!(result.is_err());
        })
        .await
        .expect("test_certificate_file_validation_missing_files timed out");
    }

    #[test]
    fn test_certificate_config_empty_domain() {
        let config = TlsConfig {
            enabled: true,
            sni_enabled: true,
            certificates: Some(vec![CertificateConfig {
                domain: "".to_string(),
                cert_path: "cert.crt".to_string(),
                key_path: "cert.key".to_string(),
                wildcard: false,
            }]),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_certificate_config_empty_paths() {
        let config = TlsConfig {
            enabled: true,
            sni_enabled: true,
            certificates: Some(vec![CertificateConfig {
                domain: "example.com".to_string(),
                cert_path: "".to_string(),
                key_path: "cert.key".to_string(),
                wildcard: false,
            }]),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_tls_manager_with_sni_disabled() {
        let config = TlsConfig {
            enabled: true,
            sni_enabled: false,
            cert_path: Some("test.crt".to_string()),
            key_path: Some("test.key".to_string()),
            ..Default::default()
        };

        let manager = TlsManager::new(config);

        // SNI domain matching should return None when SNI is disabled
        assert_eq!(manager.get_sni_domain("example.com"), None);
    }

    #[test]
    fn test_wildcard_certificate_matching() {
        let config = TlsConfig {
            sni_enabled: true,
            certificates: Some(vec![CertificateConfig {
                domain: "*.example.com".to_string(),
                cert_path: "wildcard.crt".to_string(),
                key_path: "wildcard.key".to_string(),
                wildcard: true,
            }]),
            ..Default::default()
        };

        let manager = TlsManager::new(config);

        // Test various wildcard matches
        assert_eq!(
            manager.get_sni_domain("api.example.com"),
            Some("*.example.com".to_string())
        );
        assert_eq!(
            manager.get_sni_domain("www.example.com"),
            Some("*.example.com".to_string())
        );
        assert_eq!(manager.get_sni_domain("v1.api.example.com"), None); // Doesn't match *.example.com
        assert_eq!(manager.get_sni_domain("example.com"), None); // Base domain doesn't match wildcard
    }
}
