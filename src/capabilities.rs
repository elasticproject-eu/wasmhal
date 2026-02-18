// Platform capabilities interface - Requirement 15

use crate::error::HalResult;
use crate::platform::PlatformType;
use serde::{Deserialize, Serialize};

/// HAL Platform Capabilities Interface
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    pub platform_type: PlatformType,
    pub hal_version: String,
    pub features: CapabilityFeatures,
    pub limits: PlatformLimits,
    pub crypto_support: CryptoSupport,
}

/// Capability features supported by the platform
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityFeatures {
    pub clock: bool,
    pub random: bool,
    pub storage: bool,
    pub secure_storage: bool,
    pub tcp_sockets: bool,
    pub udp_sockets: bool,
    pub tls_support: bool,
    pub dtls_support: bool,
    pub gpu_compute: bool,
    pub dynamic_resources: bool,
    pub event_handling: bool,
    pub internal_communication: bool,
    pub attestation: bool,
}

/// Platform resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformLimits {
    pub max_memory_mb: u64,
    pub max_cpu_cores: u32,
    pub max_storage_mb: u64,
    pub max_open_sockets: u32,
    pub max_event_handlers: u32,
    pub max_comm_buffers: u32,
}

/// Cryptographic algorithm support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoSupport {
    pub symmetric_ciphers: Vec<String>,
    pub asymmetric_ciphers: Vec<String>,
    pub hash_algorithms: Vec<String>,
    pub signature_schemes: Vec<String>,
    pub key_exchange: Vec<String>,
    pub hardware_acceleration: bool,
}

impl PlatformCapabilities {
    /// Create capabilities for a specific platform type
    pub fn new(platform_type: PlatformType) -> Self {
        let features = match platform_type {
            PlatformType::AmdSev => CapabilityFeatures {
                clock: true,
                random: true,
                storage: true,
                secure_storage: true,
                tcp_sockets: true,
                udp_sockets: true,
                tls_support: true,
                dtls_support: true,
                gpu_compute: true, // AMD SEV supports GPU passthrough
                dynamic_resources: true,
                event_handling: true,
                internal_communication: true,
                attestation: true,
            },
            PlatformType::IntelTdx => CapabilityFeatures {
                clock: true,                  // ✅ Fully implemented with TSC
                random: true,                 // ✅ Fully implemented with RDRAND/RDSEED
                storage: true,                // ✅ Fully implemented with encrypted FS
                secure_storage: true,         // ✅ Fully implemented with AES-256-GCM
                tcp_sockets: true,            // ✅ Fully implemented with TLS 1.3
                udp_sockets: true,            // ✅ Fully implemented
                tls_support: true,            // ✅ Fully implemented with rustls
                dtls_support: true,           // ✅ Fully implemented
                gpu_compute: false,           // ❌ Limited - No direct GPU passthrough in TDX
                dynamic_resources: true,      // ✅ Fully implemented with TEE overhead accounting
                event_handling: true,         // ✅ Fully implemented with secure channels
                internal_communication: true, // ✅ Fully implemented with TDX memory encryption
                attestation: true,            // ✅ Fully implemented with TD Quote + MRTD/RTMR
            },
        };

        let limits = PlatformLimits {
            max_memory_mb: 16384, // 16GB default
            max_cpu_cores: 16,
            max_storage_mb: 102400, // 100GB default
            max_open_sockets: 1024,
            max_event_handlers: 256,
            max_comm_buffers: 128,
        };

        let crypto_support = CryptoSupport {
            symmetric_ciphers: vec![
                "AES-128-GCM".to_string(),
                "AES-256-GCM".to_string(),
                "ChaCha20-Poly1305".to_string(),
            ],
            asymmetric_ciphers: vec![
                "RSA-2048".to_string(),
                "RSA-4096".to_string(),
                "ECDSA-P256".to_string(),
                "Ed25519".to_string(),
            ],
            hash_algorithms: vec![
                "SHA-256".to_string(),
                "SHA-384".to_string(),
                "SHA-512".to_string(),
                "BLAKE3".to_string(),
            ],
            signature_schemes: vec![
                "RSA-PSS".to_string(),
                "ECDSA".to_string(),
                "Ed25519".to_string(),
            ],
            key_exchange: vec!["ECDH-P256".to_string(), "X25519".to_string()],
            hardware_acceleration: true, // Both TDX and SEV-SNP support AES-NI
        };

        Self {
            platform_type,
            hal_version: crate::HAL_VERSION.to_string(),
            features,
            limits,
            crypto_support,
        }
    }

    /// Get platform HAL support information
    pub fn get_platform_hal_support(&self) -> HalResult<String> {
        let support_info = serde_json::json!({
            "platform": self.platform_type,
            "hal_version": self.hal_version,
            "supported_features": self.features,
            "platform_limits": self.limits,
            "cryptographic_support": self.crypto_support
        });

        Ok(serde_json::to_string_pretty(&support_info)?)
    }

    /// Check if a specific feature is supported
    pub fn is_feature_supported(&self, feature: &str) -> bool {
        match feature {
            "clock" => self.features.clock,
            "random" => self.features.random,
            "storage" => self.features.storage,
            "secure_storage" => self.features.secure_storage,
            "tcp_sockets" => self.features.tcp_sockets,
            "udp_sockets" => self.features.udp_sockets,
            "tls_support" => self.features.tls_support,
            "dtls_support" => self.features.dtls_support,
            "gpu_compute" => self.features.gpu_compute,
            "dynamic_resources" => self.features.dynamic_resources,
            "event_handling" => self.features.event_handling,
            "internal_communication" => self.features.internal_communication,
            "attestation" => self.features.attestation,
            _ => false,
        }
    }

    /// Check if a cryptographic algorithm is supported
    pub fn is_crypto_supported(&self, algorithm_type: &str, algorithm: &str) -> bool {
        match algorithm_type {
            "symmetric" => self
                .crypto_support
                .symmetric_ciphers
                .contains(&algorithm.to_string()),
            "asymmetric" => self
                .crypto_support
                .asymmetric_ciphers
                .contains(&algorithm.to_string()),
            "hash" => self
                .crypto_support
                .hash_algorithms
                .contains(&algorithm.to_string()),
            "signature" => self
                .crypto_support
                .signature_schemes
                .contains(&algorithm.to_string()),
            "key_exchange" => self
                .crypto_support
                .key_exchange
                .contains(&algorithm.to_string()),
            _ => false,
        }
    }

    /// Get resource limits for a specific resource type
    pub fn get_resource_limit(&self, resource_type: &str) -> Option<u64> {
        match resource_type {
            "memory_mb" => Some(self.limits.max_memory_mb),
            "cpu_cores" => Some(self.limits.max_cpu_cores as u64),
            "storage_mb" => Some(self.limits.max_storage_mb),
            "open_sockets" => Some(self.limits.max_open_sockets as u64),
            "event_handlers" => Some(self.limits.max_event_handlers as u64),
            "comm_buffers" => Some(self.limits.max_comm_buffers as u64),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amd_sev_capabilities() {
        let caps = PlatformCapabilities::new(PlatformType::AmdSev);
        assert!(caps.features.gpu_compute);
        assert!(caps.features.attestation);
        assert!(caps.is_feature_supported("gpu_compute"));
    }

    #[test]
    fn test_crypto_support() {
        let caps = PlatformCapabilities::new(PlatformType::AmdSev);
        assert!(caps.is_crypto_supported("symmetric", "AES-256-GCM"));
        assert!(caps.is_crypto_supported("hash", "SHA-256"));
        assert!(!caps.is_crypto_supported("symmetric", "DES"));
    }

    #[test]
    fn test_resource_limits() {
        let caps = PlatformCapabilities::new(PlatformType::AmdSev);
        assert_eq!(caps.get_resource_limit("memory_mb"), Some(16384));
        assert_eq!(caps.get_resource_limit("unknown"), None);
    }
}
