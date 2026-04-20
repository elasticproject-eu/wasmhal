// Default implementations of HAL interfaces
// Wraps the existing implementation modules

use crate::interfaces::*;

/// Default platform provider using ElasticTeeHal
pub struct DefaultPlatformProvider {
    hal: crate::platform::ElasticTeeHal,
}

impl DefaultPlatformProvider {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            hal: crate::platform::ElasticTeeHal::new()
                .map_err(|e| format!("Failed to initialize HAL: {}", e))?,
        })
    }
}

impl PlatformInterface for DefaultPlatformProvider {
    fn attestation(&self, report_data: &[u8]) -> Result<Vec<u8>, String> {
        futures::executor::block_on(self.hal.attest(report_data)).map_err(|e| e.to_string())
    }

    fn platform_info(&self) -> Result<(String, String, bool), String> {
        let platform_type = format!("{:?}", self.hal.platform_type());
        let version = crate::HAL_VERSION.to_string();
        let attestation_support = true; // All supported platforms have attestation
        Ok((platform_type, version, attestation_support))
    }
}

/// Default capabilities provider
pub struct DefaultCapabilitiesProvider {
    caps: crate::capabilities::PlatformCapabilities,
}

impl Default for DefaultCapabilitiesProvider {
    fn default() -> Self {
        let platform_type = crate::platform::ElasticTeeHal::new()
            .map(|hal| hal.platform_type().clone())
            .unwrap_or(crate::platform::PlatformType::IntelTdx);

        Self {
            caps: crate::capabilities::PlatformCapabilities::new(platform_type),
        }
    }
}

impl CapabilitiesInterface for DefaultCapabilitiesProvider {
    fn list_capabilities(&self) -> Result<Vec<(String, bool, String)>, String> {
        let result = vec![
            (
                "random".to_string(),
                self.caps.features.random,
                "1.0".to_string(),
            ),
            (
                "crypto".to_string(),
                self.caps.crypto_support.hardware_acceleration,
                "1.0".to_string(),
            ),
            (
                "attestation".to_string(),
                self.caps.features.attestation,
                "1.0".to_string(),
            ),
            (
                "secure-storage".to_string(),
                self.caps.features.secure_storage,
                "1.0".to_string(),
            ),
            (
                "gpu-compute".to_string(),
                self.caps.features.gpu_compute,
                "1.0".to_string(),
            ),
        ];

        Ok(result)
    }

    fn has_capability(&self, feature_name: &str) -> Result<bool, String> {
        let has = match feature_name {
            "random" => self.caps.features.random,
            "crypto" => self.caps.crypto_support.hardware_acceleration,
            "attestation" => self.caps.features.attestation,
            "secure-storage" => self.caps.features.secure_storage,
            "gpu-compute" => self.caps.features.gpu_compute,
            _ => false,
        };
        Ok(has)
    }
}

/// Default crypto provider
#[derive(Default)]
pub struct DefaultCryptoProvider {
    crypto: crate::crypto::CryptoInterface,
}

impl CryptoInterface for DefaultCryptoProvider {
    fn hash(&self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, String> {
        futures::executor::block_on(self.crypto.hash_data(algorithm, data))
            .map_err(|e| e.to_string())
    }

    fn encrypt(&self, data: &[u8], key: &[u8], algorithm: &str) -> Result<Vec<u8>, String> {
        futures::executor::block_on(self.crypto.symmetric_encrypt(algorithm, key, data, None))
            .map_err(|e| e.to_string())
    }

    fn decrypt(&self, data: &[u8], key: &[u8], algorithm: &str) -> Result<Vec<u8>, String> {
        futures::executor::block_on(self.crypto.symmetric_decrypt(algorithm, key, data, None))
            .map_err(|e| e.to_string())
    }

    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        futures::executor::block_on(async {
            // Generate a key for Ed25519
            let key = self.crypto.generate_symmetric_key("AES-256-GCM").await?;
            let _ctx = self
                .crypto
                .load_key_context("Ed25519", &key[0..32], "signing")
                .await?;

            // Generate Ed25519 keypair manually (simplified)
            let private_key = key[0..32].to_vec();
            let public_key = key[0..32].to_vec(); // Placeholder - in real impl would derive public key

            Ok((public_key, private_key))
        })
        .map_err(|e: crate::error::HalError| e.to_string())
    }

    fn sign(&self, data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String> {
        futures::executor::block_on(async {
            let ctx = self
                .crypto
                .load_key_context("Ed25519", private_key, "signing")
                .await?;
            let sig = self.crypto.sign_data(ctx, data).await?;
            Ok(sig.signature)
        })
        .map_err(|e: crate::error::HalError| e.to_string())
    }

    fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, String> {
        futures::executor::block_on(
            self.crypto
                .verify_signature("Ed25519", public_key, data, signature),
        )
        .map_err(|e| e.to_string())
    }
}

/// Default random provider
#[derive(Default)]
pub struct DefaultRandomProvider {
    random: crate::random::RandomInterface,
}

impl RandomInterface for DefaultRandomProvider {
    fn get_random_bytes(&self, length: u32) -> Result<Vec<u8>, String> {
        self.random
            .generate_random_bytes(length as usize)
            .map_err(|e| e.to_string())
    }

    fn get_secure_random(&self, length: u32) -> Result<Vec<u8>, String> {
        // Use the same implementation for now
        self.random
            .generate_random_bytes(length as usize)
            .map_err(|e| e.to_string())
    }
}

/// Default clock provider
#[derive(Default)]
pub struct DefaultClockProvider {
    clock: crate::clock::ClockInterface,
}

impl ClockInterface for DefaultClockProvider {
    fn system_time(&self) -> Result<(u64, u32), String> {
        self.clock
            .read_current_time()
            .map(|t| (t.seconds, t.nanoseconds))
            .map_err(|e| e.to_string())
    }

    fn monotonic_time(&self) -> Result<(u64, u32), String> {
        self.clock
            .read_monotonic_time()
            .map(|t| (t.elapsed_seconds, t.elapsed_nanoseconds))
            .map_err(|e| e.to_string())
    }

    fn resolution(&self) -> Result<u64, String> {
        // Return nanosecond resolution (typical for system clocks)
        Ok(1)
    }

    fn sleep(&self, duration_ns: u64) -> Result<(), String> {
        let duration = std::time::Duration::from_nanos(duration_ns);
        futures::executor::block_on(self.clock.sleep(duration)).map_err(|e| e.to_string())
    }
}
