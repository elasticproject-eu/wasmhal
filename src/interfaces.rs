// ELASTIC TEE HAL - Modular Interface Traits
// Trait-based system allowing custom implementations and composition

/// Platform interface trait
pub trait PlatformInterface: Send + Sync {
    fn attestation(&self, report_data: &[u8]) -> Result<Vec<u8>, String>;
    fn platform_info(&self) -> Result<(String, String, bool), String>;
}

/// Capabilities interface trait
pub trait CapabilitiesInterface: Send + Sync {
    fn list_capabilities(&self) -> Result<Vec<(String, bool, String)>, String>;
    fn has_capability(&self, feature_name: &str) -> Result<bool, String>;
}

/// Crypto interface trait
pub trait CryptoInterface: Send + Sync {
    fn hash(&self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, String>;
    fn encrypt(&self, data: &[u8], key: &[u8], algorithm: &str) -> Result<Vec<u8>, String>;
    fn decrypt(&self, data: &[u8], key: &[u8], algorithm: &str) -> Result<Vec<u8>, String>;
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), String>;
    fn sign(&self, data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String>;
    fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, String>;
}

/// Random interface trait
pub trait RandomInterface: Send + Sync {
    fn get_random_bytes(&self, length: u32) -> Result<Vec<u8>, String>;
    fn get_secure_random(&self, length: u32) -> Result<Vec<u8>, String>;
}

/// Clock interface trait
pub trait ClockInterface: Send + Sync {
    fn system_time(&self) -> Result<(u64, u32), String>;
    fn monotonic_time(&self) -> Result<(u64, u32), String>;
    fn resolution(&self) -> Result<u64, String>;
    fn sleep(&self, duration_ns: u64) -> Result<(), String>;
}

/// Storage interface trait
pub trait StorageInterface: Send + Sync {
    fn create_container(&self, name: &str) -> Result<u64, String>;
    fn open_container(&self, name: &str) -> Result<u64, String>;
    fn store_object(&self, container: u64, key: &str, data: &[u8]) -> Result<u64, String>;
    fn retrieve_object(&self, container: u64, key: &str) -> Result<Vec<u8>, String>;
}

/// HAL Provider - Allows custom implementations
pub struct HalProvider {
    pub platform: Option<Box<dyn PlatformInterface>>,
    pub capabilities: Option<Box<dyn CapabilitiesInterface>>,
    pub crypto: Option<Box<dyn CryptoInterface>>,
    pub random: Option<Box<dyn RandomInterface>>,
    pub clock: Option<Box<dyn ClockInterface>>,
    pub storage: Option<Box<dyn StorageInterface>>,
}

impl HalProvider {
    /// Create a new HAL provider with default implementations
    pub fn new() -> Self {
        Self {
            platform: None,
            capabilities: None,
            crypto: None,
            random: None,
            clock: None,
            storage: None,
        }
    }

    /// Create with all default implementations loaded
    pub fn with_defaults() -> Self {
        use crate::providers::*;

        Self {
            platform: DefaultPlatformProvider::new()
                .ok()
                .map(|p| Box::new(p) as Box<dyn PlatformInterface>),
            capabilities: Some(Box::new(DefaultCapabilitiesProvider::default())),
            crypto: Some(Box::new(DefaultCryptoProvider::default())),
            random: Some(Box::new(DefaultRandomProvider::default())),
            clock: Some(Box::new(DefaultClockProvider::default())),
            storage: None, // Optional
        }
    }

    /// Builder: Set custom platform implementation
    pub fn with_platform(mut self, platform: Box<dyn PlatformInterface>) -> Self {
        self.platform = Some(platform);
        self
    }

    /// Builder: Set custom crypto implementation
    pub fn with_crypto(mut self, crypto: Box<dyn CryptoInterface>) -> Self {
        self.crypto = Some(crypto);
        self
    }

    /// Builder: Set custom random implementation
    pub fn with_random(mut self, random: Box<dyn RandomInterface>) -> Self {
        self.random = Some(random);
        self
    }
}

impl Default for HalProvider {
    fn default() -> Self {
        Self::with_defaults()
    }
}
