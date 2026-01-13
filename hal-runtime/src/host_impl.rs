//! Host implementation of HAL WIT interfaces
//! 
//! This module bridges WIT interface calls from WASM guests to the native HAL implementation

use anyhow::Result;
use elastic_tee_hal::{
    platform::Platform,
    crypto::CryptoContext,
    storage::StorageContainer,
    clock::Clock,
    random::SecureRandom,
};

/// Host-side HAL implementation that WASM components call into
pub struct HalHost {
    platform: Platform,
    crypto: CryptoContext,
    storage: StorageContainer,
    clock: Clock,
    random: SecureRandom,
}

impl HalHost {
    pub fn new() -> Result<Self> {
        Ok(Self {
            platform: Platform::detect()?,
            crypto: CryptoContext::new()?,
            storage: StorageContainer::new()?,
            clock: Clock::new()?,
            random: SecureRandom::new()?,
        })
    }
    
    // Platform interface implementations
    pub fn platform_attestation(&mut self, report_data: Vec<u8>) -> Result<Vec<u8>, String> {
        self.platform
            .generate_attestation_report(&report_data)
            .map_err(|e| e.to_string())
    }
    
    pub fn platform_info(&self) -> PlatformInfo {
        let info = self.platform.get_info();
        PlatformInfo {
            platform_type: info.platform_type.to_string(),
            version: info.version.clone(),
            attestation_support: info.attestation_support,
        }
    }
    
    // Crypto interface implementations
    pub fn crypto_hash(&mut self, algorithm: HashAlgorithm, data: Vec<u8>) -> Result<Vec<u8>, String> {
        let algo = match algorithm {
            HashAlgorithm::Sha256 => elastic_tee_hal::crypto::HashAlgorithm::Sha256,
            HashAlgorithm::Sha384 => elastic_tee_hal::crypto::HashAlgorithm::Sha384,
            HashAlgorithm::Sha512 => elastic_tee_hal::crypto::HashAlgorithm::Sha512,
        };
        
        self.crypto
            .hash(algo, &data)
            .map_err(|e| e.to_string())
    }
    
    // Storage interface implementations
    pub fn storage_container_create(&mut self, name: String) -> Result<u64, String> {
        self.storage
            .create_container(&name)
            .map(|handle| handle.as_u64())
            .map_err(|e| e.to_string())
    }
    
    pub fn storage_object_write(
        &mut self,
        container: u64,
        key: String,
        value: Vec<u8>,
    ) -> Result<(), String> {
        self.storage
            .write_object(container.into(), &key, &value)
            .map_err(|e| e.to_string())
    }
    
    pub fn storage_object_read(
        &mut self,
        container: u64,
        key: String,
    ) -> Result<Vec<u8>, String> {
        self.storage
            .read_object(container.into(), &key)
            .map_err(|e| e.to_string())
    }
    
    // Clock interface implementations
    pub fn clock_system_time(&self) -> Result<SystemTime, String> {
        let time = self.clock
            .get_system_time()
            .map_err(|e| e.to_string())?;
        
        Ok(SystemTime {
            seconds: time.seconds,
            nanoseconds: time.nanoseconds,
        })
    }
    
    // Random interface implementations
    pub fn random_bytes(&mut self, length: u32) -> Result<Vec<u8>, String> {
        self.random
            .generate_random_bytes(length as usize)
            .map_err(|e| e.to_string())
    }
}

// WIT types mirrored from interface definitions

#[derive(Clone)]
pub struct PlatformInfo {
    pub platform_type: String,
    pub version: String,
    pub attestation_support: bool,
}

pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone)]
pub struct SystemTime {
    pub seconds: u64,
    pub nanoseconds: u32,
}
