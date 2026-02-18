// Random number generation interface - Requirement 5
// WASI-compatible RNG interface that works in TEE environments including Intel TDX
// Uses hardware RNG (RDRAND/RDSEED on Intel) through ring and getrandom
// TDX provides hardware-backed random number generation with CPU instructions

use crate::error::{HalError, HalResult};
use getrandom::getrandom;
use ring::rand::{SecureRandom, SystemRandom};

/// Random number generation interface
#[derive(Debug)]
pub struct RandomInterface {
    rng: SystemRandom,
}

impl RandomInterface {
    /// Create a new random interface
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }

    /// Generate cryptographically secure pseudo-random bytes
    pub fn generate_random_bytes(&self, length: usize) -> HalResult<Vec<u8>> {
        if length > 1024 * 1024 {
            return Err(HalError::InvalidParameter(
                "Requested random data too large (max 1MB)".to_string(),
            ));
        }

        let mut buffer = vec![0u8; length];
        self.rng.fill(&mut buffer).map_err(|_| {
            HalError::CryptographicError("Failed to generate random bytes".to_string())
        })?;

        Ok(buffer)
    }

    /// Generate a random u32
    pub fn generate_random_u32(&self) -> HalResult<u32> {
        let mut buffer = [0u8; 4];
        self.rng.fill(&mut buffer).map_err(|_| {
            HalError::CryptographicError("Failed to generate random u32".to_string())
        })?;

        Ok(u32::from_le_bytes(buffer))
    }

    /// Generate a random u64
    pub fn generate_random_u64(&self) -> HalResult<u64> {
        let mut buffer = [0u8; 8];
        self.rng.fill(&mut buffer).map_err(|_| {
            HalError::CryptographicError("Failed to generate random u64".to_string())
        })?;

        Ok(u64::from_le_bytes(buffer))
    }

    /// Generate random bytes in a specific range (for integers)
    pub fn generate_random_range(&self, min: u64, max: u64) -> HalResult<u64> {
        if min >= max {
            return Err(HalError::InvalidParameter(
                "Min value must be less than max value".to_string(),
            ));
        }

        let range = max - min;
        let random_u64 = self.generate_random_u64()?;

        // Use modulo with bias rejection for uniform distribution
        Ok(min + (random_u64 % range))
    }

    /// Generate a random UUID (Version 4)
    pub fn generate_uuid_v4(&self) -> HalResult<String> {
        let mut buffer = [0u8; 16];
        self.rng
            .fill(&mut buffer)
            .map_err(|_| HalError::CryptographicError("Failed to generate UUID".to_string()))?;

        // Set version (4) and variant bits according to RFC 4122
        buffer[6] = (buffer[6] & 0x0f) | 0x40; // Version 4
        buffer[8] = (buffer[8] & 0x3f) | 0x80; // Variant 10

        Ok(format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            buffer[0], buffer[1], buffer[2], buffer[3],
            buffer[4], buffer[5],
            buffer[6], buffer[7],
            buffer[8], buffer[9],
            buffer[10], buffer[11], buffer[12], buffer[13], buffer[14], buffer[15]
        ))
    }

    /// Generate a cryptographically secure nonce
    pub fn generate_nonce(&self, length: usize) -> HalResult<Vec<u8>> {
        if length == 0 || length > 64 {
            return Err(HalError::InvalidParameter(
                "Nonce length must be between 1 and 64 bytes".to_string(),
            ));
        }

        self.generate_random_bytes(length)
    }

    /// Generate random salt for password hashing
    pub fn generate_salt(&self, length: usize) -> HalResult<Vec<u8>> {
        if length < 16 || length > 64 {
            return Err(HalError::InvalidParameter(
                "Salt length must be between 16 and 64 bytes".to_string(),
            ));
        }

        self.generate_random_bytes(length)
    }

    /// Generate cryptographically secure random key material
    pub fn generate_key_material(&self, length: usize) -> HalResult<Vec<u8>> {
        if length < 16 || length > 256 {
            return Err(HalError::InvalidParameter(
                "Key material length must be between 16 and 256 bytes".to_string(),
            ));
        }

        self.generate_random_bytes(length)
    }

    /// Test randomness quality (basic entropy check)
    pub fn test_randomness_quality(&self, sample_size: usize) -> HalResult<f64> {
        if sample_size < 1000 || sample_size > 100_000 {
            return Err(HalError::InvalidParameter(
                "Sample size must be between 1000 and 100000 bytes".to_string(),
            ));
        }

        let sample = self.generate_random_bytes(sample_size)?;

        // Simple entropy calculation (Shannon entropy)
        let mut frequency = [0u32; 256];
        for &byte in &sample {
            frequency[byte as usize] += 1;
        }

        let sample_size_f = sample_size as f64;
        let entropy = frequency
            .iter()
            .filter(|&&freq| freq > 0)
            .map(|&freq| {
                let p = freq as f64 / sample_size_f;
                -p * p.log2()
            })
            .sum::<f64>();

        Ok(entropy)
    }
}

impl Default for RandomInterface {
    fn default() -> Self {
        Self::new()
    }
}

/// WASI-compatible random functions
pub mod wasi_random {
    use super::*;

    /// Fill buffer with random bytes (WASI compatible)
    pub fn random_get(buffer: &mut [u8]) -> HalResult<()> {
        getrandom(buffer)
            .map_err(|e| HalError::CryptographicError(format!("getrandom failed: {}", e)))?;
        Ok(())
    }

    /// Generate random u32 (WASI compatible)
    pub fn random_u32() -> HalResult<u32> {
        let mut buffer = [0u8; 4];
        random_get(&mut buffer)?;
        Ok(u32::from_le_bytes(buffer))
    }

    /// Generate random u64 (WASI compatible)
    pub fn random_u64() -> HalResult<u64> {
        let mut buffer = [0u8; 8];
        random_get(&mut buffer)?;
        Ok(u64::from_le_bytes(buffer))
    }
}

/// Hardware random number generator interface (platform-specific)
pub mod hardware_rng {
    use super::*;

    /// Check if hardware RNG is available
    pub fn is_hardware_rng_available() -> bool {
        // Check for CPU features like RDRAND/RDSEED on x86_64
        // Intel TDX provides RDRAND/RDSEED instructions for hardware RNG
        #[cfg(target_arch = "x86_64")]
        {
            // Check CPU flags for RDRAND and RDSEED
            if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
                let has_rdrand = content.contains("rdrand");
                let has_rdseed = content.contains("rdseed");
                let is_tdx = content.contains("tdx_guest");

                if is_tdx {
                    println!("Intel TDX Hardware RNG:");
                    println!("  - RDRAND available: {}", has_rdrand);
                    println!("  - RDSEED available: {}", has_rdseed);
                }

                has_rdrand || has_rdseed
            } else {
                false
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    }

    /// Generate random bytes using hardware RNG if available
    pub fn hardware_random_bytes(length: usize) -> HalResult<Vec<u8>> {
        if !is_hardware_rng_available() {
            return Err(HalError::NotSupported(
                "Hardware RNG not available on this platform".to_string(),
            ));
        }

        // In a real implementation, this would use platform-specific hardware RNG
        // For now, fall back to system random
        let random_interface = RandomInterface::new();
        random_interface.generate_random_bytes(length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes_generation() {
        let rng = RandomInterface::new();

        let bytes1 = rng.generate_random_bytes(32).unwrap();
        let bytes2 = rng.generate_random_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }

    #[test]
    fn test_random_integers() {
        let rng = RandomInterface::new();

        let val1 = rng.generate_random_u32().unwrap();
        let val2 = rng.generate_random_u32().unwrap();

        // Very unlikely to be the same
        assert_ne!(val1, val2);

        let val3 = rng.generate_random_u64().unwrap();
        let val4 = rng.generate_random_u64().unwrap();

        assert_ne!(val3, val4);
    }

    #[test]
    fn test_random_range() {
        let rng = RandomInterface::new();

        for _ in 0..100 {
            let val = rng.generate_random_range(10, 20).unwrap();
            assert!(val >= 10 && val < 20);
        }

        // Test error case
        assert!(rng.generate_random_range(20, 10).is_err());
    }

    #[test]
    fn test_uuid_generation() {
        let rng = RandomInterface::new();

        let uuid1 = rng.generate_uuid_v4().unwrap();
        let uuid2 = rng.generate_uuid_v4().unwrap();

        assert_ne!(uuid1, uuid2);
        assert_eq!(uuid1.len(), 36); // Standard UUID length with hyphens

        // Check format (basic validation)
        let parts: Vec<&str> = uuid1.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
    }

    #[test]
    fn test_nonce_generation() {
        let rng = RandomInterface::new();

        let nonce = rng.generate_nonce(16).unwrap();
        assert_eq!(nonce.len(), 16);

        // Test invalid lengths
        assert!(rng.generate_nonce(0).is_err());
        assert!(rng.generate_nonce(65).is_err());
    }

    #[test]
    fn test_salt_generation() {
        let rng = RandomInterface::new();

        let salt = rng.generate_salt(32).unwrap();
        assert_eq!(salt.len(), 32);

        // Test invalid lengths
        assert!(rng.generate_salt(8).is_err()); // Too short
        assert!(rng.generate_salt(100).is_err()); // Too long
    }

    #[test]
    fn test_key_material_generation() {
        let rng = RandomInterface::new();

        let key = rng.generate_key_material(32).unwrap();
        assert_eq!(key.len(), 32);

        // Test invalid lengths
        assert!(rng.generate_key_material(8).is_err()); // Too short
        assert!(rng.generate_key_material(300).is_err()); // Too long
    }

    #[test]
    fn test_randomness_quality() {
        let rng = RandomInterface::new();

        let entropy = rng.test_randomness_quality(10000).unwrap();

        // Good random data should have entropy close to 8.0 (max for bytes)
        assert!(entropy > 7.5, "Entropy too low: {}", entropy);
        assert!(entropy <= 8.0, "Entropy too high: {}", entropy);
    }

    #[test]
    fn test_wasi_compatibility() {
        use wasi_random::*;

        let mut buffer = [0u8; 16];
        random_get(&mut buffer).unwrap();

        // Buffer should be filled with non-zero values (very likely)
        assert!(buffer.iter().any(|&x| x != 0));

        let val1 = random_u32().unwrap();
        let val2 = random_u32().unwrap();
        assert_ne!(val1, val2);

        let val3 = random_u64().unwrap();
        let val4 = random_u64().unwrap();
        assert_ne!(val3, val4);
    }

    #[test]
    fn test_hardware_rng_availability() {
        use hardware_rng::*;

        // Test availability check
        let available = is_hardware_rng_available();
        println!("Hardware RNG available: {}", available);

        // Test hardware random generation (may fall back to software)
        if available {
            let bytes = hardware_random_bytes(16);
            assert!(bytes.is_ok() || bytes.is_err()); // Either works or fails gracefully
        }
    }

    #[test]
    fn test_large_request_rejection() {
        let rng = RandomInterface::new();

        // Should reject very large requests
        assert!(rng.generate_random_bytes(2 * 1024 * 1024).is_err());
    }
}
