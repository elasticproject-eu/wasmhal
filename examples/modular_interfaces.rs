// Example: Modular HAL Interface Usage
// Demonstrates the plugin-style architecture without Wasmtime

use elastic_tee_hal::interfaces::*;
use elastic_tee_hal::providers::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    log::info!("=== ELASTIC TEE HAL - Modular Interface Demo ===\n");

    // Option 1: Use default implementations
    log::info!("1. Using default provider:");
    let provider = HalProvider::with_defaults();

    if let Some(platform) = &provider.platform {
        let (platform_type, version, attestation_support) = platform.platform_info()?;
        log::debug!("  Platform: {}", platform_type);
        log::debug!("  Version: {}", version);
        log::debug!("  Attestation: {}", attestation_support);
    }
    log::info!("");

    // Option 2: Use individual interfaces
    log::info!("2. Using individual interfaces:");

    // Random interface
    let random = DefaultRandomProvider::default();
    let random_bytes = random.get_random_bytes(32)?;
    log::debug!("  Generated {} random bytes", random_bytes.len());

    // Crypto interface
    let crypto = DefaultCryptoProvider::default();
    let test_data = b"Hello, TEE!";
    let hash = crypto.hash(test_data, "SHA-256")?;
    log::debug!("  SHA-256 hash: {} bytes", hash.len());

    // Capabilities interface
    let caps = DefaultCapabilitiesProvider::default();
    let has_rdrand = caps.has_capability("rdrand")?;
    log::debug!("  RDRAND available: {}", has_rdrand);

    // Clock interface
    let clock = DefaultClockProvider::default();
    let (seconds, nanos) = clock.system_time()?;
    log::debug!("  System time: {}.{:09} seconds", seconds, nanos);

    // Option 3: Custom composition
    log::info!("3. Custom composition:");
    let mut custom_provider = HalProvider::new();
    if let Ok(platform) = DefaultPlatformProvider::new() {
        custom_provider.platform = Some(Box::new(platform));
    }
    custom_provider.crypto = Some(Box::new(DefaultCryptoProvider::default()));
    custom_provider.random = Some(Box::new(DefaultRandomProvider::default()));

    log::info!("  ✓ Custom provider with interfaces");
    log::info!("");

    // Option 4: Test attestation
    log::info!("4. Platform attestation:");
    if let Some(platform) = &provider.platform {
        let nonce = b"test_nonce_for_attestation_demo_";
        match platform.attestation(nonce) {
            Ok(attestation) => {
                log::info!("  ✓ Attestation generated: {} bytes", attestation.len());
            }
            Err(e) => {
                log::warn!("  ⚠ Attestation error: {}", e);
            }
        }
    }

    // Option 5: Crypto operations
    log::info!("5. Cryptographic operations:");
    let keypair = crypto.generate_keypair()?;
    log::info!("  ✓ Keypair generated:");
    log::debug!("    Public key: {} bytes", keypair.0.len());
    log::debug!("    Private key: {} bytes", keypair.1.len());

    let message = b"Sign this message";
    let signature = crypto.sign(message, &keypair.1)?;
    log::info!("  ✓ Signature: {} bytes", signature.len());

    let valid = crypto.verify(message, &signature, &keypair.0)?;
    log::info!("  ✓ Signature valid: {}", valid);
    log::info!("");

    log::info!("=== All operations completed successfully ===");

    Ok(())
}
