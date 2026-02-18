// Example: Modular HAL Interface Usage
// Demonstrates the plugin-style architecture without Wasmtime

use elastic_tee_hal::interfaces::*;
use elastic_tee_hal::providers::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ELASTIC TEE HAL - Modular Interface Demo ===\n");

    // Option 1: Use default implementations
    println!("1. Using default provider:");
    let provider = HalProvider::with_defaults();

    if let Some(platform) = &provider.platform {
        let (platform_type, version, attestation_support) = platform.platform_info()?;
        println!("  Platform: {}", platform_type);
        println!("  Version: {}", version);
        println!("  Attestation: {}", attestation_support);
    }
    println!();

    // Option 2: Use individual interfaces
    println!("2. Using individual interfaces:");

    // Random interface
    let random = DefaultRandomProvider::new();
    let random_bytes = random.get_random_bytes(32)?;
    println!("  Generated {} random bytes", random_bytes.len());

    // Crypto interface
    let crypto = DefaultCryptoProvider::new();
    let test_data = b"Hello, TEE!";
    let hash = crypto.hash(test_data, "SHA-256")?;
    println!("  SHA-256 hash: {} bytes", hash.len());

    // Capabilities interface
    let caps = DefaultCapabilitiesProvider::new();
    let has_rdrand = caps.has_capability("rdrand")?;
    println!("  RDRAND available: {}", has_rdrand);

    // Clock interface
    let clock = DefaultClockProvider::new();
    let (seconds, nanos) = clock.system_time()?;
    println!("  System time: {}.{:09} seconds", seconds, nanos);
    println!();

    // Option 3: Custom composition
    println!("3. Custom composition:");
    let mut custom_provider = HalProvider::new();
    if let Ok(platform) = DefaultPlatformProvider::new() {
        custom_provider.platform = Some(Box::new(platform));
    }
    custom_provider.crypto = Some(Box::new(DefaultCryptoProvider::new()));
    custom_provider.random = Some(Box::new(DefaultRandomProvider::new()));

    println!("  ✓ Custom provider with interfaces");
    println!();

    // Option 4: Test attestation
    println!("4. Platform attestation:");
    if let Some(platform) = &provider.platform {
        let nonce = b"test_nonce_for_attestation_demo_";
        match platform.attestation(nonce) {
            Ok(attestation) => {
                println!("  ✓ Attestation generated: {} bytes", attestation.len());
            }
            Err(e) => {
                println!("  ⚠ Attestation error: {}", e);
            }
        }
    }
    println!();

    // Option 5: Crypto operations
    println!("5. Cryptographic operations:");
    let keypair = crypto.generate_keypair()?;
    println!("  ✓ Keypair generated:");
    println!("    Public key: {} bytes", keypair.0.len());
    println!("    Private key: {} bytes", keypair.1.len());

    let message = b"Sign this message";
    let signature = crypto.sign(message, &keypair.1)?;
    println!("  ✓ Signature: {} bytes", signature.len());

    let valid = crypto.verify(message, &signature, &keypair.0)?;
    println!("  ✓ Signature valid: {}", valid);
    println!();

    println!("=== All operations completed successfully ===");

    Ok(())
}
