//! Minimal end-to-end tour of the HAL.
//!
//! Every interface is constructed directly — the HAL exposes them as
//! independent types rather than as accessors on a session object, so a guest
//! takes only what it needs.
//!
//! This runs against the detected platform, so it needs SEV-SNP or TDX
//! hardware. Interfaces that do not depend on the TEE (crypto, random, clock)
//! would work anywhere; storage and attestation are exercised here because they
//! are the interesting cases.

use elastic_tee_hal::{
    ClockInterface, CryptoInterface, ElasticTeeHal, HalError, HalResult, RandomInterface,
    StorageInterface,
};

#[tokio::main]
async fn main() -> HalResult<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Initialise the HAL. Auto-detects SEV-SNP or TDX, or fails with
    // PlatformNotSupported on a host with neither.
    let hal = ElasticTeeHal::new()?;
    log::info!("ELASTIC TEE HAL initialised");
    log::info!("  - Platform: {:?}", hal.platform_type());
    log::info!("  - Initialised: {}", hal.is_initialized());

    // Capabilities are reported per detected platform, and reflect the host:
    // `attestation` is false where no evidence source is present.
    let capabilities = hal.capabilities().await;
    log::info!("  - HAL version: {}", capabilities.hal_version);
    log::info!(
        "  - Attestation available: {}",
        capabilities.features.attestation
    );

    // Attestation. `attest` binds the report data (a verifier's nonce) into
    // the hardware-signed report, so a stale report cannot be replayed.
    if capabilities.features.attestation {
        match hal.attest(b"basic_usage".as_slice()).await {
            Ok(evidence) => log::info!(
                "Attestation evidence: {} bytes ({})",
                evidence.len(),
                preview(&evidence)
            ),
            Err(e) => log::warn!("Attestation failed: {}", e),
        }
    } else {
        log::warn!("Skipping attestation: no evidence source on this host");
    }

    // Crypto: generate a key, then round-trip data through AES-256-GCM.
    let crypto = CryptoInterface::new();
    let key = crypto.generate_symmetric_key("AES-256-GCM").await?;
    log::info!("Generated AES-256-GCM key: {} bytes", key.len());

    let plaintext = b"Hello, TEE World!";
    let ciphertext = crypto
        .symmetric_encrypt("AES-256-GCM", &key, plaintext, None)
        .await?;
    let decrypted = crypto
        .symmetric_decrypt("AES-256-GCM", &key, &ciphertext, None)
        .await?;
    log::info!(
        "Encrypted {} bytes -> {} bytes, decrypted back to {:?}",
        plaintext.len(),
        ciphertext.len(),
        String::from_utf8_lossy(&decrypted)
    );

    let digest = crypto.hash_data("SHA-256", plaintext).await?;
    log::debug!("SHA-256: {}", hex::encode(&digest));

    // Storage. Uses a temporary directory so the example leaves nothing behind.
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| HalError::Internal(format!("could not create temp dir: {}", e)))?;
    let storage = StorageInterface::new(temp_dir.path()).await?;
    let container = storage.open_container("test-container", true).await?;
    log::info!("Opened encrypted container: {}", container);

    storage
        .write_object(container, "greeting", plaintext)
        .await?;
    let retrieved = storage.read_object(container, "greeting").await?;
    log::info!(
        "Stored and retrieved: {:?}",
        String::from_utf8_lossy(&retrieved)
    );

    let keys = storage.list_objects(container).await?;
    log::info!("Objects in container: {:?}", keys);

    // Random and clock need no TEE, and round out the tour.
    let nonce = RandomInterface::new().generate_nonce(32)?;
    log::info!("Generated a 32-byte nonce: {}", hex::encode(&nonce));

    let now = ClockInterface::new().read_current_time()?;
    log::info!("System time: {}.{:09}s", now.seconds, now.nanoseconds);

    Ok(())
}

/// Describe evidence bytes without dumping them.
///
/// Attestation evidence is a signed report or a signed document; printing it
/// whole would flood the terminal, and a prefix is enough to tell the two
/// evidence shapes apart in a log.
fn preview(evidence: &[u8]) -> String {
    const PREVIEW: usize = 48;
    let text = String::from_utf8_lossy(evidence);
    if text.starts_with('{') {
        "JSON document".to_string()
    } else {
        format!(
            "{} bytes, prefix {}",
            evidence.len(),
            hex::encode(&evidence[..PREVIEW.min(evidence.len())])
        )
    }
}
