use elastic_tee_hal::{
    CryptoInterface, ElasticTeeHal, HalResult, PlatformInterface, StorageInterface,
};

#[tokio::main]
async fn main() -> HalResult<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Initialize the HAL
    let hal = ElasticTeeHal::new()?;
    log::info!("ELASTIC TEE HAL initialized successfully");

    // Get platform information
    let platform = hal.platform();
    let platform_info = platform.get_platform_info().await?;
    log::info!(
        "Platform: {} v{}",
        platform_info.platform_type,
        platform_info.version
    );

    // Generate attestation
    if platform_info.attestation_support {
        let attestation = platform.generate_attestation().await?;
        log::info!("Generated attestation: {} bytes", attestation.len());
    }

    // Test cryptographic operations
    let crypto = hal.crypto();
    let key_pair = crypto.generate_keypair().await?;
    log::info!(
        "Generated key pair: {} byte public key",
        key_pair.public_key.len()
    );

    // Test secure storage
    let storage = hal.storage();
    let container = storage.create_container("test-container").await?;
    log::info!("Created storage container: {:?}", container);

    let data = b"Hello, TEE World!";
    let object_id = storage
        .store_object(container, "greeting", data.to_vec())
        .await?;
    log::info!("Stored object: {:?}", object_id);

    let retrieved = storage.retrieve_object(container, "greeting").await?;
    log::info!("Retrieved: {}", String::from_utf8_lossy(&retrieved));

    Ok(())
}
