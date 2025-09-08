use elastic_tee_hal::{
    ElasticTeeHal, CryptoInterface, StorageInterface, PlatformInterface,
    HalResult
};

#[tokio::main]
async fn main() -> HalResult<()> {
    // Initialize the HAL
    let hal = ElasticTeeHal::new()?;
    println!("ELASTIC TEE HAL initialized successfully");

    // Get platform information
    let platform = hal.platform();
    let platform_info = platform.get_platform_info().await?;
    println!("Platform: {} v{}", platform_info.platform_type, platform_info.version);

    // Generate attestation
    if platform_info.attestation_support {
        let attestation = platform.generate_attestation().await?;
        println!("Generated attestation: {} bytes", attestation.len());
    }

    // Test cryptographic operations
    let crypto = hal.crypto();
    let key_pair = crypto.generate_keypair().await?;
    println!("Generated key pair: {} byte public key", key_pair.public_key.len());

    // Test secure storage
    let storage = hal.storage();
    let container = storage.create_container("test-container").await?;
    println!("Created storage container: {:?}", container);

    let data = b"Hello, TEE World!";
    let object_id = storage.store_object(container, "greeting", data.to_vec()).await?;
    println!("Stored object: {:?}", object_id);

    let retrieved = storage.retrieve_object(container, "greeting").await?;
    println!("Retrieved: {}", String::from_utf8_lossy(&retrieved));

    Ok(())
}
