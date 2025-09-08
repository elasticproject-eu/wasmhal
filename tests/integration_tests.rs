use elastic_tee_hal::*;

#[tokio::test]
async fn test_platform_integration() {
    let hal = ElasticTeeHal::new().expect("Failed to create HAL");
    let platform = hal.platform();
    
    let info = platform.get_platform_info().await.expect("Failed to get platform info");
    assert!(!info.platform_type.is_empty());
    assert!(!info.version.is_empty());
}

#[tokio::test]
async fn test_crypto_integration() {
    let hal = ElasticTeeHal::new().expect("Failed to create HAL");
    let crypto = hal.crypto();
    
    // Test key generation
    let keypair = crypto.generate_keypair().await.expect("Failed to generate keypair");
    assert!(!keypair.public_key.is_empty());
    assert!(!keypair.private_key.is_empty());
    
    // Test signing and verification
    let data = b"test message";
    let signature = crypto.sign(data.to_vec(), keypair.private_key.clone()).await
        .expect("Failed to sign data");
    
    let verified = crypto.verify(data.to_vec(), signature, keypair.public_key).await
        .expect("Failed to verify signature");
    assert!(verified);
}

#[tokio::test]
async fn test_storage_integration() {
    let hal = ElasticTeeHal::new().expect("Failed to create HAL");
    let storage = hal.storage();
    
    // Create container
    let container = storage.create_container("test-container").await
        .expect("Failed to create container");
    
    // Store and retrieve data
    let test_data = b"Hello, TEE!";
    let _object_id = storage.store_object(container, "test-key", test_data.to_vec()).await
        .expect("Failed to store object");
    
    let retrieved = storage.retrieve_object(container, "test-key").await
        .expect("Failed to retrieve object");
    
    assert_eq!(retrieved, test_data.to_vec());
    
    // Clean up
    storage.delete_object(container, "test-key").await
        .expect("Failed to delete object");
    storage.delete_container(container).await
        .expect("Failed to delete container");
}
