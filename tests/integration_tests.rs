use elastic_tee_hal::platform::PlatformType;
use elastic_tee_hal::*;

#[tokio::test]
async fn test_platform_integration() {
    let hal = ElasticTeeHal::new().expect("Failed to create HAL");

    // After construction the HAL must be initialised and report a known platform.
    assert!(hal.is_initialized());
    let platform_type = hal.platform_type().clone();
    assert!(matches!(
        platform_type,
        PlatformType::AmdSev | PlatformType::IntelTdx
    ));
}

#[tokio::test]
async fn test_crypto_integration() {
    // The crypto interface is independent of the HAL platform layer.
    let crypto = CryptoInterface::new();

    // Symmetric round-trip via AES-256-GCM.
    let key = crypto
        .generate_symmetric_key("AES-256-GCM")
        .await
        .expect("Failed to generate symmetric key");
    assert_eq!(key.len(), 32);

    let plaintext = b"test message";
    let ciphertext = crypto
        .symmetric_encrypt("AES-256-GCM", &key, plaintext, None)
        .await
        .expect("Failed to encrypt");
    assert_ne!(ciphertext, plaintext.to_vec());

    let decrypted = crypto
        .symmetric_decrypt("AES-256-GCM", &key, &ciphertext, None)
        .await
        .expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext.to_vec());

    // Hashing sanity-check.
    let digest = crypto
        .hash_data("SHA-256", plaintext)
        .await
        .expect("Failed to hash data");
    assert_eq!(digest.len(), 32);
}

#[tokio::test]
async fn test_storage_integration() {
    let tmp = tempfile::tempdir().expect("Failed to create tempdir");
    let storage = StorageInterface::new(tmp.path())
        .await
        .expect("Failed to create storage interface");

    // Open (or create) a plaintext container.
    let container = storage
        .open_container("test-container", false)
        .await
        .expect("Failed to open container");

    let test_data = b"Hello, TEE!";
    storage
        .write_object(container, "test-key", test_data)
        .await
        .expect("Failed to write object");

    let retrieved = storage
        .read_object(container, "test-key")
        .await
        .expect("Failed to read object");
    assert_eq!(retrieved, test_data.to_vec());

    // Clean up.
    storage
        .delete_object(container, "test-key")
        .await
        .expect("Failed to delete object");
    storage
        .close_container(container)
        .await
        .expect("Failed to close container");
}
