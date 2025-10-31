// Object storage interface - Requirements 7 & 8
// WASI-compatible storage interface using tokio::fs for async filesystem operations
// Works in TEE environments including Intel TDX with standard filesystem access
// TDX protects storage data in memory; this layer adds AES-GCM encryption at rest

use crate::error::{HalError, HalResult};
use crate::crypto::CryptoInterface;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::fs;
use serde::{Deserialize, Serialize};

/// Storage container handle
pub type ContainerHandle = u64;

/// Object key type
pub type ObjectKey = String;

/// Storage interface for persistent data
#[derive(Debug)]
pub struct StorageInterface {
    containers: Arc<RwLock<HashMap<ContainerHandle, Container>>>,
    next_handle: Arc<RwLock<ContainerHandle>>,
    base_path: PathBuf,
    crypto: Option<Arc<CryptoInterface>>,
}

/// Storage container
#[derive(Debug, Clone)]
struct Container {
    handle: ContainerHandle,
    name: String,
    path: PathBuf,
    encrypted: bool,
    encryption_key: Option<Vec<u8>>,
    metadata: ContainerMetadata,
}

/// Container metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerMetadata {
    pub created_at: u64,
    pub last_accessed: u64,
    pub object_count: usize,
    pub total_size: u64,
    pub encrypted: bool,
}

/// Object metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObjectMetadata {
    key: String,
    size: u64,
    created_at: u64,
    last_modified: u64,
    content_type: Option<String>,
    encrypted: bool,
}

impl StorageInterface {
    /// Create a new storage interface
    pub async fn new(base_path: impl AsRef<Path>) -> HalResult<Self> {
        let base_path = base_path.as_ref().to_path_buf();
        
        // Create base directory if it doesn't exist
        if !base_path.exists() {
            fs::create_dir_all(&base_path).await
                .map_err(|e| HalError::StorageError(format!("Failed to create storage directory: {}", e)))?;
        }

        Ok(Self {
            containers: Arc::new(RwLock::new(HashMap::new())),
            next_handle: Arc::new(RwLock::new(1)),
            base_path,
            crypto: None,
        })
    }

    /// Create storage interface with encryption support
    pub async fn with_encryption(
        base_path: impl AsRef<Path>,
        crypto: Arc<CryptoInterface>,
    ) -> HalResult<Self> {
        let mut storage = Self::new(base_path).await?;
        storage.crypto = Some(crypto);
        Ok(storage)
    }

    /// Open or create a storage container
    pub async fn open_container(&self, name: &str, encrypted: bool) -> HalResult<ContainerHandle> {
        let mut containers = self.containers.write().await;
        let mut next_handle = self.next_handle.write().await;

        // Check if container already exists
        for container in containers.values() {
            if container.name == name {
                return Ok(container.handle);
            }
        }

        // Create new container
        let handle = *next_handle;
        *next_handle += 1;

        let container_path = self.base_path.join(format!("container_{}", handle));
        fs::create_dir_all(&container_path).await
            .map_err(|e| HalError::StorageError(format!("Failed to create container directory: {}", e)))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let metadata = ContainerMetadata {
            created_at: now,
            last_accessed: now,
            object_count: 0,
            total_size: 0,
            encrypted,
        };

        let container = Container {
            handle,
            name: name.to_string(),
            path: container_path.clone(),
            encrypted,
            encryption_key: if encrypted {
                Some(self.generate_container_key().await?)
            } else {
                None
            },
            metadata,
        };

        // Save container metadata
        self.save_container_metadata(&container).await?;

        containers.insert(handle, container);
        Ok(handle)
    }

    /// Read object from container
    pub async fn read_object(
        &self,
        container_handle: ContainerHandle,
        key: &str,
    ) -> HalResult<Vec<u8>> {
        let containers = self.containers.read().await;
        let container = containers.get(&container_handle)
            .ok_or_else(|| HalError::NotFound("Container not found".to_string()))?;

        let object_path = container.path.join(format!("{}.obj", key));
        if !object_path.exists() {
            return Err(HalError::NotFound(format!("Object '{}' not found", key)));
        }

        let data = fs::read(&object_path).await
            .map_err(|e| HalError::StorageError(format!("Failed to read object: {}", e)))?;

        // Decrypt if container is encrypted
        if container.encrypted {
            if let Some(ref encryption_key) = container.encryption_key {
                return self.decrypt_object_data(&data, encryption_key).await;
            }
        }

        Ok(data)
    }

    /// Write object to container
    pub async fn write_object(
        &self,
        container_handle: ContainerHandle,
        key: &str,
        data: &[u8],
    ) -> HalResult<()> {
        let mut containers = self.containers.write().await;
        let container = containers.get_mut(&container_handle)
            .ok_or_else(|| HalError::NotFound("Container not found".to_string()))?;

        let object_path = container.path.join(format!("{}.obj", key));
        let metadata_path = container.path.join(format!("{}.meta", key));

        // Encrypt data if container is encrypted
        let final_data = if container.encrypted {
            if let Some(ref encryption_key) = container.encryption_key {
                self.encrypt_object_data(data, encryption_key).await?
            } else {
                return Err(HalError::StorageError("Container is encrypted but no key available".to_string()));
            }
        } else {
            data.to_vec()
        };

        // Write object data
        fs::write(&object_path, &final_data).await
            .map_err(|e| HalError::StorageError(format!("Failed to write object: {}", e)))?;

        // Create object metadata
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let object_metadata = ObjectMetadata {
            key: key.to_string(),
            size: data.len() as u64,
            created_at: now,
            last_modified: now,
            content_type: None,
            encrypted: container.encrypted,
        };

        // Write metadata
        let metadata_json = serde_json::to_string(&object_metadata)?;
        fs::write(&metadata_path, metadata_json).await
            .map_err(|e| HalError::StorageError(format!("Failed to write metadata: {}", e)))?;

        // Update container metadata
        container.metadata.last_accessed = now;
        container.metadata.object_count += 1;
        container.metadata.total_size += data.len() as u64;

        self.save_container_metadata(container).await?;

        Ok(())
    }

    /// Load encryption key for container
    pub async fn load_object_key(
        &self,
        container_handle: ContainerHandle,
        key_data: &[u8],
    ) -> HalResult<()> {
        let mut containers = self.containers.write().await;
        let container = containers.get_mut(&container_handle)
            .ok_or_else(|| HalError::NotFound("Container not found".to_string()))?;

        if !container.encrypted {
            return Err(HalError::InvalidParameter(
                "Container is not encrypted".to_string()
            ));
        }

        // Validate key length
        if key_data.len() != 32 {
            return Err(HalError::InvalidParameter(
                "Encryption key must be 32 bytes".to_string()
            ));
        }

        container.encryption_key = Some(key_data.to_vec());
        Ok(())
    }

    /// Delete object from container
    pub async fn delete_object(
        &self,
        container_handle: ContainerHandle,
        key: &str,
    ) -> HalResult<()> {
        let mut containers = self.containers.write().await;
        let container = containers.get_mut(&container_handle)
            .ok_or_else(|| HalError::NotFound("Container not found".to_string()))?;

        let object_path = container.path.join(format!("{}.obj", key));
        let metadata_path = container.path.join(format!("{}.meta", key));

        if !object_path.exists() {
            return Err(HalError::NotFound(format!("Object '{}' not found", key)));
        }

        // Read metadata to get object size
        if let Ok(metadata_content) = fs::read_to_string(&metadata_path).await {
            if let Ok(metadata) = serde_json::from_str::<ObjectMetadata>(&metadata_content) {
                container.metadata.total_size = container.metadata.total_size.saturating_sub(metadata.size);
                container.metadata.object_count = container.metadata.object_count.saturating_sub(1);
            }
        }

        // Delete files
        fs::remove_file(&object_path).await
            .map_err(|e| HalError::StorageError(format!("Failed to delete object: {}", e)))?;
        
        if metadata_path.exists() {
            fs::remove_file(&metadata_path).await
                .map_err(|e| HalError::StorageError(format!("Failed to delete metadata: {}", e)))?;
        }

        // Update container metadata
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        container.metadata.last_accessed = now;

        self.save_container_metadata(container).await?;

        Ok(())
    }

    /// List objects in container
    pub async fn list_objects(&self, container_handle: ContainerHandle) -> HalResult<Vec<String>> {
        let containers = self.containers.read().await;
        let container = containers.get(&container_handle)
            .ok_or_else(|| HalError::NotFound("Container not found".to_string()))?;

        let mut objects = Vec::new();
        let mut entries = fs::read_dir(&container.path).await
            .map_err(|e| HalError::StorageError(format!("Failed to read container directory: {}", e)))?;

        while let Some(entry) = entries.next_entry().await
            .map_err(|e| HalError::StorageError(format!("Failed to read directory entry: {}", e)))? {
            
            if let Some(file_name) = entry.file_name().to_str() {
                if file_name.ends_with(".obj") {
                    let object_key = file_name.strip_suffix(".obj").unwrap().to_string();
                    objects.push(object_key);
                }
            }
        }

        Ok(objects)
    }

    /// Get container metadata
    pub async fn get_container_metadata(&self, container_handle: ContainerHandle) -> HalResult<ContainerMetadata> {
        let containers = self.containers.read().await;
        let container = containers.get(&container_handle)
            .ok_or_else(|| HalError::NotFound("Container not found".to_string()))?;

        Ok(container.metadata.clone())
    }

    /// Close container
    pub async fn close_container(&self, container_handle: ContainerHandle) -> HalResult<()> {
        let mut containers = self.containers.write().await;
        containers.remove(&container_handle);
        Ok(())
    }

    // Private helper methods

    async fn generate_container_key(&self) -> HalResult<Vec<u8>> {
        if let Some(ref crypto) = self.crypto {
            // Use crypto interface to generate key
            crypto.generate_symmetric_key("AES-256-GCM").await
        } else {
            // Use random interface as fallback
            let random = crate::random::RandomInterface::new();
            random.generate_key_material(32)
        }
    }

    async fn encrypt_object_data(&self, data: &[u8], key: &[u8]) -> HalResult<Vec<u8>> {
        if let Some(ref crypto) = self.crypto {
            crypto.symmetric_encrypt("AES-256-GCM", key, data, None).await
        } else {
            // Simple AES-GCM encryption as fallback
            use aes_gcm::{Aes256Gcm, KeyInit, Key};
            use aes_gcm::aead::{Aead, generic_array::GenericArray};

            let key_array = GenericArray::from_slice(key);
            let cipher = Aes256Gcm::new(key_array);
            let nonce_bytes = crate::random::RandomInterface::new().generate_nonce(12)?;
            let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
            
            let ciphertext = cipher.encrypt(nonce, data)
                .map_err(|_| HalError::CryptographicError("Encryption failed".to_string()))?;

            // Prepend nonce to ciphertext
            let mut result = nonce_bytes;
            result.extend_from_slice(&ciphertext);
            Ok(result)
        }
    }

    async fn decrypt_object_data(&self, data: &[u8], key: &[u8]) -> HalResult<Vec<u8>> {
        if let Some(ref crypto) = self.crypto {
            crypto.symmetric_decrypt("AES-256-GCM", key, data, None).await
        } else {
            // Simple AES-GCM decryption as fallback
            use aes_gcm::{Aes256Gcm, KeyInit};
            use aes_gcm::aead::{Aead, generic_array::GenericArray};

            if data.len() < 12 {
                return Err(HalError::CryptographicError("Invalid encrypted data".to_string()));
            }

            let key_array = GenericArray::from_slice(key);
            let cipher = Aes256Gcm::new(key_array);
            let nonce = aes_gcm::Nonce::from_slice(&data[..12]);
            let ciphertext = &data[12..];
            
            let plaintext = cipher.decrypt(nonce, ciphertext)
                .map_err(|_| HalError::CryptographicError("Decryption failed".to_string()))?;

            Ok(plaintext)
        }
    }

    async fn save_container_metadata(&self, container: &Container) -> HalResult<()> {
        let metadata_path = container.path.join("container.meta");
        let metadata_json = serde_json::to_string_pretty(&container.metadata)?;
        
        fs::write(&metadata_path, metadata_json).await
            .map_err(|e| HalError::StorageError(format!("Failed to save container metadata: {}", e)))?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_storage() -> (StorageInterface, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage = StorageInterface::new(temp_dir.path()).await.unwrap();
        (storage, temp_dir)
    }

    #[tokio::test]
    async fn test_container_operations() {
        let (storage, _temp_dir) = create_test_storage().await;

        // Open container
        let handle = storage.open_container("test_container", false).await.unwrap();
        assert!(handle > 0);

        // Open same container again (should return same handle)
        let handle2 = storage.open_container("test_container", false).await.unwrap();
        assert_eq!(handle, handle2);
    }

    #[tokio::test]
    async fn test_object_operations() {
        let (storage, _temp_dir) = create_test_storage().await;

        let handle = storage.open_container("test_container", false).await.unwrap();

        // Write object
        let test_data = b"Hello, World!";
        storage.write_object(handle, "test_key", test_data).await.unwrap();

        // Read object
        let read_data = storage.read_object(handle, "test_key").await.unwrap();
        assert_eq!(read_data, test_data);

        // List objects
        let objects = storage.list_objects(handle).await.unwrap();
        assert!(objects.contains(&"test_key".to_string()));

        // Delete object
        storage.delete_object(handle, "test_key").await.unwrap();
        let objects = storage.list_objects(handle).await.unwrap();
        assert!(!objects.contains(&"test_key".to_string()));
    }

    #[tokio::test]
    async fn test_encrypted_container() {
        let (storage, _temp_dir) = create_test_storage().await;

        let handle = storage.open_container("encrypted_container", true).await.unwrap();

        // Write and read encrypted object
        let test_data = b"Secret data";
        storage.write_object(handle, "secret_key", test_data).await.unwrap();

        let read_data = storage.read_object(handle, "secret_key").await.unwrap();
        assert_eq!(read_data, test_data);
    }

    #[tokio::test]
    async fn test_object_not_found() {
        let (storage, _temp_dir) = create_test_storage().await;

        let handle = storage.open_container("test_container", false).await.unwrap();

        // Try to read non-existent object
        let result = storage.read_object(handle, "non_existent").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HalError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_container_metadata() {
        let (storage, _temp_dir) = create_test_storage().await;

        let handle = storage.open_container("test_container", false).await.unwrap();

        // Check initial metadata
        let metadata = storage.get_container_metadata(handle).await.unwrap();
        assert_eq!(metadata.object_count, 0);
        assert_eq!(metadata.total_size, 0);
        assert!(!metadata.encrypted);

        // Add object and check metadata update
        let test_data = b"Test data";
        storage.write_object(handle, "test", test_data).await.unwrap();

        let metadata = storage.get_container_metadata(handle).await.unwrap();
        assert_eq!(metadata.object_count, 1);
        assert_eq!(metadata.total_size, test_data.len() as u64);
    }
}
