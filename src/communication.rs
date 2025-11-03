// Protected internal communication interface - Requirement 11

use crate::error::{HalError, HalResult};
use crate::crypto::CryptoInterface;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};

/// Communication buffer handle
pub type CommBufferHandle = u64;

/// Protected internal communication interface
/// 
/// In Intel TDX environments:
/// - Communication buffers are protected by TDX memory encryption
/// - Encryption keys can be derived from TDX measurements (MRTD/RTMR)
/// - Cross-TD communication requires explicit shared memory setup
/// - TDX attestation can be used for buffer authentication
#[derive(Debug)]
pub struct CommunicationInterface {
    buffers: Arc<RwLock<HashMap<CommBufferHandle, CommunicationBuffer>>>,
    next_handle: Arc<RwLock<CommBufferHandle>>,
    crypto: Option<Arc<CryptoInterface>>,
    is_tdx_env: bool,
}

/// Communication buffer for inter-workload communication
#[derive(Debug)]
struct CommunicationBuffer {
    handle: CommBufferHandle,
    name: String,
    data: Vec<u8>,
    capacity: usize,
    is_encrypted: bool,
    read_position: usize,
    write_position: usize,
    created_at: u64,
    last_accessed: u64,
    access_permissions: AccessPermissions,
    encryption_key: Option<Vec<u8>>,
}

/// Access permissions for communication buffers
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessPermissions {
    read_allowed: Vec<String>,
    write_allowed: Vec<String>,
    admin_allowed: Vec<String>,
}

/// Buffer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferInfo {
    pub handle: CommBufferHandle,
    pub name: String,
    pub capacity: usize,
    pub current_size: usize,
    pub is_encrypted: bool,
    pub created_at: u64,
    pub last_accessed: u64,
}

/// Communication message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommMessage {
    pub message_id: String,
    pub sender: String,
    pub timestamp: u64,
    pub message_type: MessageType,
    pub data: Vec<u8>,
    pub priority: MessagePriority,
}

/// Message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Data,
    Control,
    Event,
    Heartbeat,
    Acknowledgment,
}

/// Message priority levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePriority {
    Low,
    Normal,
    High,
    Critical,
}

/// Buffer configuration
#[derive(Debug, Clone)]
pub struct BufferConfig {
    pub name: String,
    pub capacity: usize,
    pub is_encrypted: bool,
    pub read_permissions: Vec<String>,
    pub write_permissions: Vec<String>,
    pub admin_permissions: Vec<String>,
}

impl CommunicationInterface {
    /// Create a new communication interface
    pub fn new() -> Self {
        let is_tdx_env = crate::platform::is_intel_tdx_available();
        
        if is_tdx_env {
            log::info!("Communication interface initialized in Intel TDX secure mode");
            log::info!("All communication buffers are protected by TDX memory encryption");
        }
        
        Self {
            buffers: Arc::new(RwLock::new(HashMap::new())),
            next_handle: Arc::new(RwLock::new(1)),
            crypto: None,
            is_tdx_env,
        }
    }

    /// Create communication interface with encryption support
    pub fn with_crypto(crypto: Arc<CryptoInterface>) -> Self {
        let is_tdx_env = crate::platform::is_intel_tdx_available();
        
        if is_tdx_env {
            log::info!("Communication interface initialized with TDX-enhanced encryption");
        }
        
        Self {
            buffers: Arc::new(RwLock::new(HashMap::new())),
            next_handle: Arc::new(RwLock::new(1)),
            crypto: Some(crypto),
            is_tdx_env,
        }
    }

    /// Set up a communication buffer
    pub async fn setup_communication_buffer(&self, config: BufferConfig) -> HalResult<CommBufferHandle> {
        let mut buffers = self.buffers.write().await;
        let mut next_handle = self.next_handle.write().await;

        // Check if buffer with same name already exists
        for buffer in buffers.values() {
            if buffer.name == config.name {
                return Err(HalError::CommunicationError(
                    format!("Buffer with name '{}' already exists", config.name)
                ));
            }
        }

        let handle = *next_handle;
        *next_handle += 1;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Generate encryption key if needed
        let encryption_key = if config.is_encrypted {
            if let Some(ref crypto) = self.crypto {
                Some(crypto.generate_symmetric_key("AES-256-GCM").await?)
            } else {
                // Fallback to random key generation
                Some(crate::random::RandomInterface::new().generate_key_material(32)?)
            }
        } else {
            None
        };

        let buffer = CommunicationBuffer {
            handle,
            name: config.name.clone(),
            data: vec![0u8; config.capacity],
            capacity: config.capacity,
            is_encrypted: config.is_encrypted,
            read_position: 0,
            write_position: 0,
            created_at: now,
            last_accessed: now,
            access_permissions: AccessPermissions {
                read_allowed: config.read_permissions,
                write_allowed: config.write_permissions,
                admin_allowed: config.admin_permissions,
            },
            encryption_key,
        };

        buffers.insert(handle, buffer);

        log::info!("Set up communication buffer '{}' with handle {}", config.name, handle);
        Ok(handle)
    }

    /// Push data to buffer
    pub async fn push_data_to_buffer(
        &self,
        handle: CommBufferHandle,
        data: &[u8],
        sender: &str,
        message_type: MessageType,
        priority: MessagePriority,
    ) -> HalResult<()> {
        let mut buffers = self.buffers.write().await;
        let buffer = buffers.get_mut(&handle)
            .ok_or_else(|| HalError::NotFound("Communication buffer not found".to_string()))?;

        // Check write permissions
        if !buffer.access_permissions.write_allowed.contains(&sender.to_string()) &&
           !buffer.access_permissions.admin_allowed.contains(&sender.to_string()) {
            return Err(HalError::PermissionDenied(
                format!("Sender '{}' does not have write permission", sender)
            ));
        }

        // Create message
        let message = CommMessage {
            message_id: self.generate_message_id(),
            sender: sender.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            message_type,
            data: data.to_vec(),
            priority,
        };

        // Serialize message
        let serialized_message = bincode::serialize(&message)
            .map_err(|e| HalError::CommunicationError(format!("Failed to serialize message: {}", e)))?;

        // Encrypt if needed
        let final_data = if buffer.is_encrypted {
            if let Some(ref key) = buffer.encryption_key {
                self.encrypt_data(&serialized_message, key).await?
            } else {
                return Err(HalError::CommunicationError("Buffer is encrypted but no key available".to_string()));
            }
        } else {
            serialized_message
        };

        // Check if there's enough space
        let required_space = final_data.len() + 4; // 4 bytes for length prefix
        let available_space = if buffer.write_position >= buffer.read_position {
            buffer.capacity - buffer.write_position + buffer.read_position
        } else {
            buffer.read_position - buffer.write_position
        };

        if required_space > available_space {
            return Err(HalError::CommunicationError("Insufficient buffer space".to_string()));
        }

        // Write length prefix (4 bytes)
        let length_bytes = (final_data.len() as u32).to_le_bytes();
        self.write_bytes_to_buffer(buffer, &length_bytes)?;

        // Write data
        self.write_bytes_to_buffer(buffer, &final_data)?;

        // Update timestamp
        buffer.last_accessed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        log::debug!(
            "Pushed {} bytes to buffer {} from sender {}",
            data.len(),
            handle,
            sender
        );

        Ok(())
    }

    /// Read data from buffer
    pub async fn read_data_from_buffer(
        &self,
        handle: CommBufferHandle,
        reader: &str,
    ) -> HalResult<Option<CommMessage>> {
        let mut buffers = self.buffers.write().await;
        let buffer = buffers.get_mut(&handle)
            .ok_or_else(|| HalError::NotFound("Communication buffer not found".to_string()))?;

        // Check read permissions
        if !buffer.access_permissions.read_allowed.contains(&reader.to_string()) &&
           !buffer.access_permissions.admin_allowed.contains(&reader.to_string()) {
            return Err(HalError::PermissionDenied(
                format!("Reader '{}' does not have read permission", reader)
            ));
        }

        // Check if there's data to read
        if buffer.read_position == buffer.write_position {
            return Ok(None); // No data available
        }

        // Read length prefix (4 bytes)
        let length_bytes = self.read_bytes_from_buffer(buffer, 4)?;
        let data_length = u32::from_le_bytes([
            length_bytes[0],
            length_bytes[1],
            length_bytes[2],
            length_bytes[3],
        ]) as usize;

        // Read data
        let encrypted_data = self.read_bytes_from_buffer(buffer, data_length)?;

        // Decrypt if needed
        let decrypted_data = if buffer.is_encrypted {
            if let Some(ref key) = buffer.encryption_key {
                self.decrypt_data(&encrypted_data, key).await?
            } else {
                return Err(HalError::CommunicationError("Buffer is encrypted but no key available".to_string()));
            }
        } else {
            encrypted_data
        };

        // Deserialize message
        let message: CommMessage = bincode::deserialize(&decrypted_data)
            .map_err(|e| HalError::CommunicationError(format!("Failed to deserialize message: {}", e)))?;

        // Update timestamp
        buffer.last_accessed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        log::debug!(
            "Read {} bytes from buffer {} by reader {}",
            message.data.len(),
            handle,
            reader
        );

        Ok(Some(message))
    }

    /// Get buffer information
    pub async fn get_buffer_info(&self, handle: CommBufferHandle) -> HalResult<BufferInfo> {
        let buffers = self.buffers.read().await;
        let buffer = buffers.get(&handle)
            .ok_or_else(|| HalError::NotFound("Communication buffer not found".to_string()))?;

        let current_size = if buffer.write_position >= buffer.read_position {
            buffer.write_position - buffer.read_position
        } else {
            buffer.capacity - buffer.read_position + buffer.write_position
        };

        Ok(BufferInfo {
            handle: buffer.handle,
            name: buffer.name.clone(),
            capacity: buffer.capacity,
            current_size,
            is_encrypted: buffer.is_encrypted,
            created_at: buffer.created_at,
            last_accessed: buffer.last_accessed,
        })
    }

    /// List all communication buffers
    pub async fn list_communication_buffers(&self) -> HalResult<Vec<BufferInfo>> {
        let buffers = self.buffers.read().await;
        let mut buffer_infos = Vec::new();

        for buffer in buffers.values() {
            let current_size = if buffer.write_position >= buffer.read_position {
                buffer.write_position - buffer.read_position
            } else {
                buffer.capacity - buffer.read_position + buffer.write_position
            };

            buffer_infos.push(BufferInfo {
                handle: buffer.handle,
                name: buffer.name.clone(),
                capacity: buffer.capacity,
                current_size,
                is_encrypted: buffer.is_encrypted,
                created_at: buffer.created_at,
                last_accessed: buffer.last_accessed,
            });
        }

        Ok(buffer_infos)
    }

    /// Clear buffer contents
    pub async fn clear_buffer(&self, handle: CommBufferHandle, requester: &str) -> HalResult<()> {
        let mut buffers = self.buffers.write().await;
        let buffer = buffers.get_mut(&handle)
            .ok_or_else(|| HalError::NotFound("Communication buffer not found".to_string()))?;

        // Check admin permissions
        if !buffer.access_permissions.admin_allowed.contains(&requester.to_string()) {
            return Err(HalError::PermissionDenied(
                format!("Requester '{}' does not have admin permission", requester)
            ));
        }

        // Reset positions
        buffer.read_position = 0;
        buffer.write_position = 0;
        buffer.data.fill(0);

        buffer.last_accessed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        log::info!("Cleared buffer {} by requester {}", handle, requester);
        Ok(())
    }

    /// Remove communication buffer
    pub async fn remove_communication_buffer(&self, handle: CommBufferHandle, requester: &str) -> HalResult<()> {
        let mut buffers = self.buffers.write().await;
        
        // Check admin permissions before removal
        if let Some(buffer) = buffers.get(&handle) {
            if !buffer.access_permissions.admin_allowed.contains(&requester.to_string()) {
                return Err(HalError::PermissionDenied(
                    format!("Requester '{}' does not have admin permission", requester)
                ));
            }
        }

        buffers.remove(&handle)
            .ok_or_else(|| HalError::NotFound("Communication buffer not found".to_string()))?;

        log::info!("Removed communication buffer {} by requester {}", handle, requester);
        Ok(())
    }

    // Private helper methods

    fn write_bytes_to_buffer(&self, buffer: &mut CommunicationBuffer, data: &[u8]) -> HalResult<()> {
        for &byte in data {
            buffer.data[buffer.write_position] = byte;
            buffer.write_position = (buffer.write_position + 1) % buffer.capacity;
        }
        Ok(())
    }

    fn read_bytes_from_buffer(&self, buffer: &mut CommunicationBuffer, length: usize) -> HalResult<Vec<u8>> {
        let mut result = Vec::with_capacity(length);
        
        for _ in 0..length {
            if buffer.read_position == buffer.write_position {
                return Err(HalError::CommunicationError("Insufficient data in buffer".to_string()));
            }
            
            result.push(buffer.data[buffer.read_position]);
            buffer.read_position = (buffer.read_position + 1) % buffer.capacity;
        }
        
        Ok(result)
    }

    async fn encrypt_data(&self, data: &[u8], key: &[u8]) -> HalResult<Vec<u8>> {
        if let Some(ref crypto) = self.crypto {
            crypto.symmetric_encrypt("AES-256-GCM", key, data, None).await
        } else {
            // Fallback encryption using AES-GCM
            use aes_gcm::{Aes256Gcm, KeyInit};
            use aes_gcm::aead::{Aead, generic_array::GenericArray};

            let key_array = GenericArray::from_slice(key);
            let cipher = Aes256Gcm::new(key_array);
            let nonce_bytes = crate::random::RandomInterface::new().generate_nonce(12)?;
            let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
            
            let ciphertext = cipher.encrypt(nonce, data)
                .map_err(|_| HalError::CryptographicError("Encryption failed".to_string()))?;

            let mut result = nonce_bytes;
            result.extend_from_slice(&ciphertext);
            Ok(result)
        }
    }

    async fn decrypt_data(&self, data: &[u8], key: &[u8]) -> HalResult<Vec<u8>> {
        if let Some(ref crypto) = self.crypto {
            crypto.symmetric_decrypt("AES-256-GCM", key, data, None).await
        } else {
            // Fallback decryption using AES-GCM
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

    fn generate_message_id(&self) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        
        format!("msg_{:x}", timestamp)
    }
}

impl Default for CommunicationInterface {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_buffer_config() -> BufferConfig {
        BufferConfig {
            name: "test_buffer".to_string(),
            capacity: 1024,
            is_encrypted: false,
            read_permissions: vec!["reader1".to_string(), "reader2".to_string()],
            write_permissions: vec!["writer1".to_string(), "writer2".to_string()],
            admin_permissions: vec!["admin".to_string()],
        }
    }

    #[tokio::test]
    async fn test_buffer_setup() {
        let comm_interface = CommunicationInterface::new();
        let config = create_test_buffer_config();

        let handle = comm_interface.setup_communication_buffer(config).await.unwrap();
        assert!(handle > 0);

        let info = comm_interface.get_buffer_info(handle).await.unwrap();
        assert_eq!(info.name, "test_buffer");
        assert_eq!(info.capacity, 1024);
        assert!(!info.is_encrypted);
    }

    #[tokio::test]
    async fn test_data_push_and_read() {
        let comm_interface = CommunicationInterface::new();
        let config = create_test_buffer_config();
        let handle = comm_interface.setup_communication_buffer(config).await.unwrap();

        let test_data = b"Hello, World!";
        
        // Push data
        comm_interface.push_data_to_buffer(
            handle,
            test_data,
            "writer1",
            MessageType::Data,
            MessagePriority::Normal,
        ).await.unwrap();

        // Read data
        let message = comm_interface.read_data_from_buffer(handle, "reader1").await.unwrap();
        assert!(message.is_some());

        let message = message.unwrap();
        assert_eq!(message.sender, "writer1");
        assert_eq!(message.data, test_data);
        assert!(matches!(message.message_type, MessageType::Data));
    }

    #[tokio::test]
    async fn test_permission_enforcement() {
        let comm_interface = CommunicationInterface::new();
        let config = create_test_buffer_config();
        let handle = comm_interface.setup_communication_buffer(config).await.unwrap();

        let test_data = b"Test data";

        // Try to write without permission
        let result = comm_interface.push_data_to_buffer(
            handle,
            test_data,
            "unauthorized_writer",
            MessageType::Data,
            MessagePriority::Normal,
        ).await;
        assert!(result.is_err());

        // Try to read without permission
        let result = comm_interface.read_data_from_buffer(handle, "unauthorized_reader").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_encrypted_buffer() {
        let comm_interface = CommunicationInterface::new();
        
        let config = BufferConfig {
            name: "encrypted_buffer".to_string(),
            capacity: 1024,
            is_encrypted: true,
            read_permissions: vec!["reader".to_string()],
            write_permissions: vec!["writer".to_string()],
            admin_permissions: vec!["admin".to_string()],
        };

        let handle = comm_interface.setup_communication_buffer(config).await.unwrap();

        let test_data = b"Secret message";
        
        // Push encrypted data
        comm_interface.push_data_to_buffer(
            handle,
            test_data,
            "writer",
            MessageType::Data,
            MessagePriority::High,
        ).await.unwrap();

        // Read and decrypt data
        let message = comm_interface.read_data_from_buffer(handle, "reader").await.unwrap();
        assert!(message.is_some());

        let message = message.unwrap();
        assert_eq!(message.data, test_data);
        assert_eq!(message.sender, "writer");
    }

    #[tokio::test]
    async fn test_buffer_listing() {
        let comm_interface = CommunicationInterface::new();
        
        let config1 = BufferConfig {
            name: "buffer1".to_string(),
            capacity: 512,
            is_encrypted: false,
            read_permissions: vec!["reader".to_string()],
            write_permissions: vec!["writer".to_string()],
            admin_permissions: vec!["admin".to_string()],
        };

        let config2 = BufferConfig {
            name: "buffer2".to_string(),
            capacity: 1024,
            is_encrypted: true,
            read_permissions: vec!["reader".to_string()],
            write_permissions: vec!["writer".to_string()],
            admin_permissions: vec!["admin".to_string()],
        };

        let _handle1 = comm_interface.setup_communication_buffer(config1).await.unwrap();
        let _handle2 = comm_interface.setup_communication_buffer(config2).await.unwrap();

        let buffers = comm_interface.list_communication_buffers().await.unwrap();
        assert_eq!(buffers.len(), 2);

        let buffer_names: Vec<&str> = buffers.iter().map(|b| b.name.as_str()).collect();
        assert!(buffer_names.contains(&"buffer1"));
        assert!(buffer_names.contains(&"buffer2"));
    }

    #[tokio::test]
    async fn test_buffer_clearing() {
        let comm_interface = CommunicationInterface::new();
        let config = create_test_buffer_config();
        let handle = comm_interface.setup_communication_buffer(config).await.unwrap();

        // Add some data
        comm_interface.push_data_to_buffer(
            handle,
            b"test data",
            "writer1",
            MessageType::Data,
            MessagePriority::Normal,
        ).await.unwrap();

        // Check data exists
        let info = comm_interface.get_buffer_info(handle).await.unwrap();
        assert!(info.current_size > 0);

        // Clear buffer
        comm_interface.clear_buffer(handle, "admin").await.unwrap();

        // Check buffer is empty
        let info = comm_interface.get_buffer_info(handle).await.unwrap();
        assert_eq!(info.current_size, 0);
    }

    #[tokio::test]
    async fn test_buffer_removal() {
        let comm_interface = CommunicationInterface::new();
        let config = create_test_buffer_config();
        let handle = comm_interface.setup_communication_buffer(config).await.unwrap();

        // Buffer should exist
        assert!(comm_interface.get_buffer_info(handle).await.is_ok());

        // Remove buffer
        comm_interface.remove_communication_buffer(handle, "admin").await.unwrap();

        // Buffer should no longer exist
        assert!(comm_interface.get_buffer_info(handle).await.is_err());
    }

    #[tokio::test]
    async fn test_multiple_messages() {
        let comm_interface = CommunicationInterface::new();
        let config = create_test_buffer_config();
        let handle = comm_interface.setup_communication_buffer(config).await.unwrap();

        // Push multiple messages
        for i in 0..5 {
            let data = format!("Message {}", i);
            comm_interface.push_data_to_buffer(
                handle,
                data.as_bytes(),
                "writer1",
                MessageType::Data,
                MessagePriority::Normal,
            ).await.unwrap();
        }

        // Read messages in order
        for i in 0..5 {
            let message = comm_interface.read_data_from_buffer(handle, "reader1").await.unwrap();
            assert!(message.is_some());
            
            let message = message.unwrap();
            let expected_data = format!("Message {}", i);
            assert_eq!(message.data, expected_data.as_bytes());
        }

        // No more messages should be available
        let message = comm_interface.read_data_from_buffer(handle, "reader1").await.unwrap();
        assert!(message.is_none());
    }
}
