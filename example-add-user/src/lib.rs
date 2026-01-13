//! Add User Service - LUND Demo
//! 
//! This WASM component demonstrates using ELASTIC HAL from a WASM service.
//! It provides a user management API with:
//! - Storage using HAL storage interface
//! - Cryptography using HAL crypto interface
//! - Attestation using HAL platform interface

#[allow(warnings)]
mod bindings;

use bindings::exports::elastic::add_user_service::user_api::{Guest, User};
use bindings::elastic::platform::platform as platform_hal;
use bindings::elastic::crypto::crypto as crypto_hal;
use bindings::elastic::storage::storage as storage_hal;
use bindings::elastic::clock::clock as clock_hal;
use bindings::elastic::random::random as random_hal;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// User database stored in HAL storage
#[derive(Serialize, Deserialize)]
struct UserDatabase {
    users: HashMap<String, UserRecord>,
}

#[derive(Serialize, Deserialize, Clone)]
struct UserRecord {
    id: String,
    name: String,
    email: String,
    email_hash: Vec<u8>,
    created_at: u64,
}

struct Component;

impl Guest for Component {
    fn add_user(name: String, email: String) -> Result<User, String> {
        // 1. Generate user ID using random bytes
        let id_bytes = random_hal::get_random_bytes(16)
            .map_err(|e| format!("Failed to generate ID: {}", e))?;
        let id = hex::encode(&id_bytes);
        
        // 2. Hash the email for privacy
        let email_hash = crypto_hal::hash(
            email.as_bytes(),
            crypto_hal::HashAlgorithm::Sha256
        ).map_err(|e| format!("Failed to hash email: {}", e))?;
        
        // 3. Get current timestamp
        let time = clock_hal::get_system_time()
            .map_err(|e| format!("Failed to get time: {}", e))?;
        let created_at = time.seconds;
        
        // 4. Create user record
        let user_record = UserRecord {
            id: id.clone(),
            name: name.clone(),
            email: email.clone(),
            email_hash,
            created_at,
        };
        
        // 5. Store in HAL storage
        let user_json = serde_json::to_string(&user_record)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        // Create/open user database container
        let container = storage_hal::open_container("user-db")
            .or_else(|_| storage_hal::create_container("user-db"))
            .map_err(|e| format!("Failed to access storage: {}", e))?;
        
        // Write user record
        storage_hal::store_object(container, &id, user_json.as_bytes())
            .map_err(|e| format!("Failed to write user: {}", e))?;
        
        // 6. Return user (without hash for API response)
        Ok(User {
            id,
            name,
            email,
            created_at,
        })
    }
    
    fn get_user(id: String) -> Result<User, String> {
        // Open database
        let container = storage_hal::open_container("user-db")
            .map_err(|e| format!("Database not found: {}", e))?;
        
        // Read user record
        let user_data = storage_hal::retrieve_object(container, &id)
            .map_err(|e| format!("User not found: {}", e))?;
        
        // Deserialize
        let user_record: UserRecord = serde_json::from_slice(&user_data)
            .map_err(|e| format!("Data corruption: {}", e))?;
        
        Ok(User {
            id: user_record.id,
            name: user_record.name,
            email: user_record.email,
            created_at: user_record.created_at,
        })
    }
    
    fn list_users() -> Result<Vec<String>, String> {
        // Open database
        let container = storage_hal::open_container("user-db")
            .map_err(|_| "No users yet".to_string())?;
        
        // List all objects
        let keys = storage_hal::list_objects(container)
            .map_err(|e| format!("Failed to list users: {}", e))?;
        
        Ok(keys)
    }
    
    fn get_attestation(nonce: Vec<u8>) -> Result<Vec<u8>, String> {
        // Get platform attestation report
        // This proves the service is running in a TEE
        platform_hal::attestation(&nonce)
    }
}

bindings::export!(Component with_types_in bindings);

// Hex encoding helper
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

