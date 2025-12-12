// Provider wrappers for enforcement (audit, rate limiting, quota)

use super::{EntityId, AuditLog, AuditEvent, EnforcementError, EnforcementResult};
use crate::interfaces::*;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::collections::VecDeque;

// ============================================================================
// Audited Providers - Log all operations
// ============================================================================

/// Wrapper that adds audit logging to PlatformInterface
pub struct AuditedPlatformProvider<T: PlatformInterface> {
    inner: T,
    entity_id: EntityId,
    audit_log: AuditLog,
}

impl<T: PlatformInterface> AuditedPlatformProvider<T> {
    pub fn new(inner: T, entity_id: EntityId, audit_log: AuditLog) -> Self {
        Self {
            inner,
            entity_id,
            audit_log,
        }
    }
}

impl<T: PlatformInterface> PlatformInterface for AuditedPlatformProvider<T> {
    fn attestation(&self, report_data: &[u8]) -> Result<Vec<u8>, String> {
        let result = self.inner.attestation(report_data);
        
        self.audit_log.log(
            AuditEvent::new(
                self.entity_id.clone(),
                "platform",
                "attestation",
            )
            .with_success(result.is_ok())
            .with_details(format!("report_data_len={}", report_data.len()))
        );
        
        result
    }
    
    fn platform_info(&self) -> Result<(String, String, bool), String> {
        let result = self.inner.platform_info();
        
        self.audit_log.log(
            AuditEvent::new(
                self.entity_id.clone(),
                "platform",
                "platform_info",
            )
            .with_success(result.is_ok())
        );
        
        result
    }
}

/// Wrapper that adds audit logging to CryptoInterface
pub struct AuditedCryptoProvider<T: CryptoInterface> {
    inner: T,
    entity_id: EntityId,
    audit_log: AuditLog,
}

impl<T: CryptoInterface> AuditedCryptoProvider<T> {
    pub fn new(inner: T, entity_id: EntityId, audit_log: AuditLog) -> Self {
        Self {
            inner,
            entity_id,
            audit_log,
        }
    }
}

impl<T: CryptoInterface> CryptoInterface for AuditedCryptoProvider<T> {
    fn hash(&self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, String> {
        let result = self.inner.hash(data, algorithm);
        
        self.audit_log.log(
            AuditEvent::new(self.entity_id.clone(), "crypto", "hash")
                .with_success(result.is_ok())
                .with_details(format!("algorithm={}, data_len={}", algorithm, data.len()))
        );
        
        result
    }
    
    fn encrypt(&self, data: &[u8], key: &[u8], algorithm: &str) -> Result<Vec<u8>, String> {
        let result = self.inner.encrypt(data, key, algorithm);
        
        self.audit_log.log(
            AuditEvent::new(self.entity_id.clone(), "crypto", "encrypt")
                .with_success(result.is_ok())
                .with_details(format!("algorithm={}, data_len={}", algorithm, data.len()))
        );
        
        result
    }
    
    fn decrypt(&self, data: &[u8], key: &[u8], algorithm: &str) -> Result<Vec<u8>, String> {
        let result = self.inner.decrypt(data, key, algorithm);
        
        self.audit_log.log(
            AuditEvent::new(self.entity_id.clone(), "crypto", "decrypt")
                .with_success(result.is_ok())
                .with_details(format!("algorithm={}, data_len={}", algorithm, data.len()))
        );
        
        result
    }
    
    fn sign(&self, data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String> {
        let result = self.inner.sign(data, private_key);
        
        self.audit_log.log(
            AuditEvent::new(self.entity_id.clone(), "crypto", "sign")
                .with_success(result.is_ok())
                .with_details(format!("data_len={}", data.len()))
        );
        
        result
    }
    
    fn verify(&self, data: &[u8], public_key: &[u8], signature: &[u8]) -> Result<bool, String> {
        let result = self.inner.verify(data, public_key, signature);
        
        self.audit_log.log(
            AuditEvent::new(self.entity_id.clone(), "crypto", "verify")
                .with_success(result.is_ok())
                .with_details(format!("data_len={}, sig_len={}", data.len(), signature.len()))
        );
        
        result
    }
    
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        let result = self.inner.generate_keypair();
        
        self.audit_log.log(
            AuditEvent::new(self.entity_id.clone(), "crypto", "generate_keypair")
                .with_success(result.is_ok())
        );
        
        result
    }
}

// ============================================================================
// Rate Limited Providers - Enforce rate limits
// ============================================================================

struct RateLimiter {
    operations_per_second: u64,
    burst_size: u64,
    tokens: Arc<RwLock<f64>>,
    last_update: Arc<RwLock<Instant>>,
}

impl RateLimiter {
    fn new(operations_per_second: u64, burst_size: u64) -> Self {
        Self {
            operations_per_second,
            burst_size,
            tokens: Arc::new(RwLock::new(burst_size as f64)),
            last_update: Arc::new(RwLock::new(Instant::now())),
        }
    }
    
    fn check_rate_limit(&self) -> bool {
        let now = Instant::now();
        let mut tokens = self.tokens.write().unwrap();
        let mut last_update = self.last_update.write().unwrap();
        
        // Add tokens based on time elapsed
        let elapsed = now.duration_since(*last_update).as_secs_f64();
        *tokens = (*tokens + elapsed * self.operations_per_second as f64)
            .min(self.burst_size as f64);
        *last_update = now;
        
        // Try to consume one token
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Wrapper that adds rate limiting to PlatformInterface
pub struct RateLimitedPlatformProvider<T: PlatformInterface> {
    inner: T,
    entity_id: EntityId,
    rate_limiter: RateLimiter,
}

impl<T: PlatformInterface> RateLimitedPlatformProvider<T> {
    pub fn new(inner: T, entity_id: EntityId, ops_per_sec: u64, burst_size: u64) -> Self {
        Self {
            inner,
            entity_id,
            rate_limiter: RateLimiter::new(ops_per_sec, burst_size),
        }
    }
}

impl<T: PlatformInterface> PlatformInterface for RateLimitedPlatformProvider<T> {
    fn attestation(&self, report_data: &[u8]) -> Result<Vec<u8>, String> {
        if !self.rate_limiter.check_rate_limit() {
            return Err(format!(
                "Rate limit exceeded for entity {}",
                self.entity_id
            ));
        }
        self.inner.attestation(report_data)
    }
    
    fn platform_info(&self) -> Result<(String, String, bool), String> {
        if !self.rate_limiter.check_rate_limit() {
            return Err(format!(
                "Rate limit exceeded for entity {}",
                self.entity_id
            ));
        }
        self.inner.platform_info()
    }
}

/// Wrapper that adds rate limiting to CryptoInterface
pub struct RateLimitedCryptoProvider<T: CryptoInterface> {
    inner: T,
    entity_id: EntityId,
    rate_limiter: RateLimiter,
}

impl<T: CryptoInterface> RateLimitedCryptoProvider<T> {
    pub fn new(inner: T, entity_id: EntityId, ops_per_sec: u64, burst_size: u64) -> Self {
        Self {
            inner,
            entity_id,
            rate_limiter: RateLimiter::new(ops_per_sec, burst_size),
        }
    }
}

impl<T: CryptoInterface> CryptoInterface for RateLimitedCryptoProvider<T> {
    fn hash(&self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, String> {
        if !self.rate_limiter.check_rate_limit() {
            return Err(format!("Rate limit exceeded for entity {}", self.entity_id));
        }
        self.inner.hash(data, algorithm)
    }
    
    fn encrypt(&self, data: &[u8], key: &[u8], algorithm: &str) -> Result<Vec<u8>, String> {
        if !self.rate_limiter.check_rate_limit() {
            return Err(format!("Rate limit exceeded for entity {}", self.entity_id));
        }
        self.inner.encrypt(data, key, algorithm)
    }
    
    fn decrypt(&self, data: &[u8], key: &[u8], algorithm: &str) -> Result<Vec<u8>, String> {
        if !self.rate_limiter.check_rate_limit() {
            return Err(format!("Rate limit exceeded for entity {}", self.entity_id));
        }
        self.inner.decrypt(data, key, algorithm)
    }
    
    fn sign(&self, data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String> {
        if !self.rate_limiter.check_rate_limit() {
            return Err(format!("Rate limit exceeded for entity {}", self.entity_id));
        }
        self.inner.sign(data, private_key)
    }
    
    fn verify(&self, data: &[u8], public_key: &[u8], signature: &[u8]) -> Result<bool, String> {
        if !self.rate_limiter.check_rate_limit() {
            return Err(format!("Rate limit exceeded for entity {}", self.entity_id));
        }
        self.inner.verify(data, public_key, signature)
    }
    
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        if !self.rate_limiter.check_rate_limit() {
            return Err(format!("Rate limit exceeded for entity {}", self.entity_id));
        }
        self.inner.generate_keypair()
    }
}

// ============================================================================
// Quota Enforced Providers - Track usage against quotas
// ============================================================================

struct QuotaTracker {
    max_bytes: Option<u64>,
    max_operations: Option<u64>,
    bytes_used: Arc<RwLock<u64>>,
    operations_used: Arc<RwLock<u64>>,
}

impl QuotaTracker {
    fn new(max_bytes: Option<u64>, max_operations: Option<u64>) -> Self {
        Self {
            max_bytes,
            max_operations,
            bytes_used: Arc::new(RwLock::new(0)),
            operations_used: Arc::new(RwLock::new(0)),
        }
    }
    
    fn check_quota(&self, bytes: usize) -> bool {
        let mut ops = self.operations_used.write().unwrap();
        let mut bytes_used = self.bytes_used.write().unwrap();
        
        // Check operation quota
        if let Some(max_ops) = self.max_operations {
            if *ops >= max_ops {
                return false;
            }
        }
        
        // Check byte quota
        if let Some(max_bytes) = self.max_bytes {
            if *bytes_used + bytes as u64 > max_bytes {
                return false;
            }
        }
        
        // Update counters
        *ops += 1;
        *bytes_used += bytes as u64;
        true
    }
    
    fn get_usage(&self) -> (u64, u64) {
        let ops = *self.operations_used.read().unwrap();
        let bytes = *self.bytes_used.read().unwrap();
        (ops, bytes)
    }
}

/// Wrapper that adds quota enforcement to CryptoInterface
pub struct QuotaEnforcedCryptoProvider<T: CryptoInterface> {
    inner: T,
    entity_id: EntityId,
    quota_tracker: QuotaTracker,
}

impl<T: CryptoInterface> QuotaEnforcedCryptoProvider<T> {
    pub fn new(
        inner: T,
        entity_id: EntityId,
        max_bytes: Option<u64>,
        max_operations: Option<u64>,
    ) -> Self {
        Self {
            inner,
            entity_id,
            quota_tracker: QuotaTracker::new(max_bytes, max_operations),
        }
    }
    
    pub fn get_usage(&self) -> (u64, u64) {
        self.quota_tracker.get_usage()
    }
}

impl<T: CryptoInterface> CryptoInterface for QuotaEnforcedCryptoProvider<T> {
    fn hash(&self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, String> {
        if !self.quota_tracker.check_quota(data.len()) {
            return Err(format!("Quota exceeded for entity {}", self.entity_id));
        }
        self.inner.hash(data, algorithm)
    }
    
    fn encrypt(&self, data: &[u8], key: &[u8], algorithm: &str) -> Result<Vec<u8>, String> {
        if !self.quota_tracker.check_quota(data.len()) {
            return Err(format!("Quota exceeded for entity {}", self.entity_id));
        }
        self.inner.encrypt(data, key, algorithm)
    }
    
    fn decrypt(&self, data: &[u8], key: &[u8], algorithm: &str) -> Result<Vec<u8>, String> {
        if !self.quota_tracker.check_quota(data.len()) {
            return Err(format!("Quota exceeded for entity {}", self.entity_id));
        }
        self.inner.decrypt(data, key, algorithm)
    }
    
    fn sign(&self, data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String> {
        if !self.quota_tracker.check_quota(data.len()) {
            return Err(format!("Quota exceeded for entity {}", self.entity_id));
        }
        self.inner.sign(data, private_key)
    }
    
    fn verify(&self, data: &[u8], public_key: &[u8], signature: &[u8]) -> Result<bool, String> {
        if !self.quota_tracker.check_quota(data.len()) {
            return Err(format!("Quota exceeded for entity {}", self.entity_id));
        }
        self.inner.verify(data, public_key, signature)
    }
    
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        if !self.quota_tracker.check_quota(0) {
            return Err(format!("Quota exceeded for entity {}", self.entity_id));
        }
        self.inner.generate_keypair()
    }
}
