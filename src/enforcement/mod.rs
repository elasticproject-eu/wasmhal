// Enforcement Layer - Capability-based security for HAL access
//
// This module provides fine-grained access control over HAL interfaces,
// allowing different entities (WASM modules, services) to have restricted
// access to only the capabilities they need.

pub mod audit;
pub mod engine;
pub mod policy;
pub mod wrappers;

pub use audit::{AuditEvent, AuditLog};
pub use engine::EnforcementLayer;
pub use policy::{CapabilitySet, EntityPolicy, PolicyEngine};

use serde::{Deserialize, Serialize};

/// Unique identifier for an entity (WASM module, service, etc.)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityId(pub String);

impl EntityId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error types for enforcement layer
#[derive(Debug, thiserror::Error)]
pub enum EnforcementError {
    #[error("Entity {0} not found")]
    EntityNotFound(EntityId),

    #[error("Capability {0} denied for entity {1}")]
    CapabilityDenied(String, EntityId),

    #[error("Rate limit exceeded for entity {0}: {1}")]
    RateLimitExceeded(EntityId, String),

    #[error("Quota exceeded for entity {0}: {1}")]
    QuotaExceeded(EntityId, String),

    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("HAL initialization failed: {0}")]
    HalInitError(String),
}

pub type EnforcementResult<T> = Result<T, EnforcementError>;
