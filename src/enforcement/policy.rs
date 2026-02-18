// Policy definitions and management

use super::{EnforcementError, EnforcementResult, EntityId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Capabilities that can be granted to an entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub platform: bool,      // Platform attestation
    pub capabilities: bool,  // Capability detection
    pub crypto: bool,        // Cryptographic operations
    pub random: bool,        // Random number generation
    pub clock: bool,         // Time operations
    pub storage: bool,       // Storage operations
    pub sockets: bool,       // Network sockets
    pub gpu: bool,           // GPU compute
    pub resources: bool,     // Resource allocation
    pub events: bool,        // Event handling
    pub communication: bool, // Inter-component communication
}

impl CapabilitySet {
    /// Create a capability set with all capabilities disabled
    pub fn none() -> Self {
        Self {
            platform: false,
            capabilities: false,
            crypto: false,
            random: false,
            clock: false,
            storage: false,
            sockets: false,
            gpu: false,
            resources: false,
            events: false,
            communication: false,
        }
    }

    /// Create a capability set with all capabilities enabled
    pub fn all() -> Self {
        Self {
            platform: true,
            capabilities: true,
            crypto: true,
            random: true,
            clock: true,
            storage: true,
            sockets: true,
            gpu: true,
            resources: true,
            events: true,
            communication: true,
        }
    }

    /// Check if a specific capability is granted
    pub fn has_capability(&self, cap: &str) -> bool {
        match cap {
            "platform" => self.platform,
            "capabilities" => self.capabilities,
            "crypto" => self.crypto,
            "random" => self.random,
            "clock" => self.clock,
            "storage" => self.storage,
            "sockets" => self.sockets,
            "gpu" => self.gpu,
            "resources" => self.resources,
            "events" => self.events,
            "communication" => self.communication,
            _ => false,
        }
    }
}

/// Rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub operations_per_second: u64,
    pub burst_size: u64,
}

impl RateLimit {
    pub fn new(ops_per_sec: u64) -> Self {
        Self {
            operations_per_second: ops_per_sec,
            burst_size: ops_per_sec * 2, // Allow 2x burst
        }
    }
}

/// Quota configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quota {
    pub max_bytes: Option<u64>,
    pub max_operations: Option<u64>,
}

/// Policy for a single entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityPolicy {
    pub entity_id: EntityId,
    pub capabilities: CapabilitySet,

    #[serde(default)]
    pub rate_limits: HashMap<String, RateLimit>,

    #[serde(default)]
    pub quotas: HashMap<String, Quota>,

    /// Whether this entity can grant capabilities to others
    #[serde(default)]
    pub can_grant: bool,
}

impl EntityPolicy {
    pub fn new(entity_id: EntityId, capabilities: CapabilitySet) -> Self {
        Self {
            entity_id,
            capabilities,
            rate_limits: HashMap::new(),
            quotas: HashMap::new(),
            can_grant: false,
        }
    }

    pub fn with_rate_limit(mut self, capability: impl Into<String>, limit: RateLimit) -> Self {
        self.rate_limits.insert(capability.into(), limit);
        self
    }

    pub fn with_quota(mut self, capability: impl Into<String>, quota: Quota) -> Self {
        self.quotas.insert(capability.into(), quota);
        self
    }

    pub fn as_umbrella(mut self) -> Self {
        self.can_grant = true;
        self
    }
}

/// Complete policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub entities: Vec<EntityPolicy>,

    #[serde(default)]
    pub umbrella: Option<EntityPolicy>,
}

/// Policy engine that manages and enforces policies
pub struct PolicyEngine {
    policies: HashMap<EntityId, EntityPolicy>,
    umbrella_id: Option<EntityId>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            umbrella_id: None,
        }
    }

    /// Load policies from configuration
    pub fn from_config(config: PolicyConfig) -> EnforcementResult<Self> {
        let mut engine = Self::new();

        // Load entity policies
        for policy in config.entities {
            engine.add_policy(policy)?;
        }

        // Load umbrella policy
        if let Some(umbrella) = config.umbrella {
            let umbrella_id = umbrella.entity_id.clone();
            engine.add_policy(umbrella)?;
            engine.umbrella_id = Some(umbrella_id);
        }

        Ok(engine)
    }

    /// Add or update a policy
    pub fn add_policy(&mut self, policy: EntityPolicy) -> EnforcementResult<()> {
        self.policies.insert(policy.entity_id.clone(), policy);
        Ok(())
    }

    /// Get policy for an entity
    pub fn get_policy(&self, entity_id: &EntityId) -> EnforcementResult<&EntityPolicy> {
        self.policies
            .get(entity_id)
            .ok_or_else(|| EnforcementError::EntityNotFound(entity_id.clone()))
    }

    /// Check if entity has a specific capability
    pub fn check_capability(
        &self,
        entity_id: &EntityId,
        capability: &str,
    ) -> EnforcementResult<()> {
        let policy = self.get_policy(entity_id)?;

        if !policy.capabilities.has_capability(capability) {
            return Err(EnforcementError::CapabilityDenied(
                capability.to_string(),
                entity_id.clone(),
            ));
        }

        Ok(())
    }

    /// Grant a capability to an entity (requires umbrella permission)
    pub fn grant_capability(
        &mut self,
        granter_id: &EntityId,
        target_id: &EntityId,
        capability: &str,
    ) -> EnforcementResult<()> {
        // Check if granter is umbrella entity
        if Some(granter_id) != self.umbrella_id.as_ref() {
            let granter_policy = self.get_policy(granter_id)?;
            if !granter_policy.can_grant {
                return Err(EnforcementError::CapabilityDenied(
                    "grant_capability".to_string(),
                    granter_id.clone(),
                ));
            }
        }

        // Grant the capability
        let policy = self
            .policies
            .get_mut(target_id)
            .ok_or_else(|| EnforcementError::EntityNotFound(target_id.clone()))?;

        match capability {
            "platform" => policy.capabilities.platform = true,
            "capabilities" => policy.capabilities.capabilities = true,
            "crypto" => policy.capabilities.crypto = true,
            "random" => policy.capabilities.random = true,
            "clock" => policy.capabilities.clock = true,
            "storage" => policy.capabilities.storage = true,
            "sockets" => policy.capabilities.sockets = true,
            "gpu" => policy.capabilities.gpu = true,
            "resources" => policy.capabilities.resources = true,
            "events" => policy.capabilities.events = true,
            "communication" => policy.capabilities.communication = true,
            _ => {
                return Err(EnforcementError::InvalidPolicy(format!(
                    "Unknown capability: {}",
                    capability
                )))
            }
        }

        Ok(())
    }

    /// Revoke a capability from an entity
    pub fn revoke_capability(
        &mut self,
        revoker_id: &EntityId,
        target_id: &EntityId,
        capability: &str,
    ) -> EnforcementResult<()> {
        // Check if revoker is umbrella entity
        if Some(revoker_id) != self.umbrella_id.as_ref() {
            let revoker_policy = self.get_policy(revoker_id)?;
            if !revoker_policy.can_grant {
                return Err(EnforcementError::CapabilityDenied(
                    "revoke_capability".to_string(),
                    revoker_id.clone(),
                ));
            }
        }

        // Revoke the capability
        let policy = self
            .policies
            .get_mut(target_id)
            .ok_or_else(|| EnforcementError::EntityNotFound(target_id.clone()))?;

        match capability {
            "platform" => policy.capabilities.platform = false,
            "capabilities" => policy.capabilities.capabilities = false,
            "crypto" => policy.capabilities.crypto = false,
            "random" => policy.capabilities.random = false,
            "clock" => policy.capabilities.clock = false,
            "storage" => policy.capabilities.storage = false,
            "sockets" => policy.capabilities.sockets = false,
            "gpu" => policy.capabilities.gpu = false,
            "resources" => policy.capabilities.resources = false,
            "events" => policy.capabilities.events = false,
            "communication" => policy.capabilities.communication = false,
            _ => {
                return Err(EnforcementError::InvalidPolicy(format!(
                    "Unknown capability: {}",
                    capability
                )))
            }
        }

        Ok(())
    }

    /// List all entities
    pub fn list_entities(&self) -> Vec<&EntityId> {
        self.policies.keys().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_set() {
        let caps = CapabilitySet::none();
        assert!(!caps.platform);
        assert!(!caps.crypto);

        let all_caps = CapabilitySet::all();
        assert!(all_caps.platform);
        assert!(all_caps.crypto);
    }

    #[test]
    fn test_policy_engine() {
        let mut engine = PolicyEngine::new();

        let policy = EntityPolicy::new(EntityId::new("test-entity"), CapabilitySet::none());

        engine.add_policy(policy).unwrap();

        let result = engine.check_capability(&EntityId::new("test-entity"), "platform");
        assert!(result.is_err());
    }
}
