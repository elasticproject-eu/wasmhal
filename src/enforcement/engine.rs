// Enforcement engine - Creates restricted HAL instances per entity

use super::{wrappers::*, AuditLog, EnforcementResult, EntityId, PolicyEngine};
use crate::interfaces::HalProvider;
use crate::providers::*;
use std::sync::Arc;

/// Main enforcement layer that creates restricted HAL instances
pub struct EnforcementLayer {
    policy_engine: Arc<PolicyEngine>,
    audit_log: AuditLog,
}

impl EnforcementLayer {
    pub fn new(policy_engine: PolicyEngine) -> Self {
        Self {
            policy_engine: Arc::new(policy_engine),
            audit_log: AuditLog::new(),
        }
    }

    pub fn with_audit_log(policy_engine: PolicyEngine, audit_log: AuditLog) -> Self {
        Self {
            policy_engine: Arc::new(policy_engine),
            audit_log,
        }
    }

    /// Create a restricted HAL instance for an entity
    pub fn create_restricted_hal(&self, entity_id: &EntityId) -> EnforcementResult<HalProvider> {
        let policy = self.policy_engine.get_policy(entity_id)?;
        let mut hal = HalProvider::new();

        // Platform interface (attestation)
        if policy.capabilities.platform {
            if let Ok(platform) = DefaultPlatformProvider::new() {
                let audited = AuditedPlatformProvider::new(
                    platform,
                    entity_id.clone(),
                    self.audit_log.clone(),
                );

                // Apply rate limiting if configured
                if let Some(rate_limit) = policy.rate_limits.get("platform") {
                    let rate_limited = RateLimitedPlatformProvider::new(
                        audited,
                        entity_id.clone(),
                        rate_limit.operations_per_second,
                        rate_limit.burst_size,
                    );
                    hal.platform = Some(Box::new(rate_limited));
                } else {
                    hal.platform = Some(Box::new(audited));
                }
            }
        }

        // Crypto interface
        if policy.capabilities.crypto {
            let crypto = DefaultCryptoProvider::default();
            let audited =
                AuditedCryptoProvider::new(crypto, entity_id.clone(), self.audit_log.clone());

            // Apply rate limiting
            let rate_limited = if let Some(rate_limit) = policy.rate_limits.get("crypto") {
                RateLimitedCryptoProvider::new(
                    audited,
                    entity_id.clone(),
                    rate_limit.operations_per_second,
                    rate_limit.burst_size,
                )
            } else {
                // Default rate limit: 1000 ops/sec
                RateLimitedCryptoProvider::new(audited, entity_id.clone(), 1000, 2000)
            };

            // Apply quota if configured
            if let Some(quota) = policy.quotas.get("crypto") {
                let quota_enforced = QuotaEnforcedCryptoProvider::new(
                    rate_limited,
                    entity_id.clone(),
                    quota.max_bytes,
                    quota.max_operations,
                );
                hal.crypto = Some(Box::new(quota_enforced));
            } else {
                hal.crypto = Some(Box::new(rate_limited));
            }
        }

        // Capabilities interface
        if policy.capabilities.capabilities {
            hal.capabilities = Some(Box::new(DefaultCapabilitiesProvider::default()));
        }

        // Random interface
        if policy.capabilities.random {
            hal.random = Some(Box::new(DefaultRandomProvider::default()));
        }

        // Clock interface
        if policy.capabilities.clock {
            hal.clock = Some(Box::new(DefaultClockProvider::default()));
        }

        // Storage interface
        if policy.capabilities.storage {
            // TODO: Add storage provider when implemented
        }

        Ok(hal)
    }

    /// Get the audit log
    pub fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }

    /// Get the policy engine (for capability management)
    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    /// Check if an entity has a specific capability
    pub fn has_capability(&self, entity_id: &EntityId, capability: &str) -> bool {
        self.policy_engine
            .check_capability(entity_id, capability)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::policy::{CapabilitySet, EntityPolicy};

    #[test]
    fn test_enforcement_layer() {
        let mut policy_engine = PolicyEngine::new();

        // Create a restricted entity
        let entity_id = EntityId::new("test-entity");
        let mut caps = CapabilitySet::none();
        caps.crypto = true;
        caps.random = true;

        let policy = EntityPolicy::new(entity_id.clone(), caps);
        policy_engine.add_policy(policy).unwrap();

        // Create enforcement layer
        let enforcement = EnforcementLayer::new(policy_engine);

        // Create restricted HAL
        let hal = enforcement.create_restricted_hal(&entity_id).unwrap();

        // Should have crypto and random
        assert!(hal.crypto.is_some());
        assert!(hal.random.is_some());

        // Should NOT have platform
        assert!(hal.platform.is_none());
    }
}
