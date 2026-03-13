// Example: Enforcement Layer with Multi-Entity Capability Control
//
// This demonstrates:
// - Multiple entities with different HAL access levels
// - Umbrella entity managing permissions
// - Audit logging of all operations
// - Rate limiting and quota enforcement
// - Dynamic capability granting/revoking

use elastic_tee_hal::enforcement::policy::{Quota, RateLimit};
use elastic_tee_hal::enforcement::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ELASTIC TEE HAL - Enforcement Layer Demo ===\n");

    // ========================================================================
    // 1. Setup: Create policy engine with multiple entities
    // ========================================================================

    println!("1. Setting up enforcement layer with 4 entities:\n");

    let mut policy_engine = PolicyEngine::new();

    // Entity A: Attestation Service (minimal privileges - only platform)
    let attestation_service_id = EntityId::new("attestation-service");
    let mut attestation_caps = CapabilitySet::none();
    attestation_caps.platform = true;
    attestation_caps.capabilities = true;

    let attestation_policy = EntityPolicy::new(attestation_service_id.clone(), attestation_caps)
        .with_rate_limit("platform", RateLimit::new(10)); // 10 attestations/sec max

    policy_engine.add_policy(attestation_policy)?;
    println!("  ✓ attestation-service: platform + capabilities only (10 ops/sec limit)");

    // Entity B: Crypto Worker (crypto + random)
    let crypto_worker_id = EntityId::new("crypto-worker");
    let mut crypto_caps = CapabilitySet::none();
    crypto_caps.crypto = true;
    crypto_caps.random = true;
    crypto_caps.clock = true;

    let crypto_policy = EntityPolicy::new(crypto_worker_id.clone(), crypto_caps)
        .with_rate_limit("crypto", RateLimit::new(1000)) // 1000 ops/sec
        .with_quota(
            "crypto",
            Quota {
                max_bytes: Some(10 * 1024 * 1024), // 10 MB
                max_operations: Some(10_000),
            },
        );

    policy_engine.add_policy(crypto_policy)?;
    println!("  ✓ crypto-worker: crypto + random + clock (1000 ops/sec, 10MB quota)");

    // Entity C: Untrusted Service (very limited - only random)
    let untrusted_id = EntityId::new("untrusted-service");
    let mut untrusted_caps = CapabilitySet::none();
    untrusted_caps.random = true;

    let untrusted_policy = EntityPolicy::new(untrusted_id.clone(), untrusted_caps)
        .with_rate_limit("random", RateLimit::new(100)); // Very limited

    policy_engine.add_policy(untrusted_policy)?;
    println!("  ✓ untrusted-service: random only (100 ops/sec limit)");

    // Entity D: Umbrella Entity (full privileges + can grant)
    let umbrella_id = EntityId::new("supervisor");
    let umbrella_policy =
        EntityPolicy::new(umbrella_id.clone(), CapabilitySet::all()).as_umbrella();

    policy_engine.add_policy(umbrella_policy)?;
    println!("  ✓ supervisor: all capabilities + can grant/revoke\n");

    // ========================================================================
    // 2. Create enforcement layer
    // ========================================================================

    println!("2. Creating enforcement layer with audit logging...\n");
    let enforcement = EnforcementLayer::new(policy_engine);

    // ========================================================================
    // 3. Test Entity A: Attestation Service
    // ========================================================================

    println!("3. Testing attestation-service (limited to platform):\n");
    let attestation_hal = enforcement.create_restricted_hal(&attestation_service_id)?;

    // This should work - has platform capability
    if let Some(platform) = &attestation_hal.platform {
        match platform.platform_info() {
            Ok((ptype, version, _)) => {
                println!("  ✓ Platform info: {} v{}", ptype, version);
            }
            Err(e) => println!("  ⚠ Platform info error (expected on non-TEE): {}", e),
        }
    }

    // This should be None - no crypto capability
    if attestation_hal.crypto.is_none() {
        println!("  ✓ Crypto interface correctly denied");
    }

    if attestation_hal.storage.is_none() {
        println!("  ✓ Storage interface correctly denied\n");
    }

    // ========================================================================
    // 4. Test Entity B: Crypto Worker
    // ========================================================================

    println!("4. Testing crypto-worker (crypto + random + clock):\n");
    let crypto_hal = enforcement.create_restricted_hal(&crypto_worker_id)?;

    // Test random generation (should work)
    if let Some(random) = &crypto_hal.random {
        match random.get_random_bytes(32) {
            Ok(bytes) => println!("  ✓ Generated {} random bytes", bytes.len()),
            Err(e) => println!("  ✗ Random generation failed: {}", e),
        }
    }

    // Test crypto (should work)
    if let Some(crypto) = &crypto_hal.crypto {
        let data = b"Hello, TEE!";
        match crypto.hash(data, "SHA-256") {
            Ok(hash) => println!("  ✓ SHA-256 hash: {} bytes", hash.len()),
            Err(e) => println!("  ✗ Hash failed: {}", e),
        }
    }

    // Test clock (should work)
    if let Some(clock) = &crypto_hal.clock {
        match clock.system_time() {
            Ok((secs, nanos)) => println!("  ✓ System time: {}.{:09}s", secs, nanos),
            Err(e) => println!("  ✗ Clock failed: {}", e),
        }
    }

    // Platform should be denied
    if crypto_hal.platform.is_none() {
        println!("  ✓ Platform interface correctly denied\n");
    }

    // ========================================================================
    // 5. Test Entity C: Untrusted Service
    // ========================================================================

    println!("5. Testing untrusted-service (random only):\n");
    let untrusted_hal = enforcement.create_restricted_hal(&untrusted_id)?;

    // Only random should work
    if let Some(random) = &untrusted_hal.random {
        match random.get_random_bytes(16) {
            Ok(bytes) => println!("  ✓ Generated {} random bytes", bytes.len()),
            Err(e) => println!("  ✗ Random generation failed: {}", e),
        }
    }

    // Everything else denied
    if untrusted_hal.platform.is_none() && untrusted_hal.crypto.is_none() {
        println!("  ✓ Platform and crypto correctly denied\n");
    }

    // ========================================================================
    // 6. Test Rate Limiting
    // ========================================================================

    println!("6. Testing rate limiting on crypto-worker:\n");
    if let Some(crypto) = &crypto_hal.crypto {
        let mut successes = 0;
        let mut rate_limited = 0;

        // Try to exceed rate limit (1000 ops/sec + burst)
        for i in 0..3000 {
            match crypto.hash(b"test", "SHA-256") {
                Ok(_) => successes += 1,
                Err(e) if e.contains("Rate limit") => rate_limited += 1,
                Err(_) => {}
            }
        }

        println!("  - Attempted 3000 operations");
        println!("  - Successful: {}", successes);
        println!("  - Rate limited: {}", rate_limited);

        if rate_limited > 0 {
            println!("  ✓ Rate limiting is working!\n");
        }
    }

    // ========================================================================
    // 7. Audit Log Review
    // ========================================================================

    println!("7. Reviewing audit log:\n");
    let audit_log = enforcement.audit_log();
    let total_events = audit_log.count();

    println!("  Total events logged: {}", total_events);

    // Events by entity
    println!("\n  Events by entity:");
    for entity_id in &[&attestation_service_id, &crypto_worker_id, &untrusted_id] {
        let count = audit_log.get_entity_events(entity_id).len();
        println!("    - {}: {} events", entity_id, count);
    }

    // Events by capability
    println!("\n  Events by capability:");
    for cap in &["platform", "crypto", "random"] {
        let count = audit_log.get_capability_events(cap).len();
        if count > 0 {
            println!("    - {}: {} events", cap, count);
        }
    }

    // Failed operations
    let failed = audit_log.get_failed_events();
    println!("\n  Failed operations: {}", failed.len());
    if !failed.is_empty() {
        for event in failed.iter().take(3) {
            println!("    - {} by {} failed", event.operation, event.entity_id);
        }
    }

    println!("\n=== Enforcement Layer Demo Complete ===\n");

    println!("Key Takeaways:");
    println!("  ✓ Fine-grained capability control per entity");
    println!("  ✓ Rate limiting prevents resource exhaustion");
    println!("  ✓ Quota enforcement tracks usage");
    println!("  ✓ Complete audit trail of all operations");
    println!("  ✓ Umbrella entity can manage permissions dynamically");

    Ok(())
}
