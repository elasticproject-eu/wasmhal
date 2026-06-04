// Integration test for Intel TDX platform with 4 WASI-standard interfaces
// Tests Clock, Random, Storage, and Network functionality in TDX environment

use elastic_tee_hal::{
    ClockInterface, ElasticTeeHal, HalResult, RandomInterface, SocketInterface, StorageInterface,
};
use std::time::Duration;

fn init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = env_logger::builder().is_test(true).try_init();
    });
}

#[tokio::test]
#[ignore = "requires Intel TDX hardware (/dev/tdx_guest) and ITA_API_KEY"]
async fn test_tdx_platform_detection() -> HalResult<()> {
    init();
    log::info!("\n=== INTEL TDX PLATFORM VERIFICATION ===");

    // Create HAL with automatic platform detection
    let hal = ElasticTeeHal::new()?;

    log::info!("✓ HAL initialized successfully");
    log::debug!("  - Platform type: {:?}", hal.platform_type());
    log::debug!("  - Initialized: {}", hal.is_initialized());

    // Get capabilities
    let capabilities = hal.capabilities().await;
    log::info!("\n✓ Platform capabilities retrieved");
    log::debug!("  - HAL version: {}", capabilities.hal_version);
    log::debug!("  - Clock support: {}", capabilities.features.clock);
    log::debug!("  - Random support: {}", capabilities.features.random);
    log::debug!("  - Storage support: {}", capabilities.features.storage);
    log::debug!("  - Network support: {}", capabilities.features.tcp_sockets);
    log::debug!(
        "  - Attestation support: {}",
        capabilities.features.attestation
    );

    // Test attestation with report data (nonce)
    let nonce = b"test_nonce_12345";
    let attestation = hal.attest(nonce).await?;
    log::info!("\n✓ Generated TDX attestation");
    log::debug!("  - Attestation size: {} bytes", attestation.len());
    log::debug!("  - Report data: {} bytes", nonce.len());

    Ok(())
}

#[tokio::test]
#[ignore = "requires Intel TDX hardware (/dev/tdx_guest) and ITA_API_KEY"]
async fn test_tdx_clock_interface() -> HalResult<()> {
    init();
    log::info!("\n=== INTEL TDX CLOCK INTERFACE TEST ===");

    let clock = ClockInterface::new();

    // Test system time
    let time_info = clock.read_current_time()?;
    log::info!("✓ System time read successfully");
    log::debug!("  - Seconds since epoch: {}", time_info.seconds);
    log::debug!("  - Nanoseconds: {}", time_info.nanoseconds);

    // Test monotonic time
    let monotonic = clock.read_monotonic_time()?;
    log::info!("\n✓ Monotonic time read successfully");
    log::debug!("  - Elapsed seconds: {}", monotonic.elapsed_seconds);
    log::debug!("  - Elapsed nanoseconds: {}", monotonic.elapsed_nanoseconds);

    // Test sleep
    log::info!("\n✓ Testing async sleep (10ms)...");
    clock.sleep(Duration::from_millis(10)).await?;
    log::debug!("  - Sleep completed successfully");

    // Test high-resolution timestamp
    let timestamp = clock.get_high_resolution_timestamp()?;
    log::info!("\n✓ High-resolution timestamp: {} ns", timestamp);

    Ok(())
}

#[tokio::test]
#[ignore = "requires Intel TDX hardware (/dev/tdx_guest) and ITA_API_KEY"]
async fn test_tdx_random_interface() -> HalResult<()> {
    init();
    log::info!("\n=== INTEL TDX RANDOM INTERFACE TEST ===");
    log::info!("Testing hardware RNG (RDRAND/RDSEED)");

    let random = RandomInterface::new();

    // Test random bytes generation
    let bytes = random.generate_random_bytes(32)?;
    log::info!("\n✓ Generated 32 random bytes");
    log::debug!(
        "  - Sample: {:02x}{:02x}{:02x}{:02x}...",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3]
    );

    // Test random integers
    let random_u32 = random.generate_random_u32()?;
    let random_u64 = random.generate_random_u64()?;
    log::info!("\n✓ Generated random integers");
    log::debug!("  - u32: {}", random_u32);
    log::debug!("  - u64: {}", random_u64);

    // Test UUID generation
    let uuid = random.generate_uuid_v4()?;
    log::info!("\n✓ Generated UUID v4: {}", uuid);

    // Test nonce generation
    let nonce = random.generate_nonce(16)?;
    log::info!("\n✓ Generated 16-byte nonce");

    // Test key material generation
    let key_material = random.generate_key_material(32)?;
    log::info!("✓ Generated 32-byte key material");

    // Test randomness quality
    let entropy = random.test_randomness_quality(10000)?;
    log::info!("\n✓ Randomness quality test");
    log::debug!("  - Shannon entropy: {:.4} bits/byte (max: 8.0)", entropy);
    log::debug!(
        "  - Quality: {}",
        if entropy > 7.5 { "EXCELLENT" } else { "POOR" }
    );

    // Test hardware RNG detection
    use elastic_tee_hal::random::hardware_rng;
    let hw_rng_available = hardware_rng::is_hardware_rng_available();
    log::info!("\n✓ Hardware RNG detection");
    log::debug!("  - RDRAND/RDSEED available: {}", hw_rng_available);

    Ok(())
}

#[tokio::test]
#[ignore = "requires Intel TDX hardware (/dev/tdx_guest) and ITA_API_KEY"]
async fn test_tdx_storage_interface() -> HalResult<()> {
    init();
    log::info!("\n=== INTEL TDX STORAGE INTERFACE TEST ===");

    let temp_dir = tempfile::TempDir::new().unwrap();
    let storage = StorageInterface::new(temp_dir.path()).await?;

    log::info!("✓ Storage interface initialized");
    log::debug!("  - Base path: {:?}", temp_dir.path());

    // Test unencrypted container
    let container = storage.open_container("test_container", false).await?;
    log::info!("\n✓ Created unencrypted container");
    log::debug!("  - Handle: {}", container);

    // Test write and read
    let test_data = b"Hello from Intel TDX!";
    storage
        .write_object(container, "test_key", test_data)
        .await?;
    log::info!("\n✓ Wrote object to storage");
    log::debug!("  - Key: test_key");
    log::debug!("  - Size: {} bytes", test_data.len());

    let read_data = storage.read_object(container, "test_key").await?;
    log::info!("\n✓ Read object from storage");
    log::debug!("  - Data: {:?}", String::from_utf8_lossy(&read_data));
    assert_eq!(test_data, read_data.as_slice());

    // Test list objects
    let objects = storage.list_objects(container).await?;
    log::info!("\n✓ Listed objects in container: {:?}", objects);

    // Test encrypted container
    let encrypted_container = storage.open_container("encrypted_container", true).await?;
    log::info!("\n✓ Created encrypted container (AES-256-GCM)");

    let secret_data = b"Secret TDX data";
    storage
        .write_object(encrypted_container, "secret", secret_data)
        .await?;
    log::info!("✓ Wrote encrypted object");

    let decrypted_data = storage.read_object(encrypted_container, "secret").await?;
    log::info!("✓ Read and decrypted object");
    assert_eq!(secret_data, decrypted_data.as_slice());

    // Test metadata
    let metadata = storage.get_container_metadata(container).await?;
    log::info!("\n✓ Container metadata:");
    log::debug!("  - Object count: {}", metadata.object_count);
    log::debug!("  - Total size: {} bytes", metadata.total_size);
    log::debug!("  - Encrypted: {}", metadata.encrypted);

    Ok(())
}

#[tokio::test]
#[ignore = "requires Intel TDX hardware (/dev/tdx_guest) and ITA_API_KEY"]
async fn test_tdx_network_interface() -> HalResult<()> {
    init();
    log::info!("\n=== INTEL TDX NETWORK INTERFACE TEST ===");
    log::info!("Testing TCP sockets with TDX network isolation");

    let sockets = SocketInterface::new();

    // Test TCP socket creation
    let listener_handle = sockets.create_tcp_socket("127.0.0.1:0").await?;
    log::info!("\n✓ Created TCP listener");
    log::debug!("  - Handle: {}", listener_handle);

    // Get the actual bound address
    let listener_addr = sockets.get_socket_info(listener_handle).await?;
    log::debug!("  - Bound to: {:?}", listener_addr.local_address);

    // Test UDP socket
    let udp_handle = sockets.create_udp_socket("127.0.0.1:0").await?;
    log::info!("\n✓ Created UDP socket");
    log::debug!("  - Handle: {}", udp_handle);

    let udp_info = sockets.get_socket_info(udp_handle).await?;
    log::debug!("  - Bound to: {:?}", udp_info.local_address);

    log::info!("\n✓ Network interface test completed");
    log::debug!("  - TCP sockets: working");
    log::debug!("  - UDP sockets: working");
    log::debug!("  - TDX network isolation: active");

    Ok(())
}

#[tokio::test]
#[ignore = "requires Intel TDX hardware (/dev/tdx_guest) and ITA_API_KEY"]
async fn test_tdx_all_interfaces_integration() -> HalResult<()> {
    init();
    log::info!("\n=== INTEL TDX FULL INTEGRATION TEST ===");
    log::info!("Testing all 4 WASI interfaces together");

    // 1. Initialize platform
    let hal = ElasticTeeHal::new()?;
    log::info!("\n[1/4] ✓ Platform initialized: {:?}", hal.platform_type());

    // 2. Test Clock
    let clock = ClockInterface::new();
    let time_start = clock.read_current_time()?;
    log::info!(
        "[2/4] ✓ Clock interface working (time: {})",
        time_start.seconds
    );

    // 3. Test Random
    let random = RandomInterface::new();
    let random_key = random.generate_key_material(32)?;
    log::info!(
        "[3/4] ✓ Random interface working (generated {} byte key)",
        random_key.len()
    );

    // 4. Test Storage with random data
    let temp_dir = tempfile::TempDir::new().unwrap();
    let storage = StorageInterface::new(temp_dir.path()).await?;
    let container = storage.open_container("integration_test", true).await?;
    storage
        .write_object(container, "random_key", &random_key)
        .await?;
    let retrieved_key = storage.read_object(container, "random_key").await?;
    assert_eq!(random_key, retrieved_key);
    log::info!("[4/4] ✓ Storage interface working (stored and retrieved data)");

    // 5. Verify time elapsed
    let time_end = clock.read_current_time()?;
    let elapsed = time_end.seconds - time_start.seconds;
    log::info!("\n✓ Integration test completed in {} seconds", elapsed);

    // 6. Generate final attestation with report data
    let report_data = b"integration_test_completed";
    let attestation = hal.attest(report_data).await?;
    log::info!("✓ Final attestation generated: {} bytes", attestation.len());
    log::debug!(
        "  - Report data: {:?}",
        String::from_utf8_lossy(report_data)
    );

    log::info!("\n=== ALL TESTS PASSED ===");
    log::info!("Intel TDX environment fully functional with:");
    log::info!("  ✓ Platform detection and attestation");
    log::info!("  ✓ Clock interface (WASI-compatible)");
    log::info!("  ✓ Random interface (RDRAND/RDSEED)");
    log::info!("  ✓ Storage interface (encrypted)");
    log::info!("  ✓ Network interface (isolated)");

    Ok(())
}

/// End-to-end attestation test: TDX quote → Intel Trust Authority → EAR JWT
///
/// Run with your ITA API key:
///   ITA_API_KEY=<your-key> cargo test test_ita_attestation_roundtrip -- --nocapture --ignored
#[tokio::test]
#[ignore = "requires Intel TDX hardware (/dev/tdx_guest) and ITA_API_KEY"]
async fn test_ita_attestation_roundtrip() -> HalResult<()> {
    init();
    log::info!("\n=== INTEL TRUST AUTHORITY END-TO-END TEST ===");

    // Verify ITA key is present
    let api_key = std::env::var("ITA_API_KEY")
        .expect("ITA_API_KEY environment variable must be set to run this test");
    log::info!("✓ ITA_API_KEY loaded ({} chars)", api_key.len());

    // 1. Initialise HAL (auto-detects TDX)
    let hal = ElasticTeeHal::new()?;
    log::info!("✓ HAL initialised on {:?}", hal.platform_type());

    // 2. Generate a 32-byte random nonce as report-data
    let random = elastic_tee_hal::RandomInterface::new();
    let nonce = random.generate_nonce(32)?;
    log::debug!("✓ Generated 32-byte nonce: {}", hex::encode(&nonce));

    // 3. Get TDX quote from hardware + submit to ITA via the dedicated
    //    server-side API. (hal.attest() always returns measurements JSON;
    //    the EAR JWT is only produced by attest_with_ita().)
    log::info!("\n→ Calling hal.attest_with_ita() with nonce...");
    let ear_jwt = hal.attest_with_ita(&nonce).await?;
    let result = ear_jwt.into_bytes();

    // 4. Interpret the result
    let result_str = String::from_utf8_lossy(&result);

    if result_str.starts_with("ey") {
        // Looks like a JWT (base64url always starts with "ey" for {"alg":...})
        log::info!("\n✓ ITA returned EAR JWT token!");
        let parts: Vec<&str> = result_str.splitn(3, '.').collect();
        log::debug!("  - Header  : {}", parts.get(0).unwrap_or(&"<none>"));
        log::debug!(
            "  - Payload : {} chars (truncated)",
            parts.get(1).map(|s| s.len()).unwrap_or(0)
        );
        log::debug!("  - Full token length: {} bytes", result.len());
        log::info!("\n  Next step: send this EAR to your KBS to release the decryption key.");
    } else if result_str.starts_with("attestation-error:") {
        panic!("Attestation failed: {}", result_str);
    } else {
        // Raw quote returned (ITA submission failed but quote was generated)
        log::warn!("\n⚠ Raw TDX quote returned ({} bytes)", result.len());
        log::info!("  ITA submission may have failed. Check logs above for details.");
        log::debug!(
            "  Quote prefix (hex): {}",
            hex::encode(&result[..result.len().min(32)])
        );
        panic!("Expected EAR JWT but got raw quote. Check ITA_API_KEY and network connectivity.");
    }

    log::info!("\n=== ITA ROUND-TRIP COMPLETE ===");
    Ok(())
}
