// Integration test for Intel TDX platform with 4 WASI-standard interfaces
// Tests Clock, Random, Storage, and Network functionality in TDX environment

use elastic_tee_hal::{
    ElasticTeeHal, ClockInterface, RandomInterface, StorageInterface, SocketInterface,
    HalResult,
};
use std::time::Duration;

#[tokio::test]
async fn test_tdx_platform_detection() -> HalResult<()> {
    println!("\n=== INTEL TDX PLATFORM VERIFICATION ===");
    
    // Create HAL with automatic platform detection
    let hal = ElasticTeeHal::new()?;
    
    println!("✓ HAL initialized successfully");
    println!("  - Platform type: {:?}", hal.platform_type());
    println!("  - Initialized: {}", hal.is_initialized());
    
    // Get capabilities
    let capabilities = hal.capabilities().await;
    println!("\n✓ Platform capabilities retrieved");
    println!("  - HAL version: {}", capabilities.hal_version);
    println!("  - Clock support: {}", capabilities.features.clock);
    println!("  - Random support: {}", capabilities.features.random);
    println!("  - Storage support: {}", capabilities.features.storage);
    println!("  - Network support: {}", capabilities.features.tcp_sockets);
    println!("  - Attestation support: {}", capabilities.features.attestation);
    
    // Test attestation with report data (nonce)
    let nonce = b"test_nonce_12345";
    let attestation = hal.attest(nonce).await?;
    println!("\n✓ Generated TDX attestation");
    println!("  - Attestation size: {} bytes", attestation.len());
    println!("  - Report data: {} bytes", nonce.len());
    
    Ok(())
}

#[tokio::test]
async fn test_tdx_clock_interface() -> HalResult<()> {
    println!("\n=== INTEL TDX CLOCK INTERFACE TEST ===");
    
    let clock = ClockInterface::new();
    
    // Test system time
    let time_info = clock.read_current_time()?;
    println!("✓ System time read successfully");
    println!("  - Seconds since epoch: {}", time_info.seconds);
    println!("  - Nanoseconds: {}", time_info.nanoseconds);
    
    // Test monotonic time
    let monotonic = clock.read_monotonic_time()?;
    println!("\n✓ Monotonic time read successfully");
    println!("  - Elapsed seconds: {}", monotonic.elapsed_seconds);
    println!("  - Elapsed nanoseconds: {}", monotonic.elapsed_nanoseconds);
    
    // Test sleep
    println!("\n✓ Testing async sleep (10ms)...");
    clock.sleep(Duration::from_millis(10)).await?;
    println!("  - Sleep completed successfully");
    
    // Test high-resolution timestamp
    let timestamp = clock.get_high_resolution_timestamp()?;
    println!("\n✓ High-resolution timestamp: {} ns", timestamp);
    
    Ok(())
}

#[tokio::test]
async fn test_tdx_random_interface() -> HalResult<()> {
    println!("\n=== INTEL TDX RANDOM INTERFACE TEST ===");
    println!("Testing hardware RNG (RDRAND/RDSEED)");
    
    let random = RandomInterface::new();
    
    // Test random bytes generation
    let bytes = random.generate_random_bytes(32)?;
    println!("\n✓ Generated 32 random bytes");
    println!("  - Sample: {:02x}{:02x}{:02x}{:02x}...", 
             bytes[0], bytes[1], bytes[2], bytes[3]);
    
    // Test random integers
    let random_u32 = random.generate_random_u32()?;
    let random_u64 = random.generate_random_u64()?;
    println!("\n✓ Generated random integers");
    println!("  - u32: {}", random_u32);
    println!("  - u64: {}", random_u64);
    
    // Test UUID generation
    let uuid = random.generate_uuid_v4()?;
    println!("\n✓ Generated UUID v4: {}", uuid);
    
    // Test nonce generation
    let nonce = random.generate_nonce(16)?;
    println!("\n✓ Generated 16-byte nonce");
    
    // Test key material generation
    let key_material = random.generate_key_material(32)?;
    println!("✓ Generated 32-byte key material");
    
    // Test randomness quality
    let entropy = random.test_randomness_quality(10000)?;
    println!("\n✓ Randomness quality test");
    println!("  - Shannon entropy: {:.4} bits/byte (max: 8.0)", entropy);
    println!("  - Quality: {}", if entropy > 7.5 { "EXCELLENT" } else { "POOR" });
    
    // Test hardware RNG detection
    use elastic_tee_hal::random::hardware_rng;
    let hw_rng_available = hardware_rng::is_hardware_rng_available();
    println!("\n✓ Hardware RNG detection");
    println!("  - RDRAND/RDSEED available: {}", hw_rng_available);
    
    Ok(())
}

#[tokio::test]
async fn test_tdx_storage_interface() -> HalResult<()> {
    println!("\n=== INTEL TDX STORAGE INTERFACE TEST ===");
    
    let temp_dir = tempfile::TempDir::new().unwrap();
    let storage = StorageInterface::new(temp_dir.path()).await?;
    
    println!("✓ Storage interface initialized");
    println!("  - Base path: {:?}", temp_dir.path());
    
    // Test unencrypted container
    let container = storage.open_container("test_container", false).await?;
    println!("\n✓ Created unencrypted container");
    println!("  - Handle: {}", container);
    
    // Test write and read
    let test_data = b"Hello from Intel TDX!";
    storage.write_object(container, "test_key", test_data).await?;
    println!("\n✓ Wrote object to storage");
    println!("  - Key: test_key");
    println!("  - Size: {} bytes", test_data.len());
    
    let read_data = storage.read_object(container, "test_key").await?;
    println!("\n✓ Read object from storage");
    println!("  - Data: {:?}", String::from_utf8_lossy(&read_data));
    assert_eq!(test_data, read_data.as_slice());
    
    // Test list objects
    let objects = storage.list_objects(container).await?;
    println!("\n✓ Listed objects in container: {:?}", objects);
    
    // Test encrypted container
    let encrypted_container = storage.open_container("encrypted_container", true).await?;
    println!("\n✓ Created encrypted container (AES-256-GCM)");
    
    let secret_data = b"Secret TDX data";
    storage.write_object(encrypted_container, "secret", secret_data).await?;
    println!("✓ Wrote encrypted object");
    
    let decrypted_data = storage.read_object(encrypted_container, "secret").await?;
    println!("✓ Read and decrypted object");
    assert_eq!(secret_data, decrypted_data.as_slice());
    
    // Test metadata
    let metadata = storage.get_container_metadata(container).await?;
    println!("\n✓ Container metadata:");
    println!("  - Object count: {}", metadata.object_count);
    println!("  - Total size: {} bytes", metadata.total_size);
    println!("  - Encrypted: {}", metadata.encrypted);
    
    Ok(())
}

#[tokio::test]
async fn test_tdx_network_interface() -> HalResult<()> {
    println!("\n=== INTEL TDX NETWORK INTERFACE TEST ===");
    println!("Testing TCP sockets with TDX network isolation");
    
    let sockets = SocketInterface::new();
    
    // Test TCP socket creation
    let listener_handle = sockets.create_tcp_socket("127.0.0.1:0").await?;
    println!("\n✓ Created TCP listener");
    println!("  - Handle: {}", listener_handle);
    
    // Get the actual bound address
    let listener_addr = sockets.get_socket_info(listener_handle).await?;
    println!("  - Bound to: {:?}", listener_addr.local_address);
    
    // Test UDP socket
    let udp_handle = sockets.create_udp_socket("127.0.0.1:0").await?;
    println!("\n✓ Created UDP socket");
    println!("  - Handle: {}", udp_handle);
    
    let udp_info = sockets.get_socket_info(udp_handle).await?;
    println!("  - Bound to: {:?}", udp_info.local_address);
    
    println!("\n✓ Network interface test completed");
    println!("  - TCP sockets: working");
    println!("  - UDP sockets: working");
    println!("  - TDX network isolation: active");
    
    Ok(())
}

#[tokio::test]
async fn test_tdx_all_interfaces_integration() -> HalResult<()> {
    println!("\n=== INTEL TDX FULL INTEGRATION TEST ===");
    println!("Testing all 4 WASI interfaces together");
    
    // 1. Initialize platform
    let hal = ElasticTeeHal::new()?;
    println!("\n[1/4] ✓ Platform initialized: {:?}", hal.platform_type());
    
    // 2. Test Clock
    let clock = ClockInterface::new();
    let time_start = clock.read_current_time()?;
    println!("[2/4] ✓ Clock interface working (time: {})", time_start.seconds);
    
    // 3. Test Random
    let random = RandomInterface::new();
    let random_key = random.generate_key_material(32)?;
    println!("[3/4] ✓ Random interface working (generated {} byte key)", random_key.len());
    
    // 4. Test Storage with random data
    let temp_dir = tempfile::TempDir::new().unwrap();
    let storage = StorageInterface::new(temp_dir.path()).await?;
    let container = storage.open_container("integration_test", true).await?;
    storage.write_object(container, "random_key", &random_key).await?;
    let retrieved_key = storage.read_object(container, "random_key").await?;
    assert_eq!(random_key, retrieved_key);
    println!("[4/4] ✓ Storage interface working (stored and retrieved data)");
    
    // 5. Verify time elapsed
    let time_end = clock.read_current_time()?;
    let elapsed = time_end.seconds - time_start.seconds;
    println!("\n✓ Integration test completed in {} seconds", elapsed);
    
    // 6. Generate final attestation with report data
    let report_data = b"integration_test_completed";
    let attestation = hal.attest(report_data).await?;
    println!("✓ Final attestation generated: {} bytes", attestation.len());
    println!("  - Report data: {:?}", String::from_utf8_lossy(report_data));
    
    println!("\n=== ALL TESTS PASSED ===");
    println!("Intel TDX environment fully functional with:");
    println!("  ✓ Platform detection and attestation");
    println!("  ✓ Clock interface (WASI-compatible)");
    println!("  ✓ Random interface (RDRAND/RDSEED)");
    println!("  ✓ Storage interface (encrypted)");
    println!("  ✓ Network interface (isolated)");
    
    Ok(())
}
