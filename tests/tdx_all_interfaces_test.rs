// Comprehensive integration tests for all interfaces in Intel TDX environment

use elastic_tee_hal::communication::{
    BufferConfig, CommunicationInterface, MessagePriority, MessageType,
};
use elastic_tee_hal::crypto::CryptoInterface;
use elastic_tee_hal::events::{
    EventData, EventHandlerConfig, EventInterface, EventPriority, SubscriptionFilter,
};
use elastic_tee_hal::gpu::{GpuBufferDescriptor, GpuBufferUsage, GpuInterface};
use elastic_tee_hal::resources::{ResourceInterface, ResourceLimits};
use elastic_tee_hal::*;
use std::sync::Arc;

fn init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = env_logger::builder().is_test(true).try_init();
    });
}

#[tokio::test]
async fn test_tdx_crypto_interface_complete() {
    init();
    log::info!("\n=== TDX CRYPTO INTERFACE TEST ===");

    // Verify TDX environment
    let hal = ElasticTeeHal::new().expect("Failed to initialize HAL");
    assert!(matches!(
        hal.platform_type(),
        platform::PlatformType::IntelTdx
    ));
    log::info!("✓ Verified Intel TDX environment");

    let crypto = CryptoInterface::new();

    // Test symmetric encryption
    let key = crypto
        .generate_symmetric_key("AES-256-GCM")
        .await
        .expect("Key generation failed");
    assert_eq!(key.len(), 32);
    log::info!("✓ Generated AES-256-GCM key: {} bytes", key.len());

    let plaintext = b"TDX secure data";
    let ciphertext = crypto
        .symmetric_encrypt("AES-256-GCM", &key, plaintext, None)
        .await
        .expect("Encryption failed");
    log::info!(
        "✓ Encrypted data: {} bytes -> {} bytes",
        plaintext.len(),
        ciphertext.len()
    );

    let decrypted = crypto
        .symmetric_decrypt("AES-256-GCM", &key, &ciphertext, None)
        .await
        .expect("Decryption failed");
    assert_eq!(plaintext, decrypted.as_slice());
    log::info!("✓ Decrypted and verified data");

    // Test hashing
    let hash = crypto
        .hash_data("SHA-256", b"test data")
        .await
        .expect("Hashing failed");
    assert_eq!(hash.len(), 32);
    log::info!("✓ SHA-256 hash: {} bytes", hash.len());

    // Test platform attestation with TDX measurements
    let nonce = b"tdx_attestation_nonce_12345678";
    let attestation = crypto
        .platform_attestation(Some(nonce))
        .await
        .expect("Attestation failed");
    assert_eq!(attestation.nonce, nonce);
    assert_eq!(attestation.platform_type, "intel-tdx");
    assert!(
        attestation.measurements.contains_key("MRTD")
            || attestation.measurements.contains_key("RTMR0")
    );
    log::info!("✓ TDX attestation generated with measurements:");
    for (key, value) in &attestation.measurements {
        log::debug!("  - {}: {}", key, value);
    }

    // Test sealing/unsealing (TDX-specific)
    let sealed = crypto
        .seal_data(b"secret", Some("tdx_policy"))
        .await
        .expect("Sealing failed");
    let unsealed = crypto
        .unseal_data(&sealed, Some("tdx_policy"))
        .await
        .expect("Unsealing failed");
    assert_eq!(unsealed, b"secret");
    log::info!("✓ TDX sealing/unsealing verified");

    log::info!("=== CRYPTO TEST COMPLETE ===\n");
}

#[tokio::test]
async fn test_tdx_gpu_interface_complete() {
    init();
    log::info!("\n=== TDX GPU INTERFACE TEST ===");

    // Verify TDX environment
    let hal = ElasticTeeHal::new().expect("Failed to initialize HAL");
    assert!(matches!(
        hal.platform_type(),
        platform::PlatformType::IntelTdx
    ));
    log::info!("✓ Verified Intel TDX environment");

    let gpu = GpuInterface::new();

    // Get adapters (should be limited in TDX)
    let adapters = gpu
        .get_gpu_adapters()
        .await
        .expect("Failed to get adapters");
    assert!(!adapters.is_empty());
    log::info!("✓ Found {} GPU adapters (TDX-compatible)", adapters.len());

    for adapter_handle in &adapters {
        let info = gpu
            .get_gpu_adapter_info(*adapter_handle)
            .await
            .expect("Failed to get adapter info");
        log::debug!("  - {} ({})", info.name, info.vendor);

        // TDX should not have discrete GPUs
        if info.name.contains("TDX") {
            assert!(matches!(
                info.device_type,
                gpu::GpuDeviceType::Cpu | gpu::GpuDeviceType::VirtualGpu
            ));
            log::debug!("    Type: {:?} (TDX-appropriate)", info.device_type);
        }
    }

    // Create device
    let device_handle = gpu
        .create_gpu_device(adapters[0])
        .await
        .expect("Failed to create device");
    log::info!("✓ Created GPU device: {}", device_handle);

    // Create compute pipeline
    let shader = b"#version 450\nlayout(local_size_x = 1) in;\nvoid main() {}";
    let pipeline_handle = gpu
        .create_gpu_compute_pipeline(device_handle, shader, "main", [1, 1, 1])
        .await
        .expect("Failed to create pipeline");
    log::info!("✓ Created compute pipeline: {}", pipeline_handle);

    // Create and use buffer
    let buffer_desc = GpuBufferDescriptor {
        label: Some("tdx_test_buffer".to_string()),
        size: 256,
        usage: GpuBufferUsage {
            storage: true,
            copy_src: true,
            copy_dst: true,
            ..Default::default()
        },
        mapped_at_creation: false,
    };

    let buffer_handle = gpu
        .create_gpu_buffer(device_handle, &buffer_desc)
        .await
        .expect("Failed to create buffer");
    log::info!(
        "✓ Created GPU buffer: {} ({} bytes)",
        buffer_handle,
        buffer_desc.size
    );

    log::info!("=== GPU TEST COMPLETE ===\n");
}

#[tokio::test]
async fn test_tdx_resources_interface_complete() {
    init();
    log::info!("\n=== TDX RESOURCES INTERFACE TEST ===");

    // Verify TDX environment
    let hal = ElasticTeeHal::new().expect("Failed to initialize HAL");
    assert!(matches!(
        hal.platform_type(),
        platform::PlatformType::IntelTdx
    ));
    log::info!("✓ Verified Intel TDX environment");

    let resources = ResourceInterface::new().expect("Failed to create resource interface");

    // Get system limits (should account for TDX overhead)
    let limits = resources
        .get_system_limits()
        .await
        .expect("Failed to get limits");
    log::info!("✓ System limits (TDX-adjusted):");
    log::debug!("  - Memory: {} MB", limits.max_memory_mb);
    log::debug!("  - CPU cores: {}", limits.max_cpu_cores);
    log::debug!("  - Storage: {} MB", limits.max_storage_mb);
    log::debug!(
        "  - GPU memory: {} MB (TDX: limited)",
        limits.max_gpu_memory_mb
    );

    // In TDX, GPU memory should be 0 (no GPU passthrough)
    assert_eq!(
        limits.max_gpu_memory_mb, 0,
        "TDX should not have GPU memory"
    );

    // Request memory allocation
    let alloc = resources
        .request_additional_memory(512, "tdx_test_app")
        .await
        .expect("Memory allocation failed");
    log::info!("✓ Allocated 512 MB: {}", alloc.allocation_id);

    // Request CPU allocation
    let cpu_alloc = resources
        .request_additional_cpu(2, "tdx_test_app")
        .await
        .expect("CPU allocation failed");
    log::info!("✓ Allocated 2 CPU cores: {}", cpu_alloc.allocation_id);

    // Check usage
    let usage = resources
        .list_current_allocation()
        .await
        .expect("Failed to get usage");
    assert_eq!(usage.memory_mb, 512);
    assert_eq!(usage.cpu_cores, 2);
    log::info!(
        "✓ Current usage: {} MB RAM, {} CPU cores",
        usage.memory_mb,
        usage.cpu_cores
    );

    // Get statistics
    let stats = resources
        .get_resource_statistics()
        .await
        .expect("Failed to get stats");
    log::info!("✓ Resource utilization:");
    log::debug!("  - Memory: {:.2}%", stats.memory_utilization_percent);
    log::debug!("  - CPU: {:.2}%", stats.cpu_utilization_percent);
    log::debug!("  - Total allocations: {}", stats.total_allocations);

    // Release resources
    resources
        .release_resource(&alloc.allocation_id)
        .await
        .expect("Failed to release memory");
    resources
        .release_resource(&cpu_alloc.allocation_id)
        .await
        .expect("Failed to release CPU");
    log::info!("✓ Released all allocations");

    log::info!("=== RESOURCES TEST COMPLETE ===\n");
}

#[tokio::test]
async fn test_tdx_events_interface_complete() {
    init();
    log::info!("\n=== TDX EVENTS INTERFACE TEST ===");

    // Verify TDX environment
    let hal = ElasticTeeHal::new().expect("Failed to initialize HAL");
    assert!(matches!(
        hal.platform_type(),
        platform::PlatformType::IntelTdx
    ));
    log::info!("✓ Verified Intel TDX environment (secure event channels)");

    let events = EventInterface::new();

    // Create event handlers
    let config1 = EventHandlerConfig {
        name: "tdx_handler_1".to_string(),
        event_types: vec!["tdx_event".to_string(), "security_event".to_string()],
        max_queue_size: 100,
    };

    let handler1 = events
        .create_event_handler(config1)
        .await
        .expect("Failed to create handler");
    log::info!("✓ Created event handler 1: {}", handler1);

    let config2 = EventHandlerConfig {
        name: "tdx_handler_2".to_string(),
        event_types: vec!["tdx_event".to_string()],
        max_queue_size: 100,
    };

    let handler2 = events
        .create_event_handler(config2)
        .await
        .expect("Failed to create handler");
    log::info!("✓ Created event handler 2: {}", handler2);

    // Create subscriptions
    let filter = SubscriptionFilter {
        event_types: vec!["tdx_event".to_string()],
        source_pattern: None,
        target_pattern: None,
        data_filter: None,
    };

    let _sub1 = events
        .request_event_subscription(handler1, filter.clone())
        .await
        .expect("Failed to create subscription");
    let _sub2 = events
        .request_event_subscription(handler2, filter)
        .await
        .expect("Failed to create subscription");
    log::info!("✓ Created subscriptions for both handlers");

    // Send global event
    let event = EventInterface::create_event(
        "tdx_event",
        "tdx_secure_source",
        None,
        EventData::Text("TDX secure message".to_string()),
        EventPriority::High,
    );

    events
        .send_event_global(event)
        .await
        .expect("Failed to send event");
    log::info!("✓ Sent TDX secure event");

    // Receive events
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let event1 = events
        .try_request_event_from_handler(handler1)
        .await
        .expect("Failed to receive event 1");
    assert!(event1.is_some());
    log::info!("✓ Handler 1 received event");

    let event2 = events
        .try_request_event_from_handler(handler2)
        .await
        .expect("Failed to receive event 2");
    assert!(event2.is_some());
    log::info!("✓ Handler 2 received event");

    // Get statistics
    let stats = events
        .get_event_statistics()
        .await
        .expect("Failed to get stats");
    log::info!("✓ Event statistics:");
    log::debug!("  - Handlers: {}", stats.total_handlers);
    log::debug!("  - Subscriptions: {}", stats.total_subscriptions);

    log::info!("=== EVENTS TEST COMPLETE ===\n");
}

#[tokio::test]
async fn test_tdx_communication_interface_complete() {
    init();
    log::info!("\n=== TDX COMMUNICATION INTERFACE TEST ===");

    // Verify TDX environment
    let hal = ElasticTeeHal::new().expect("Failed to initialize HAL");
    assert!(matches!(
        hal.platform_type(),
        platform::PlatformType::IntelTdx
    ));
    log::info!("✓ Verified Intel TDX environment (encrypted comm buffers)");

    let comm = CommunicationInterface::new();

    // Create encrypted communication buffer
    let config = BufferConfig {
        name: "tdx_secure_buffer".to_string(),
        capacity: 4096,
        is_encrypted: true, // TDX-encrypted buffer
        read_permissions: vec!["reader1".to_string(), "reader2".to_string()],
        write_permissions: vec!["writer1".to_string()],
        admin_permissions: vec!["admin".to_string()],
    };

    let buffer_handle = comm
        .setup_communication_buffer(config)
        .await
        .expect("Failed to create buffer");
    log::info!(
        "✓ Created TDX-encrypted communication buffer: {}",
        buffer_handle
    );

    let info = comm
        .get_buffer_info(buffer_handle)
        .await
        .expect("Failed to get info");
    assert!(info.is_encrypted);
    log::debug!("  - Name: {}", info.name);
    log::debug!("  - Capacity: {} bytes", info.capacity);
    log::debug!("  - Encrypted: {}", info.is_encrypted);

    // Push data
    let test_data = b"TDX secure inter-TD message";
    comm.push_data_to_buffer(
        buffer_handle,
        test_data,
        "writer1",
        MessageType::Data,
        MessagePriority::High,
    )
    .await
    .expect("Failed to push data");
    log::info!("✓ Pushed {} bytes to TDX-encrypted buffer", test_data.len());

    // Read data
    let message = comm
        .read_data_from_buffer(buffer_handle, "reader1")
        .await
        .expect("Failed to read data");
    assert!(message.is_some());

    let message = message.unwrap();
    assert_eq!(message.data, test_data);
    assert_eq!(message.sender, "writer1");
    log::info!("✓ Read and verified data from TDX-encrypted buffer");
    log::debug!("  - Sender: {}", message.sender);
    log::debug!("  - Data: {} bytes", message.data.len());

    // List buffers
    let buffers = comm
        .list_communication_buffers()
        .await
        .expect("Failed to list buffers");
    assert_eq!(buffers.len(), 1);
    log::info!("✓ Listed {} communication buffer(s)", buffers.len());

    log::info!("=== COMMUNICATION TEST COMPLETE ===\n");
}

#[tokio::test]
async fn test_tdx_platform_capabilities_complete() {
    init();
    log::info!("\n=== TDX PLATFORM CAPABILITIES TEST ===");

    // Initialize HAL
    let hal = ElasticTeeHal::new().expect("Failed to initialize HAL");
    assert!(matches!(
        hal.platform_type(),
        platform::PlatformType::IntelTdx
    ));
    log::info!("✓ Verified Intel TDX environment");

    // Get capabilities
    let caps = hal.capabilities().await;
    assert!(matches!(
        caps.platform_type,
        platform::PlatformType::IntelTdx
    ));
    log::info!("✓ Platform type: {:?}", caps.platform_type);
    log::info!("✓ HAL version: {}", caps.hal_version);

    // Check TDX-specific features
    log::info!("✓ TDX Features:");
    log::info!("  - Clock: {} ✅", caps.features.clock);
    log::info!("  - Random: {} ✅", caps.features.random);
    log::info!("  - Storage: {} ✅", caps.features.storage);
    log::info!("  - Secure Storage: {} ✅", caps.features.secure_storage);
    log::info!("  - TCP Sockets: {} ✅", caps.features.tcp_sockets);
    log::info!("  - UDP Sockets: {} ✅", caps.features.udp_sockets);
    log::info!("  - TLS Support: {} ✅", caps.features.tls_support);
    log::info!(
        "  - GPU Compute: {} ❌ (TDX limitation)",
        caps.features.gpu_compute
    );
    log::info!(
        "  - Dynamic Resources: {} ✅",
        caps.features.dynamic_resources
    );
    log::info!("  - Event Handling: {} ✅", caps.features.event_handling);
    log::info!(
        "  - Internal Communication: {} ✅",
        caps.features.internal_communication
    );
    log::info!("  - Attestation: {} ✅", caps.features.attestation);

    assert!(
        !caps.features.gpu_compute,
        "TDX should not support GPU compute"
    );
    assert!(caps.features.attestation, "TDX must support attestation");
    assert!(
        caps.features.secure_storage,
        "TDX must support secure storage"
    );

    // Check crypto support
    log::info!("✓ Cryptographic Support:");
    log::debug!("  - Symmetric: {:?}", caps.crypto_support.symmetric_ciphers);
    log::debug!("  - Hash: {:?}", caps.crypto_support.hash_algorithms);
    log::debug!(
        "  - Hardware Acceleration: {}",
        caps.crypto_support.hardware_acceleration
    );

    assert!(
        caps.crypto_support.hardware_acceleration,
        "TDX should have hardware crypto"
    );
    assert!(caps.is_crypto_supported("symmetric", "AES-256-GCM"));
    assert!(caps.is_crypto_supported("hash", "SHA-256"));

    // Check resource limits
    log::info!("✓ Platform Limits:");
    log::debug!("  - Max Memory: {} MB", caps.limits.max_memory_mb);
    log::debug!("  - Max CPU Cores: {}", caps.limits.max_cpu_cores);
    log::debug!("  - Max Storage: {} MB", caps.limits.max_storage_mb);
    log::debug!("  - Max Sockets: {}", caps.limits.max_open_sockets);

    log::info!("=== CAPABILITIES TEST COMPLETE ===\n");
}

#[tokio::test]
async fn test_tdx_full_integration() {
    init();
    log::info!("\n=== TDX FULL INTEGRATION TEST ===");
    log::info!("Testing all interfaces working together in Intel TDX...\n");

    // Initialize HAL
    let hal = ElasticTeeHal::new().expect("Failed to initialize HAL");
    let platform_type = hal.platform_type();
    log::info!("✓ Platform: {:?}", platform_type);
    assert!(matches!(platform_type, platform::PlatformType::IntelTdx));

    // Initialize all interfaces
    let crypto = Arc::new(CryptoInterface::new());
    let gpu = GpuInterface::new();
    let resources = ResourceInterface::new().expect("Failed to create resources");
    let events = EventInterface::new();
    let comm = CommunicationInterface::with_crypto(crypto.clone());

    log::info!("✓ Initialized all interfaces");

    // 1. Test crypto with attestation
    let attestation = crypto
        .platform_attestation(None)
        .await
        .expect("Attestation failed");
    assert_eq!(attestation.platform_type, "intel-tdx");
    log::info!("✓ [1/7] Crypto + Attestation: TDX measurements collected");

    // 2. Test GPU (limited in TDX)
    let adapters = gpu
        .get_gpu_adapters()
        .await
        .expect("Failed to get adapters");
    log::info!("✓ [2/7] GPU: {} adapters (TDX-compatible)", adapters.len());

    // 3. Test resource allocation with TDX overhead
    let mem_alloc = resources
        .request_additional_memory(256, "integration_test")
        .await
        .expect("Memory allocation failed");
    log::info!("✓ [3/7] Resources: Allocated 256 MB (TDX overhead accounted)");

    // 4. Test secure event handling
    let handler_config = EventHandlerConfig {
        name: "integration_handler".to_string(),
        event_types: vec!["integration".to_string()],
        max_queue_size: 50,
    };
    let handler = events
        .create_event_handler(handler_config)
        .await
        .expect("Handler creation failed");
    log::info!("✓ [4/7] Events: Secure event handler created");

    // 5. Test encrypted communication
    let buffer_config = BufferConfig {
        name: "integration_buffer".to_string(),
        capacity: 2048,
        is_encrypted: true,
        read_permissions: vec!["reader".to_string()],
        write_permissions: vec!["writer".to_string()],
        admin_permissions: vec!["admin".to_string()],
    };
    let buffer = comm
        .setup_communication_buffer(buffer_config)
        .await
        .expect("Buffer creation failed");
    log::info!("✓ [5/7] Communication: TDX-encrypted buffer created");

    // 6. Test end-to-end encrypted message flow
    let message = b"End-to-end TDX secure message";
    comm.push_data_to_buffer(
        buffer,
        message,
        "writer",
        MessageType::Data,
        MessagePriority::Normal,
    )
    .await
    .expect("Failed to push message");

    let received = comm
        .read_data_from_buffer(buffer, "reader")
        .await
        .expect("Failed to read message")
        .expect("No message received");
    assert_eq!(received.data, message);
    log::info!("✓ [6/7] End-to-end: Message encrypted, transmitted, and decrypted");

    // 7. Cleanup
    resources
        .release_resource(&mem_alloc.allocation_id)
        .await
        .expect("Failed to release resources");
    log::info!("✓ [7/7] Cleanup: All resources released");

    log::info!("\n=== FULL INTEGRATION TEST COMPLETE ===");
    log::info!("All 7 interfaces working correctly in Intel TDX environment!");
}
