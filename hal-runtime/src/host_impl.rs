//! Host implementation of HAL WIT interfaces
//!
//! This module bridges ALL 11 WIT interface calls from WASM guests to the
//! native elastic-tee-hal implementation. Each section corresponds to one
//! WIT interface defined in wit/world.wit.

use anyhow::Result;
use elastic_tee_hal::{
    clock::ClockInterface as HalClock,
    communication::CommunicationInterface as HalComm,
    communication::{BufferConfig, MessagePriority as HalMsgPriority, MessageType as HalMsgType},
    crypto::CryptoInterface as HalCrypto,
    events::EventInterface as HalEvents,
    events::{EventData, EventHandlerConfig, SubscriptionFilter},
    gpu::GpuInterface as HalGpu,
    random::RandomInterface as HalRandom,
    resources::ResourceInterface as HalResources,
    sockets::SocketInterface as HalSockets,
    storage::StorageInterface as HalStorage,
    ElasticTeeHal, PlatformCapabilities,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Run a HAL future to completion from a synchronous host function.
///
/// Host calls execute inside a Tokio task. Tokio's cooperative budget makes
/// `tokio::sync` primitives return `Pending` once a task has used up its
/// budget, expecting the task to yield; a nested `block_on` never yields, so
/// after ~128 HAL calls in one guest invocation it would spin forever.
/// `unconstrained` opts the nested future out of that budget.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    futures::executor::block_on(tokio::task::unconstrained(f))
}

/// Host-side HAL implementation that WASM components call into.
/// Covers all 11 WIT interfaces: platform, capabilities, crypto, storage,
/// sockets, gpu, resources, events, communication, clock, random.
pub struct HalHost {
    // Core
    platform: ElasticTeeHal,
    capabilities: PlatformCapabilities,
    crypto: HalCrypto,
    storage: Option<HalStorage>,
    clock: HalClock,
    random: HalRandom,
    // Network
    sockets: HalSockets,
    // Compute
    gpu: HalGpu,
    // System
    resources: Option<HalResources>,
    events: HalEvents,
    communication: HalComm,
    // Internal counter for generating handles
    next_handle: AtomicU64,
    // Guest socket handle -> HalSockets handle of the bound listener or
    // connected stream behind it
    socket_backing: Mutex<HashMap<u64, u64>>,
}

impl HalHost {
    pub fn new() -> Result<Self> {
        // Auto-detect the TEE platform (TDX on GCP, SEV-SNP on AWS, etc.)
        Self::from_platform(ElasticTeeHal::new()?)
    }

    /// Create a host for an explicit platform type, skipping detection.
    /// Intended for development and benchmarking on non-TEE machines.
    pub fn with_platform(platform_type: elastic_tee_hal::platform::PlatformType) -> Result<Self> {
        Self::from_platform(ElasticTeeHal::with_platform(platform_type)?)
    }

    fn from_platform(platform: ElasticTeeHal) -> Result<Self> {
        let capabilities = block_on(platform.capabilities());

        let storage =
            block_on(async { HalStorage::new("/tmp/hal-storage").await.ok() });

        let resources = HalResources::new().ok();

        Ok(Self {
            platform,
            capabilities,
            crypto: HalCrypto::new(),
            storage,
            clock: HalClock::new(),
            random: HalRandom::new(),
            sockets: HalSockets::new(),
            gpu: HalGpu::new(),
            resources,
            events: HalEvents::new(),
            communication: HalComm::new(),
            next_handle: AtomicU64::new(1),
            socket_backing: Mutex::new(HashMap::new()),
        })
    }

    fn next_id(&self) -> u64 {
        self.next_handle.fetch_add(1, Ordering::SeqCst)
    }

    /// Attach a listener or stream to a guest socket handle, closing whatever
    /// was attached before so repeated bind/connect calls do not leak.
    fn attach_socket(&self, socket: u64, backing: u64) {
        let old = self.socket_backing.lock().unwrap().insert(socket, backing);
        if let Some(old) = old {
            let _ = block_on(self.sockets.close_socket(old));
        }
    }

    fn backing_socket(&self, socket: u64) -> Result<u64, String> {
        self.socket_backing
            .lock()
            .unwrap()
            .get(&socket)
            .copied()
            .ok_or_else(|| format!("Socket {socket} is not bound or connected"))
    }

    // ========================================================================
    // 1. PLATFORM INTERFACE  (attestation, platform-info)
    // ========================================================================

    pub fn attestation(&mut self, report_data: Vec<u8>) -> Result<Vec<u8>, String> {
        block_on(self.platform.attest(&report_data)).map_err(|e| e.to_string())
    }

    pub fn platform_info(&self) -> PlatformInfo {
        PlatformInfo {
            platform_type: format!("{:?}", self.platform.platform_type()),
            version: elastic_tee_hal::HAL_VERSION.to_string(),
            attestation_support: true,
        }
    }

    // ========================================================================
    // 2. CAPABILITIES INTERFACE  (list-capabilities, has-capability)
    // ========================================================================

    pub fn capabilities_list(&self) -> Vec<CapabilityInfo> {
        vec![
            CapabilityInfo {
                feature_name: "clock".into(),
                supported: self.capabilities.features.clock,
                version: "1.0".into(),
            },
            CapabilityInfo {
                feature_name: "random".into(),
                supported: self.capabilities.features.random,
                version: "1.0".into(),
            },
            CapabilityInfo {
                feature_name: "storage".into(),
                supported: self.capabilities.features.storage,
                version: "1.0".into(),
            },
            CapabilityInfo {
                feature_name: "secure-storage".into(),
                supported: self.capabilities.features.secure_storage,
                version: "1.0".into(),
            },
            CapabilityInfo {
                feature_name: "tcp-sockets".into(),
                supported: self.capabilities.features.tcp_sockets,
                version: "1.0".into(),
            },
            CapabilityInfo {
                feature_name: "udp-sockets".into(),
                supported: self.capabilities.features.udp_sockets,
                version: "1.0".into(),
            },
            CapabilityInfo {
                feature_name: "tls".into(),
                supported: self.capabilities.features.tls_support,
                version: "1.0".into(),
            },
            CapabilityInfo {
                feature_name: "gpu-compute".into(),
                supported: self.capabilities.features.gpu_compute,
                version: "1.0".into(),
            },
            CapabilityInfo {
                feature_name: "attestation".into(),
                supported: self.capabilities.features.attestation,
                version: "1.0".into(),
            },
            CapabilityInfo {
                feature_name: "events".into(),
                supported: self.capabilities.features.event_handling,
                version: "1.0".into(),
            },
            CapabilityInfo {
                feature_name: "communication".into(),
                supported: self.capabilities.features.internal_communication,
                version: "1.0".into(),
            },
        ]
    }

    pub fn capabilities_has(&self, feature_name: &str) -> bool {
        self.capabilities.is_feature_supported(feature_name)
    }

    // ========================================================================
    // 3. CRYPTO INTERFACE  (hash, encrypt, decrypt, generate-keypair,
    //                       sign, verify, create-context, destroy-context)
    // ========================================================================

    pub fn crypto_hash(&self, data: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>, String> {
        let algo = match algorithm {
            HashAlgorithm::Sha256 => "SHA-256",
            HashAlgorithm::Sha512 => "SHA-512",
            HashAlgorithm::Blake3 => "SHA-384", // map to available impl
        };
        block_on(self.crypto.hash_data(algo, data)).map_err(|e| e.to_string())
    }

    pub fn crypto_encrypt(
        &self,
        data: &[u8],
        key: &[u8],
        algorithm: CipherAlgorithm,
    ) -> Result<Vec<u8>, String> {
        let algo = match algorithm {
            CipherAlgorithm::Aes256Gcm => "AES-256-GCM",
            CipherAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        };
        block_on(self.crypto.symmetric_encrypt(algo, key, data, None))
            .map_err(|e| e.to_string())
    }

    pub fn crypto_decrypt(
        &self,
        data: &[u8],
        key: &[u8],
        algorithm: CipherAlgorithm,
    ) -> Result<Vec<u8>, String> {
        let algo = match algorithm {
            CipherAlgorithm::Aes256Gcm => "AES-256-GCM",
            CipherAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        };
        block_on(self.crypto.symmetric_decrypt(algo, key, data, None))
            .map_err(|e| e.to_string())
    }

    pub fn crypto_generate_keypair(&self) -> Result<KeyPair, String> {
        // Generate a 32-byte seed for Ed25519
        let seed = self
            .random
            .generate_key_material(32)
            .map_err(|e| e.to_string())?;
        // Load a signing context to extract the public key
        let ctx =
            block_on(self.crypto.load_key_context("Ed25519", &seed, "signing"))
                .map_err(|e| e.to_string())?;
        // Sign empty data to confirm context works; public key is derived from seed
        // For Ed25519, public key is the last 32 bytes of the 64-byte expanded key
        // We return the seed as private_key so the caller can reconstruct
        let _ = block_on(self.crypto.sign_data(ctx, b"test"))
            .map_err(|e| e.to_string())?;
        Ok(KeyPair {
            public_key: seed[..32].to_vec(), // placeholder; real key derivation in crypto module
            private_key: seed,
        })
    }

    pub fn crypto_sign(&self, data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String> {
        let ctx = block_on(self.crypto.load_key_context(
            "Ed25519",
            private_key,
            "signing",
        ))
        .map_err(|e| e.to_string())?;
        let sig = block_on(self.crypto.sign_data(ctx, data))
            .map_err(|e| e.to_string())?;
        Ok(sig.signature)
    }

    pub fn crypto_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, String> {
        block_on(
            self.crypto
                .verify_signature("Ed25519", public_key, data, signature),
        )
        .map_err(|e| e.to_string())
    }

    pub fn crypto_create_context(&self) -> Result<u64, String> {
        Ok(self.next_id())
    }

    pub fn crypto_destroy_context(&self, _handle: u64) -> Result<(), String> {
        Ok(())
    }

    // ========================================================================
    // 4. STORAGE INTERFACE  (create-container, open-container,
    //    delete-container, store-object, retrieve-object, delete-object,
    //    list-objects, get-metadata)
    // ========================================================================

    fn storage(&self) -> Result<&HalStorage, String> {
        self.storage
            .as_ref()
            .ok_or_else(|| "Storage not initialized".to_string())
    }

    pub fn storage_create_container(&self, name: &str) -> Result<u64, String> {
        block_on(self.storage()?.open_container(name, false))
            .map_err(|e| e.to_string())
    }

    pub fn storage_open_container(&self, name: &str) -> Result<u64, String> {
        block_on(self.storage()?.open_container(name, false))
            .map_err(|e| e.to_string())
    }

    pub fn storage_delete_container(&self, handle: u64) -> Result<(), String> {
        block_on(self.storage()?.close_container(handle))
            .map_err(|e| e.to_string())
    }

    pub fn storage_store_object(
        &self,
        container: u64,
        key: &str,
        data: &[u8],
    ) -> Result<u64, String> {
        block_on(self.storage()?.write_object(container, key, data))
            .map_err(|e| e.to_string())?;
        Ok(self.next_id()) // return object handle
    }

    pub fn storage_retrieve_object(&self, container: u64, key: &str) -> Result<Vec<u8>, String> {
        block_on(self.storage()?.read_object(container, key))
            .map_err(|e| e.to_string())
    }

    pub fn storage_delete_object(&self, container: u64, key: &str) -> Result<(), String> {
        block_on(self.storage()?.delete_object(container, key))
            .map_err(|e| e.to_string())
    }

    pub fn storage_list_objects(&self, container: u64) -> Result<Vec<String>, String> {
        block_on(self.storage()?.list_objects(container))
            .map_err(|e| e.to_string())
    }

    pub fn storage_get_metadata(
        &self,
        container: u64,
        key: &str,
    ) -> Result<ObjectMetadata, String> {
        // Read object to get size; metadata file is internal detail
        let data = self.storage_retrieve_object(container, key)?;
        Ok(ObjectMetadata {
            size: data.len() as u64,
            created_at: 0, // not tracked in current impl
            content_type: "application/octet-stream".to_string(),
        })
    }

    // ========================================================================
    // 5. SOCKETS INTERFACE  (create-socket, bind, listen, connect,
    //    accept, send, receive, close)
    // ========================================================================

    pub fn sockets_create(&self, protocol: Protocol) -> Result<u64, String> {
        match protocol {
            Protocol::Tcp => {
                // Return a handle; actual binding happens in bind()
                Ok(self.next_id())
            }
            Protocol::Udp => Ok(self.next_id()),
            Protocol::Tls => Ok(self.next_id()),
            Protocol::Dtls => Ok(self.next_id()),
        }
    }

    pub fn sockets_bind(&self, socket: u64, addr: &Address) -> Result<(), String> {
        let bind_addr = format!("{}:{}", addr.ip, addr.port);
        // For TCP, create listener; for UDP, bind socket
        let listener = block_on(self.sockets.create_tcp_socket(&bind_addr))
            .map_err(|e| e.to_string())?;
        self.attach_socket(socket, listener);
        Ok(())
    }

    pub fn sockets_listen(&self, _socket: u64, _backlog: u32) -> Result<(), String> {
        // TCP listener is created in bind; listen is implicit
        Ok(())
    }

    pub fn sockets_connect(&self, socket: u64, addr: &Address) -> Result<(), String> {
        let server_addr = format!("{}:{}", addr.ip, addr.port);
        let stream = block_on(self.sockets.tcp_connect(&server_addr))
            .map_err(|e| e.to_string())?;
        self.attach_socket(socket, stream);
        Ok(())
    }

    pub fn sockets_accept(&self, listener: u64) -> Result<u64, String> {
        let listener = self.backing_socket(listener)?;
        let stream = block_on(self.sockets.tcp_accept(listener)).map_err(|e| e.to_string())?;
        let socket = self.next_id();
        self.attach_socket(socket, stream);
        Ok(socket)
    }

    pub fn sockets_send(&self, socket: u64, data: &[u8]) -> Result<u32, String> {
        let socket = self.backing_socket(socket)?;
        block_on(self.sockets.socket_write(socket, data))
            .map(|r| r.bytes_transferred as u32)
            .map_err(|e| e.to_string())
    }

    pub fn sockets_receive(&self, socket: u64, max_len: u32) -> Result<Vec<u8>, String> {
        let socket = self.backing_socket(socket)?;
        let mut buf = vec![0u8; max_len as usize];
        let result = block_on(self.sockets.socket_read(socket, &mut buf))
            .map_err(|e| e.to_string())?;
        buf.truncate(result.bytes_transferred);
        Ok(buf)
    }

    pub fn sockets_close(&self, socket: u64) -> Result<(), String> {
        match self.socket_backing.lock().unwrap().remove(&socket) {
            Some(backing) => block_on(self.sockets.close_socket(backing)).map_err(|e| e.to_string()),
            None => Ok(()),
        }
    }

    // ========================================================================
    // 6. GPU INTERFACE  (list-adapters, get-adapter-info, create-device,
    //    create-buffer, write-buffer, read-buffer, create-compute-pipeline,
    //    dispatch)
    // ========================================================================

    pub fn gpu_list_adapters(&self) -> Result<Vec<u64>, String> {
        block_on(self.gpu.get_gpu_adapters()).map_err(|e| e.to_string())
    }

    pub fn gpu_get_adapter_info(&self, handle: u64) -> Result<AdapterInfo, String> {
        let info = block_on(self.gpu.get_gpu_adapter_info(handle))
            .map_err(|e| e.to_string())?;
        Ok(AdapterInfo {
            name: info.name,
            vendor: info.vendor,
            device_type: format!("{:?}", info.device_type),
        })
    }

    pub fn gpu_create_device(&self, adapter: u64) -> Result<u64, String> {
        block_on(self.gpu.create_gpu_device(adapter)).map_err(|e| e.to_string())
    }

    pub fn gpu_create_buffer(
        &self,
        device: u64,
        descriptor: &BufferDescriptor,
    ) -> Result<u64, String> {
        let usage = elastic_tee_hal::gpu::GpuBufferUsage {
            storage: matches!(descriptor.usage, BufferUsage::Storage),
            uniform: matches!(descriptor.usage, BufferUsage::Uniform),
            vertex: matches!(descriptor.usage, BufferUsage::Vertex),
            index: matches!(descriptor.usage, BufferUsage::Index),
            map_read: false,
            map_write: false,
            copy_src: true,
            copy_dst: true,
            indirect: false,
            query_resolve: false,
        };
        let desc = elastic_tee_hal::gpu::GpuBufferDescriptor {
            label: None,
            size: descriptor.size,
            usage,
            mapped_at_creation: false,
        };
        block_on(self.gpu.create_gpu_buffer(device, &desc))
            .map_err(|e| e.to_string())
    }

    pub fn gpu_write_buffer(&self, buffer: u64, offset: u64, data: &[u8]) -> Result<(), String> {
        block_on(self.gpu.write_gpu_buffer(buffer, offset, data))
            .map_err(|e| e.to_string())
    }

    pub fn gpu_read_buffer(&self, buffer: u64, offset: u64, size: u64) -> Result<Vec<u8>, String> {
        block_on(self.gpu.read_gpu_buffer(buffer, offset, size))
            .map_err(|e| e.to_string())
    }

    pub fn gpu_create_compute_pipeline(
        &self,
        device: u64,
        shader_code: &[u8],
    ) -> Result<u64, String> {
        block_on(self.gpu.create_gpu_compute_pipeline(
            device,
            shader_code,
            "main",
            [64, 1, 1],
        ))
        .map_err(|e| e.to_string())
    }

    pub fn gpu_dispatch(&self, pipeline: u64, x: u32, y: u32, z: u32) -> Result<(), String> {
        block_on(self.gpu.dispatch_compute(pipeline, x, y, z))
            .map_err(|e| e.to_string())
    }

    // ========================================================================
    // 7. RESOURCES INTERFACE  (allocate, deallocate, query-available)
    // ========================================================================

    fn resources(&self) -> Result<&HalResources, String> {
        self.resources
            .as_ref()
            .ok_or_else(|| "Resources not initialized".to_string())
    }

    pub fn resources_allocate(
        &self,
        request: &AllocationRequest,
    ) -> Result<AllocationResponse, String> {
        let res_type = match request.resource_type {
            ResourceType::Memory => elastic_tee_hal::resources::ResourceType::Memory,
            ResourceType::Cpu => elastic_tee_hal::resources::ResourceType::CpuCores,
            ResourceType::Storage => elastic_tee_hal::resources::ResourceType::Storage,
            ResourceType::Network => elastic_tee_hal::resources::ResourceType::NetworkBandwidth,
        };
        let hal_request = elastic_tee_hal::resources::ResourceRequest {
            resource_type: res_type,
            amount: request.amount,
            requester: "wasm-guest".to_string(),
            priority: match request.priority {
                0..=25 => elastic_tee_hal::resources::RequestPriority::Low,
                26..=50 => elastic_tee_hal::resources::RequestPriority::Normal,
                51..=75 => elastic_tee_hal::resources::RequestPriority::High,
                _ => elastic_tee_hal::resources::RequestPriority::Critical,
            },
            timeout_seconds: None,
        };
        let result = block_on(self.resources()?.allocate_resource(hal_request))
            .map_err(|e| e.to_string())?;
        Ok(AllocationResponse {
            allocation_id: result.allocation_id,
            granted_amount: result.granted_amount,
        })
    }

    pub fn resources_deallocate(&self, id: &str) -> Result<(), String> {
        block_on(self.resources()?.release_resource(id))
            .map_err(|e| e.to_string())
    }

    pub fn resources_query_available(&self, resource_type: ResourceType) -> Result<u64, String> {
        let limits = block_on(self.resources()?.get_system_limits())
            .map_err(|e| e.to_string())?;
        let usage = block_on(self.resources()?.list_current_allocation())
            .map_err(|e| e.to_string())?;
        Ok(match resource_type {
            ResourceType::Memory => limits.max_memory_mb.saturating_sub(usage.memory_mb),
            ResourceType::Cpu => {
                (limits.max_cpu_cores as u64).saturating_sub(usage.cpu_cores as u64)
            }
            ResourceType::Storage => limits.max_storage_mb.saturating_sub(usage.storage_mb),
            ResourceType::Network => limits
                .max_network_bandwidth_mbps
                .saturating_sub(usage.network_bandwidth_mbps),
        })
    }

    // ========================================================================
    // 8. EVENTS INTERFACE  (subscribe, unsubscribe, poll-events)
    // ========================================================================

    pub fn events_subscribe(&self, event_type: EventType) -> Result<u64, String> {
        let type_str = match event_type {
            EventType::Platform => "platform",
            EventType::Crypto => "crypto",
            EventType::Storage => "storage",
            EventType::Network => "network",
            EventType::Gpu => "gpu",
        };
        let config = EventHandlerConfig {
            name: format!("wasm_sub_{}", type_str),
            event_types: vec![type_str.to_string()],
            max_queue_size: 1000,
        };
        let handler = block_on(self.events.create_event_handler(config))
            .map_err(|e| e.to_string())?;
        let filter = SubscriptionFilter {
            event_types: vec![type_str.to_string()],
            source_pattern: None,
            target_pattern: None,
            data_filter: None,
        };
        block_on(self.events.request_event_subscription(handler, filter))
            .map_err(|e| e.to_string())
    }

    pub fn events_unsubscribe(&self, handle: u64) -> Result<(), String> {
        block_on(self.events.remove_event_subscription(handle))
            .map_err(|e| e.to_string())
    }

    pub fn events_poll(&self, handle: u64) -> Result<Vec<EventDataWit>, String> {
        // Try to receive events without blocking
        match block_on(self.events.request_event_from_handler(handle, Some(0))) {
            Ok(event) => Ok(vec![EventDataWit {
                event_type: match event.event_type.as_str() {
                    "platform" => EventType::Platform,
                    "crypto" => EventType::Crypto,
                    "storage" => EventType::Storage,
                    "network" => EventType::Network,
                    "gpu" => EventType::Gpu,
                    _ => EventType::Platform,
                },
                timestamp: event.timestamp,
                payload: match event.data {
                    EventData::Binary(b) => b,
                    EventData::Text(t) => t.into_bytes(),
                    EventData::Json(v) => v.to_string().into_bytes(),
                    EventData::Empty => vec![],
                },
            }]),
            Err(_) => Ok(vec![]), // no events available
        }
    }

    // ========================================================================
    // 9. COMMUNICATION INTERFACE  (send-message, receive-message,
    //    list-workloads)
    // ========================================================================

    pub fn communication_send_message(
        &self,
        recipient: &str,
        data: &[u8],
        encrypt: bool,
    ) -> Result<u64, String> {
        // Ensure a buffer exists for this channel
        let buffer_name = format!("channel_{}", recipient);
        let buffer = block_on(self.communication.setup_communication_buffer(
            BufferConfig {
                name: buffer_name,
                capacity: 65536,
                is_encrypted: encrypt,
                read_permissions: vec![recipient.to_string()],
                write_permissions: vec!["wasm-guest".to_string()],
                admin_permissions: vec!["admin".to_string()],
            },
        ));
        let buffer_handle = match buffer {
            Ok(h) => h,
            Err(_) => {
                // Buffer may already exist; try to find it
                let buffers =
                    block_on(self.communication.list_communication_buffers())
                        .map_err(|e| e.to_string())?;
                buffers
                    .first()
                    .ok_or("No communication buffer available")?
                    .handle
            }
        };
        block_on(self.communication.push_data_to_buffer(
            buffer_handle,
            data,
            "wasm-guest",
            HalMsgType::Data,
            if encrypt {
                HalMsgPriority::High
            } else {
                HalMsgPriority::Normal
            },
        ))
        .map_err(|e| e.to_string())?;
        Ok(self.next_id())
    }

    pub fn communication_receive_message(&self) -> Result<Option<Message>, String> {
        let buffers = block_on(self.communication.list_communication_buffers())
            .map_err(|e| e.to_string())?;

        for buffer_info in buffers {
            if let Ok(Some(msg)) = block_on(
                self.communication
                    .read_data_from_buffer(buffer_info.handle, "wasm-guest"),
            ) {
                return Ok(Some(Message {
                    sender: msg.sender,
                    recipient: "wasm-guest".to_string(),
                    payload: msg.data,
                    encrypted: false, // decrypted by the buffer layer
                }));
            }
        }
        Ok(None)
    }

    pub fn communication_list_workloads(&self) -> Result<Vec<String>, String> {
        // Return known workload identifiers from active buffers
        let buffers = block_on(self.communication.list_communication_buffers())
            .map_err(|e| e.to_string())?;
        Ok(buffers
            .iter()
            .map(|b| format!("workload-{}", b.name))
            .collect())
    }

    // ========================================================================
    // 10. CLOCK INTERFACE  (system-time, monotonic-time, resolution, sleep)
    // ========================================================================

    pub fn clock_system_time(&self) -> Result<WitSystemTime, String> {
        let time = self.clock.read_current_time().map_err(|e| e.to_string())?;
        Ok(WitSystemTime {
            seconds: time.seconds,
            nanoseconds: time.nanoseconds,
        })
    }

    pub fn clock_monotonic_time(&self) -> Result<WitMonotonicTime, String> {
        let time = self
            .clock
            .read_monotonic_time()
            .map_err(|e| e.to_string())?;
        Ok(WitMonotonicTime {
            elapsed_seconds: time.elapsed_seconds,
            elapsed_nanoseconds: time.elapsed_nanoseconds,
        })
    }

    pub fn clock_resolution(&self) -> Result<u64, String> {
        Ok(1) // nanosecond resolution
    }

    pub fn clock_sleep(&self, duration_ns: u64) -> Result<(), String> {
        let duration = std::time::Duration::from_nanos(duration_ns);
        block_on(self.clock.sleep(duration)).map_err(|e| e.to_string())
    }

    // ========================================================================
    // 11. RANDOM INTERFACE  (get-random-bytes, get-secure-random,
    //     get-entropy-info, reseed)
    // ========================================================================

    pub fn random_get_bytes(&self, length: u32) -> Result<Vec<u8>, String> {
        self.random
            .generate_random_bytes(length as usize)
            .map_err(|e| e.to_string())
    }

    pub fn random_get_secure(&self, length: u32) -> Result<Vec<u8>, String> {
        // Same implementation — all our random is cryptographically secure
        self.random
            .generate_random_bytes(length as usize)
            .map_err(|e| e.to_string())
    }

    pub fn random_get_entropy_info(&self) -> Result<EntropyInfo, String> {
        let is_hw = elastic_tee_hal::random::hardware_rng::is_hardware_rng_available();
        Ok(EntropyInfo {
            source: if is_hw {
                EntropySource::Hardware
            } else {
                EntropySource::Platform
            },
            quality: if is_hw { 100 } else { 80 },
            available_bytes: 1_048_576, // 1 MB available
        })
    }

    pub fn random_reseed(&self, _additional_entropy: &[u8]) -> Result<(), String> {
        // The underlying SystemRandom (ring) manages its own entropy pool
        Ok(())
    }
}

// ============================================================================
// WIT types mirrored from wit/world.wit interface definitions
// ============================================================================

// -- platform --
#[derive(Clone, Debug)]
pub struct PlatformInfo {
    pub platform_type: String,
    pub version: String,
    pub attestation_support: bool,
}

// -- capabilities --
#[derive(Clone, Debug)]
pub struct CapabilityInfo {
    pub feature_name: String,
    pub supported: bool,
    pub version: String,
}

// -- crypto --
#[derive(Clone, Debug)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    Blake3,
}

#[derive(Clone, Debug)]
pub enum CipherAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

#[derive(Clone, Debug)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

// -- storage --
#[derive(Clone, Debug)]
pub struct ObjectMetadata {
    pub size: u64,
    pub created_at: u64,
    pub content_type: String,
}

// -- sockets --
#[derive(Clone, Debug)]
pub enum Protocol {
    Tcp,
    Udp,
    Tls,
    Dtls,
}

#[derive(Clone, Debug)]
pub struct Address {
    pub ip: String,
    pub port: u16,
}

// -- gpu --
#[derive(Clone, Debug)]
pub enum BufferUsage {
    Storage,
    Uniform,
    Vertex,
    Index,
}

#[derive(Clone, Debug)]
pub struct AdapterInfo {
    pub name: String,
    pub vendor: String,
    pub device_type: String,
}

#[derive(Clone, Debug)]
pub struct BufferDescriptor {
    pub size: u64,
    pub usage: BufferUsage,
}

// -- resources --
#[derive(Clone, Debug)]
pub enum ResourceType {
    Memory,
    Cpu,
    Storage,
    Network,
}

#[derive(Clone, Debug)]
pub struct AllocationRequest {
    pub resource_type: ResourceType,
    pub amount: u64,
    pub priority: u32,
}

#[derive(Clone, Debug)]
pub struct AllocationResponse {
    pub allocation_id: String,
    pub granted_amount: u64,
}

// -- events --
#[derive(Clone, Debug)]
pub enum EventType {
    Platform,
    Crypto,
    Storage,
    Network,
    Gpu,
}

#[derive(Clone, Debug)]
pub struct EventDataWit {
    pub event_type: EventType,
    pub timestamp: u64,
    pub payload: Vec<u8>,
}

// -- communication --
#[derive(Clone, Debug)]
pub struct Message {
    pub sender: String,
    pub recipient: String,
    pub payload: Vec<u8>,
    pub encrypted: bool,
}

// -- clock --
#[derive(Clone, Debug)]
pub struct WitSystemTime {
    pub seconds: u64,
    pub nanoseconds: u32,
}

#[derive(Clone, Debug)]
pub struct WitMonotonicTime {
    pub elapsed_seconds: u64,
    pub elapsed_nanoseconds: u32,
}

// -- random --
#[derive(Clone, Debug)]
pub enum EntropySource {
    Hardware,
    Platform,
    Userspace,
}

#[derive(Clone, Debug)]
pub struct EntropyInfo {
    pub source: EntropySource,
    pub quality: u32,
    pub available_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn fds() -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().count()
    }

    #[test]
    fn socket_handle_carries_its_connection() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let host = HalHost::with_platform(elastic_tee_hal::platform::PlatformType::AmdSev).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = Address { ip: "127.0.0.1".into(), port: listener.local_addr().unwrap().port() };
        std::thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 || s.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });

        // Send and receive on the handle the guest got from create-socket.
        let s = host.sockets_create(Protocol::Tcp).unwrap();
        host.sockets_connect(s, &addr).unwrap();
        assert_eq!(host.sockets_send(s, b"ping").unwrap(), 4);
        assert_eq!(host.sockets_receive(s, 16).unwrap(), b"ping");
        host.sockets_close(s).unwrap();
        assert!(host.sockets_send(s, b"x").is_err());

        // Closing releases the connection: no descriptor growth over many cycles.
        let before = fds();
        for _ in 0..200 {
            let s = host.sockets_create(Protocol::Tcp).unwrap();
            host.sockets_connect(s, &addr).unwrap();
            host.sockets_close(s).unwrap();
        }
        // Allow for the echo threads still finishing their last connections.
        assert!(fds() < before + 20, "descriptors leaked: {} -> {}", before, fds());
    }
}
