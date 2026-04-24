//! Host trait implementations for all WIT interfaces.
//!
//! Bridges wasmtime::component::bindgen!-generated Host traits to native HAL
//! via HalHost. Each impl block corresponds to one WIT interface.
//! The `#[async_trait]` attribute is required because wasmtime 25's bindgen
//! generates Pin<Box<dyn Future>> style async traits.

use crate::RuntimeState;

// Re-export generated modules from bindgen!
use crate::elastic::hal::{
    attestation, clock, communication, crypto, events, gpu, platform, random, resources, sockets,
    storage,
};

use wasmtime::component::__internal::async_trait;

// ============================================================================
// 1. PLATFORM
// ============================================================================
#[async_trait]
impl platform::Host for RuntimeState {
    async fn get_platform_info(&mut self) -> platform::PlatformInfo {
        let info = self.hal.platform_info();
        platform::PlatformInfo {
            platform_type: info.platform_type,
            version: info.version,
        }
    }

    async fn list_capabilities(&mut self) -> Vec<platform::CapabilityInfo> {
        self.hal
            .capabilities_list()
            .into_iter()
            .map(|c| platform::CapabilityInfo {
                feature_name: c.feature_name,
                supported: c.supported,
                version: c.version,
            })
            .collect()
    }

    async fn has_capability(&mut self, feature_name: String) -> bool {
        self.hal.capabilities_has(&feature_name)
    }
}

// ============================================================================
// 2. ATTESTATION
// ============================================================================
#[async_trait]
impl attestation::Host for RuntimeState {
    async fn attestation(&mut self, report_data: Vec<u8>) -> Result<Vec<u8>, String> {
        self.hal.attestation(report_data)
    }
}

// ============================================================================
// 3. CRYPTO
// ============================================================================
#[async_trait]
impl crypto::Host for RuntimeState {
    async fn hash(
        &mut self,
        data: Vec<u8>,
        algorithm: crypto::HashAlgorithm,
    ) -> Result<Vec<u8>, String> {
        let algo = match algorithm {
            crypto::HashAlgorithm::Sha256 => crate::host_impl::HashAlgorithm::Sha256,
            crypto::HashAlgorithm::Sha512 => crate::host_impl::HashAlgorithm::Sha512,
            crypto::HashAlgorithm::Blake3 => crate::host_impl::HashAlgorithm::Blake3,
        };
        self.hal.crypto_hash(&data, algo)
    }

    async fn encrypt(
        &mut self,
        data: Vec<u8>,
        key: Vec<u8>,
        algorithm: crypto::CipherAlgorithm,
    ) -> Result<Vec<u8>, String> {
        let algo = match algorithm {
            crypto::CipherAlgorithm::Aes256Gcm => crate::host_impl::CipherAlgorithm::Aes256Gcm,
            crypto::CipherAlgorithm::Chacha20Poly1305 => {
                crate::host_impl::CipherAlgorithm::ChaCha20Poly1305
            }
        };
        self.hal.crypto_encrypt(&data, &key, algo)
    }

    async fn decrypt(
        &mut self,
        data: Vec<u8>,
        key: Vec<u8>,
        algorithm: crypto::CipherAlgorithm,
    ) -> Result<Vec<u8>, String> {
        let algo = match algorithm {
            crypto::CipherAlgorithm::Aes256Gcm => crate::host_impl::CipherAlgorithm::Aes256Gcm,
            crypto::CipherAlgorithm::Chacha20Poly1305 => {
                crate::host_impl::CipherAlgorithm::ChaCha20Poly1305
            }
        };
        self.hal.crypto_decrypt(&data, &key, algo)
    }

    async fn generate_keypair(&mut self) -> Result<crypto::KeyPair, String> {
        let kp = self.hal.crypto_generate_keypair()?;
        Ok(crypto::KeyPair {
            public_key: kp.public_key,
            private_key: kp.private_key,
        })
    }

    async fn sign(&mut self, data: Vec<u8>, private_key: Vec<u8>) -> Result<Vec<u8>, String> {
        self.hal.crypto_sign(&data, &private_key)
    }

    async fn verify(
        &mut self,
        data: Vec<u8>,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<bool, String> {
        self.hal.crypto_verify(&data, &signature, &public_key)
    }

    async fn create_context(&mut self) -> Result<crypto::CryptoContextHandle, String> {
        self.hal.crypto_create_context()
    }

    async fn destroy_context(
        &mut self,
        handle: crypto::CryptoContextHandle,
    ) -> Result<(), String> {
        self.hal.crypto_destroy_context(handle)
    }
}

// ============================================================================
// 4. STORAGE
// ============================================================================
#[async_trait]
impl storage::Host for RuntimeState {
    async fn create_container(
        &mut self,
        name: String,
    ) -> Result<storage::ContainerHandle, String> {
        self.hal.storage_create_container(&name)
    }

    async fn open_container(
        &mut self,
        name: String,
    ) -> Result<storage::ContainerHandle, String> {
        self.hal.storage_open_container(&name)
    }

    async fn delete_container(&mut self, handle: storage::ContainerHandle) -> Result<(), String> {
        self.hal.storage_delete_container(handle)
    }

    async fn store_object(
        &mut self,
        container: storage::ContainerHandle,
        key: String,
        data: Vec<u8>,
    ) -> Result<storage::ObjectHandle, String> {
        self.hal.storage_store_object(container, &key, &data)
    }

    async fn retrieve_object(
        &mut self,
        container: storage::ContainerHandle,
        key: String,
    ) -> Result<Vec<u8>, String> {
        self.hal.storage_retrieve_object(container, &key)
    }

    async fn delete_object(
        &mut self,
        container: storage::ContainerHandle,
        key: String,
    ) -> Result<(), String> {
        self.hal.storage_delete_object(container, &key)
    }

    async fn list_objects(
        &mut self,
        container: storage::ContainerHandle,
    ) -> Result<Vec<String>, String> {
        self.hal.storage_list_objects(container)
    }

    async fn get_metadata(
        &mut self,
        container: storage::ContainerHandle,
        key: String,
    ) -> Result<storage::ObjectMetadata, String> {
        let meta = self.hal.storage_get_metadata(container, &key)?;
        Ok(storage::ObjectMetadata {
            size: meta.size,
            created_at: meta.created_at,
            content_type: meta.content_type,
        })
    }
}

// ============================================================================
// 5. SOCKETS
// ============================================================================
#[async_trait]
impl sockets::Host for RuntimeState {
    async fn create_socket(
        &mut self,
        protocol: sockets::Protocol,
    ) -> Result<sockets::SocketHandle, String> {
        let p = match protocol {
            sockets::Protocol::Tcp => crate::host_impl::Protocol::Tcp,
            sockets::Protocol::Udp => crate::host_impl::Protocol::Udp,
            sockets::Protocol::Tls => crate::host_impl::Protocol::Tls,
            sockets::Protocol::Dtls => crate::host_impl::Protocol::Dtls,
        };
        self.hal.sockets_create(p)
    }

    async fn bind(
        &mut self,
        socket: sockets::SocketHandle,
        addr: sockets::Address,
    ) -> Result<(), String> {
        let a = crate::host_impl::Address {
            ip: addr.ip,
            port: addr.port,
        };
        self.hal.sockets_bind(socket, &a)
    }

    async fn listen(
        &mut self,
        socket: sockets::SocketHandle,
        backlog: u32,
    ) -> Result<(), String> {
        self.hal.sockets_listen(socket, backlog)
    }

    async fn connect(
        &mut self,
        socket: sockets::SocketHandle,
        addr: sockets::Address,
    ) -> Result<(), String> {
        let a = crate::host_impl::Address {
            ip: addr.ip,
            port: addr.port,
        };
        self.hal.sockets_connect(socket, &a).map(|_| ())
    }

    async fn accept(
        &mut self,
        socket: sockets::SocketHandle,
    ) -> Result<sockets::SocketHandle, String> {
        self.hal.sockets_accept(socket)
    }

    async fn send(
        &mut self,
        socket: sockets::SocketHandle,
        data: Vec<u8>,
    ) -> Result<u32, String> {
        self.hal.sockets_send(socket, &data)
    }

    async fn receive(
        &mut self,
        socket: sockets::SocketHandle,
        max_len: u32,
    ) -> Result<Vec<u8>, String> {
        self.hal.sockets_receive(socket, max_len)
    }

    async fn close(&mut self, socket: sockets::SocketHandle) -> Result<(), String> {
        self.hal.sockets_close(socket)
    }
}

// ============================================================================
// 6. GPU
// ============================================================================
#[async_trait]
impl gpu::Host for RuntimeState {
    async fn list_adapters(&mut self) -> Result<Vec<gpu::GpuAdapterHandle>, String> {
        self.hal.gpu_list_adapters()
    }

    async fn get_adapter_info(
        &mut self,
        handle: gpu::GpuAdapterHandle,
    ) -> Result<gpu::AdapterInfo, String> {
        let info = self.hal.gpu_get_adapter_info(handle)?;
        Ok(gpu::AdapterInfo {
            name: info.name,
            vendor: info.vendor,
            device_type: info.device_type,
        })
    }

    async fn create_device(
        &mut self,
        adapter: gpu::GpuAdapterHandle,
    ) -> Result<gpu::GpuDeviceHandle, String> {
        self.hal.gpu_create_device(adapter)
    }

    async fn create_buffer(
        &mut self,
        device: gpu::GpuDeviceHandle,
        descriptor: gpu::BufferDescriptor,
    ) -> Result<gpu::GpuBufferHandle, String> {
        let desc = crate::host_impl::BufferDescriptor {
            size: descriptor.size,
            usage: match descriptor.usage {
                gpu::BufferUsage::Storage => crate::host_impl::BufferUsage::Storage,
                gpu::BufferUsage::Uniform => crate::host_impl::BufferUsage::Uniform,
                gpu::BufferUsage::Vertex => crate::host_impl::BufferUsage::Vertex,
                gpu::BufferUsage::Index => crate::host_impl::BufferUsage::Index,
            },
        };
        self.hal.gpu_create_buffer(device, &desc)
    }

    async fn write_buffer(
        &mut self,
        buffer: gpu::GpuBufferHandle,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<(), String> {
        self.hal.gpu_write_buffer(buffer, offset, &data)
    }

    async fn read_buffer(
        &mut self,
        buffer: gpu::GpuBufferHandle,
        offset: u64,
        size: u64,
    ) -> Result<Vec<u8>, String> {
        self.hal.gpu_read_buffer(buffer, offset, size)
    }

    async fn create_compute_pipeline(
        &mut self,
        device: gpu::GpuDeviceHandle,
        shader_code: Vec<u8>,
    ) -> Result<gpu::GpuPipelineHandle, String> {
        self.hal.gpu_create_compute_pipeline(device, &shader_code)
    }

    async fn dispatch(
        &mut self,
        _device: gpu::GpuDeviceHandle,
        pipeline: gpu::GpuPipelineHandle,
        x: u32,
        y: u32,
        z: u32,
    ) -> Result<(), String> {
        self.hal.gpu_dispatch(pipeline, x, y, z)
    }
}

// ============================================================================
// 7. RESOURCES
// ============================================================================
#[async_trait]
impl resources::Host for RuntimeState {
    async fn allocate(
        &mut self,
        request: resources::AllocationRequest,
    ) -> Result<resources::AllocationResponse, String> {
        let req = crate::host_impl::AllocationRequest {
            resource_type: match request.resource_type {
                resources::ResourceType::Memory => crate::host_impl::ResourceType::Memory,
                resources::ResourceType::Cpu => crate::host_impl::ResourceType::Cpu,
                resources::ResourceType::Storage => crate::host_impl::ResourceType::Storage,
                resources::ResourceType::Network => crate::host_impl::ResourceType::Network,
            },
            amount: request.amount,
            priority: request.priority,
        };
        let resp = self.hal.resources_allocate(&req)?;
        Ok(resources::AllocationResponse {
            allocation_id: resp.allocation_id,
            granted_amount: resp.granted_amount,
        })
    }

    async fn deallocate(&mut self, id: resources::AllocationId) -> Result<(), String> {
        self.hal.resources_deallocate(&id)
    }

    async fn query_available(
        &mut self,
        resource_type: resources::ResourceType,
    ) -> Result<u64, String> {
        let rt = match resource_type {
            resources::ResourceType::Memory => crate::host_impl::ResourceType::Memory,
            resources::ResourceType::Cpu => crate::host_impl::ResourceType::Cpu,
            resources::ResourceType::Storage => crate::host_impl::ResourceType::Storage,
            resources::ResourceType::Network => crate::host_impl::ResourceType::Network,
        };
        self.hal.resources_query_available(rt)
    }
}

// ============================================================================
// 8. EVENTS
// ============================================================================
#[async_trait]
impl events::Host for RuntimeState {
    async fn subscribe(
        &mut self,
        event_type: events::EventType,
    ) -> Result<events::EventSubscriptionHandle, String> {
        let et = match event_type {
            events::EventType::Platform => crate::host_impl::EventType::Platform,
            events::EventType::Crypto => crate::host_impl::EventType::Crypto,
            events::EventType::Storage => crate::host_impl::EventType::Storage,
            events::EventType::Network => crate::host_impl::EventType::Network,
            events::EventType::Gpu => crate::host_impl::EventType::Gpu,
        };
        self.hal.events_subscribe(et)
    }

    async fn unsubscribe(
        &mut self,
        handle: events::EventSubscriptionHandle,
    ) -> Result<(), String> {
        self.hal.events_unsubscribe(handle)
    }

    async fn poll_events(
        &mut self,
        handle: events::EventSubscriptionHandle,
    ) -> Result<Vec<events::EventData>, String> {
        let evts = self.hal.events_poll(handle)?;
        Ok(evts
            .into_iter()
            .map(|e| events::EventData {
                event_type: match e.event_type {
                    crate::host_impl::EventType::Platform => events::EventType::Platform,
                    crate::host_impl::EventType::Crypto => events::EventType::Crypto,
                    crate::host_impl::EventType::Storage => events::EventType::Storage,
                    crate::host_impl::EventType::Network => events::EventType::Network,
                    crate::host_impl::EventType::Gpu => events::EventType::Gpu,
                },
                timestamp: e.timestamp,
                payload: e.payload,
            })
            .collect())
    }
}

// ============================================================================
// 9. COMMUNICATION
// ============================================================================
#[async_trait]
impl communication::Host for RuntimeState {
    async fn send_message(
        &mut self,
        recipient: communication::WorkloadId,
        data: Vec<u8>,
        encrypt: bool,
    ) -> Result<communication::MessageHandle, String> {
        self.hal
            .communication_send_message(&recipient, &data, encrypt)
    }

    async fn receive_message(&mut self) -> Result<Option<communication::Message>, String> {
        let msg = self.hal.communication_receive_message()?;
        Ok(msg.map(|m| communication::Message {
            sender: m.sender,
            recipient: m.recipient,
            payload: m.payload,
            encrypted: m.encrypted,
        }))
    }

    async fn list_workloads(&mut self) -> Result<Vec<communication::WorkloadId>, String> {
        self.hal.communication_list_workloads()
    }
}

// ============================================================================
// 10. CLOCK
// ============================================================================
#[async_trait]
impl clock::Host for RuntimeState {
    async fn get_system_time(&mut self) -> Result<clock::SystemTime, String> {
        let t = self.hal.clock_system_time()?;
        Ok(clock::SystemTime {
            seconds: t.seconds,
            nanoseconds: t.nanoseconds,
        })
    }

    async fn get_monotonic_time(&mut self) -> Result<clock::MonotonicTime, String> {
        let t = self.hal.clock_monotonic_time()?;
        Ok(clock::MonotonicTime {
            elapsed_seconds: t.elapsed_seconds,
            elapsed_nanoseconds: t.elapsed_nanoseconds,
        })
    }

    async fn resolution(&mut self) -> Result<u64, String> {
        self.hal.clock_resolution()
    }

    async fn sleep(&mut self, duration_ns: u64) -> Result<(), String> {
        self.hal.clock_sleep(duration_ns)
    }
}

// ============================================================================
// 11. RANDOM
// ============================================================================
#[async_trait]
impl random::Host for RuntimeState {
    async fn get_random_bytes(&mut self, length: u32) -> Result<Vec<u8>, String> {
        self.hal.random_get_bytes(length)
    }

    async fn get_secure_random(&mut self, length: u32) -> Result<Vec<u8>, String> {
        self.hal.random_get_secure(length)
    }

    async fn get_entropy_info(&mut self) -> Result<random::EntropyInfo, String> {
        let info = self.hal.random_get_entropy_info()?;
        Ok(random::EntropyInfo {
            source: match info.source {
                crate::host_impl::EntropySource::Hardware => random::EntropySource::Hardware,
                crate::host_impl::EntropySource::Platform => random::EntropySource::Platform,
                crate::host_impl::EntropySource::Userspace => random::EntropySource::Userspace,
            },
            quality: info.quality,
            available_bytes: info.available_bytes,
        })
    }

    async fn reseed(&mut self, additional_entropy: Vec<u8>) -> Result<(), String> {
        self.hal.random_reseed(&additional_entropy)
    }
}
