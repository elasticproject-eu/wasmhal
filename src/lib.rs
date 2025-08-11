/// Confidential Computing Elastic TEE HAL - Hardware Abstraction Layer
/// for Trusted Execution Environments supporting WASI 0.2 specification
///
/// This crate provides a comprehensive interface for TEE workloads to interact
/// with platform-specific hardware features while maintaining portability across
/// different TEE implementations (AMD SEV-SNP, Intel TDX, ARM TrustZone, etc.)

// WIT bindgen configuration - enable when WIT dependencies are fully resolved
// For now, the WIT definitions are available in ./wit/world.wit
// wit_bindgen::generate!({
//     world: "elastic-tee-hal",
//     path: "wit"
// });

pub mod error;
pub mod platform;
pub mod capabilities;
pub mod clock;
pub mod random;
pub mod storage;
pub mod crypto;
pub mod sockets;
pub mod gpu;
pub mod resources;
pub mod events;
pub mod communication;

// Re-export main types
pub use error::{HalError, HalResult};
pub use platform::ElasticTeeHal;
pub use capabilities::PlatformCapabilities;
pub use clock::ClockInterface;
pub use random::RandomInterface;
pub use storage::StorageInterface;
pub use crypto::CryptoInterface;
pub use sockets::SocketInterface;
pub use gpu::GpuInterface;
pub use resources::ResourceInterface;
pub use events::EventInterface;
pub use communication::{CommunicationInterface, CommBufferHandle, BufferConfig, CommMessage, MessageType, MessagePriority};

/// HAL version information
pub const HAL_VERSION: &str = env!("CARGO_PKG_VERSION");

// WIT interface implementations
pub struct Platform;
pub struct Capabilities;
pub struct Crypto;
pub struct Storage;
pub struct Sockets;
pub struct Gpu;
pub struct Resources;
pub struct Events;
pub struct Communication;
pub const HAL_NAME: &str = "ELASTIC TEE HAL";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hal_creation() {
        let hal = ElasticTeeHal::new();
        assert!(hal.is_ok());
    }
}
