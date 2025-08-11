# ELASTIC TEE HAL

**Hardware Abstraction Layer for Trusted Execution Environments in Confidential Computing**

[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)
[![WASI](https://img.shields.io/badge/WASI-0.2-blue.svg)](https://wasi.dev)
[![TEE](https://img.shields.io/badge/TEE-AMD%20SEV--SNP-green.svg)](https://www.amd.com/en/developer/sev.html)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

The ELASTIC TEE HAL (Hardware Abstraction Layer) provides a comprehensive interface for Trusted Execution Environment (TEE) workloads to interact with platform-specific hardware features while maintaining portability across different TEE implementations. Built for confidential computing applications, it offers WASI 0.2 compliance and supports AMD SEV-SNP and Intel TDX platforms.

## 🚀 Features

### Core Interfaces

- **🌐 Network Communication** - TCP/UDP sockets with TLS/DTLS support
- **🔐 Cryptographic Operations** - Symmetric/asymmetric crypto, signing, platform attestation
- **⚡ GPU Compute Interface** - Hardware-accelerated compute pipelines
- **🎲 Secure Random Generation** - Cryptographically secure RNG with hardware entropy
- **⏰ Time Operations** - System time and monotonic clocks with TEE-aware timekeeping
- **💾 Encrypted Object Storage** - Container-based storage with AES-GCM encryption
- **📊 Resource Management** - Dynamic memory, CPU, and resource allocation tracking
- **📡 Event Handling** - Priority-based inter-workload event communication
- **🔗 Protected Communication** - Secure Wasm-to-Wasm message passing
- **🔍 Platform Capabilities** - Runtime feature discovery and platform limits
- **🏗️ Platform Detection** - Automatic TEE platform identification and initialization

### Security Features

- **Hardware Attestation** - Platform attestation report generation and verification
- **Encrypted Storage** - All data at rest encrypted with platform-derived keys
- **Secure Boot** - TEE secure boot verification and measurement
- **Memory Protection** - TEE-aware memory allocation and protection
- **Network Security** - TLS/DTLS with certificate management and validation

### Platform Support

- **AMD SEV-SNP** - Secure Nested Paging with guest attestation
- **Intel TDX** - Trust Domain Extensions with measurement and attestation (Incomplete)
- **ARM TrustZone** - Future support planned
- **Generic TEE** - Fallback implementation for other platforms

## 📋 Requirements

- **Rust 2021 Edition** or later
- **WASI 0.2** compatible runtime (Wasmtime recommended)
- **TEE Platform** - AMD SEV-SNP
- **GPU** (optional) - For compute acceleration features

## 🛠️ Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
elastic-tee-hal = "0.1.0"
```

## 🔧 Quick Start

### Basic HAL Initialization

```rust
use elastic_tee_hal::{ElasticTeeHal, HalResult};

#[tokio::main]
async fn main() -> HalResult<()> {
    // Initialize HAL with automatic platform detection
    let hal = ElasticTeeHal::new()?;
    
    // Initialize platform-specific features
    hal.initialize().await?;
    
    // Get platform capabilities
    let capabilities = hal.get_capabilities().await?;
    println!("Platform: {:?}", capabilities.platform_type);
    println!("Features: {:?}", capabilities.features);
    
    Ok(())
}
```

### Cryptographic Operations

```rust
use elastic_tee_hal::{CryptoInterface, HalResult};

async fn crypto_example() -> HalResult<()> {
    let crypto = CryptoInterface::new().await?;
    
    // Generate key pair
    let keypair = crypto.generate_key_pair("Ed25519").await?;
    
    // Sign data
    let data = b"Hello, TEE!";
    let signature = crypto.sign(&keypair.private_key, data, "Ed25519").await?;
    
    // Verify signature
    let is_valid = crypto.verify(&keypair.public_key, data, &signature, "Ed25519").await?;
    println!("Signature valid: {}", is_valid);
    
    // Platform attestation
    let nonce = crypto.generate_nonce(32)?;
    let attestation = crypto.get_platform_attestation(&nonce).await?;
    println!("Attestation: {:?}", attestation);
    
    Ok(())
}
```

### Secure Storage

```rust
use elastic_tee_hal::{StorageInterface, StorageConfig, HalResult};

async fn storage_example() -> HalResult<()> {
    let storage = StorageInterface::new().await?;
    
    // Create encrypted storage container
    let config = StorageConfig {
        name: "my-container".to_string(),
        capacity_mb: 100,
        encrypted: true,
        compression: true,
    };
    
    let container = storage.create_container(config).await?;
    
    // Store encrypted object
    let data = b"Confidential data";
    let object_id = storage.store_object(container, "secret.txt", data, None).await?;
    
    // Retrieve and decrypt object
    let retrieved = storage.get_object(container, &object_id).await?;
    println!("Retrieved: {:?}", String::from_utf8(retrieved));
    
    Ok(())
}
```

### Network Communication

```rust
use elastic_tee_hal::{SocketInterface, HalResult};

async fn network_example() -> HalResult<()> {
    let sockets = SocketInterface::new();
    
    // Create secure TLS connection
    let socket = sockets.create_tls_client(
        "example.com:443",
        "example.com",
        None // Use default TLS config
    ).await?;
    
    // Send data
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    sockets.send(socket, data).await?;
    
    // Receive response
    let response = sockets.receive(socket, 1024).await?;
    println!("Response: {:?}", String::from_utf8_lossy(&response));
    
    Ok(())
}
```

### Protected Inter-Workload Communication

```rust
use elastic_tee_hal::{CommunicationInterface, BufferConfig, MessageType, MessagePriority, HalResult};

async fn communication_example() -> HalResult<()> {
    let comm = CommunicationInterface::new();
    
    // Set up communication buffer
    let config = BufferConfig {
        name: "workload-channel".to_string(),
        capacity: 4096,
        is_encrypted: true,
        read_permissions: vec!["workload1".to_string(), "workload2".to_string()],
        write_permissions: vec!["workload1".to_string(), "workload2".to_string()],
        admin_permissions: vec!["admin".to_string()],
    };
    
    let buffer_handle = comm.setup_communication_buffer(config).await?;
    
    // Send message from workload1
    let message_data = b"Hello from workload1!";
    comm.push_data_to_buffer(
        buffer_handle,
        message_data,
        "workload1",
        MessageType::Data,
        MessagePriority::Normal,
    ).await?;
    
    // Receive message in workload2
    if let Some(message) = comm.read_data_from_buffer(buffer_handle, "workload2").await? {
        println!("Received from {}: {:?}", message.sender, String::from_utf8(message.data));
    }
    
    Ok(())
}
```

### GPU Compute

```rust
use elastic_tee_hal::{GpuInterface, HalResult};

async fn gpu_example() -> HalResult<()> {
    let gpu = GpuInterface::new().await?;
    
    // List available GPU adapters
    let adapters = gpu.list_adapters().await?;
    println!("Available GPUs: {}", adapters.len());
    
    // Create device on first adapter
    if let Some(adapter) = adapters.first() {
        let device = gpu.create_device(adapter.handle, &[]).await?;
        
        // Create compute pipeline
        let shader_code = include_bytes!("compute_shader.wgsl");
        let pipeline = gpu.create_compute_pipeline(device, shader_code, "main", [64, 1, 1]).await?;
        
        // Create buffers and run computation
        let input_data = vec![1.0f32; 1024];
        let input_buffer = gpu.create_buffer(device, &bytemuck::cast_slice(&input_data), true, false).await?;
        let output_buffer = gpu.create_buffer(device, &vec![0u8; 4096], false, true).await?;
        
        // Execute compute pass
        let compute_pass = gpu.begin_compute_pass(device, pipeline).await?;
        gpu.set_buffer(compute_pass, 0, input_buffer).await?;
        gpu.set_buffer(compute_pass, 1, output_buffer).await?;
        gpu.dispatch(compute_pass, 16, 1, 1).await?;
        gpu.end_compute_pass(compute_pass).await?;
        
        // Read results
        let results = gpu.read_buffer(output_buffer).await?;
        println!("Compute results: {:?}", results);
    }
    
    Ok(())
}
```

## 🏗️ Architecture

### Interface Modules

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Applications  │    │   WASI Workloads │    │  TEE Workloads  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
              ┌──────────────────────────────────────┐
              │        ELASTIC TEE HAL              │
              ├──────────────────────────────────────┤
              │  Network  │  Crypto   │  Storage    │
              │  Sockets  │  Operations│  Encrypted  │
              ├──────────────────────────────────────┤
              │   GPU     │  Random   │   Clock     │
              │  Compute  │   Secure  │  Operations │
              ├──────────────────────────────────────┤
              │ Resources │  Events   │   Comm      │
              │ Management│ Handling  │ Protected   │
              ├──────────────────────────────────────┤
              │        Platform Detection            │
              │         & Capabilities               │
              └──────────────────────────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
  ┌─────────────┐       ┌──────────────┐       ┌─────────────┐
  │  AMD SEV-SNP│       │  Intel TDX   │       │  ARM TZ     │
  │   Platform  │       │   Platform   │       │  (Future)   │
  └─────────────┘       └──────────────┘       └─────────────┘
```

### Error Handling

```rust
use elastic_tee_hal::{HalError, HalResult};

// All operations return HalResult<T>
match some_hal_operation().await {
    Ok(result) => println!("Success: {:?}", result),
    Err(HalError::PlatformNotSupported(msg)) => eprintln!("Platform error: {}", msg),
    Err(HalError::CryptographicError(msg)) => eprintln!("Crypto error: {}", msg),
    Err(HalError::NetworkError(msg)) => eprintln!("Network error: {}", msg),
    Err(HalError::StorageError(msg)) => eprintln!("Storage error: {}", msg),
    Err(e) => eprintln!("Other error: {:?}", e),
}
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific interface tests
cargo test crypto::tests
cargo test storage::tests
cargo test communication::tests

# Run with features
cargo test --features gpu
```

## 🏆 Performance

The HAL is designed for high-performance confidential computing:

- **Zero-copy operations** where possible
- **Async/await** throughout for non-blocking I/O
- **Hardware acceleration** via GPU compute and crypto instructions
- **Memory pool management** for reduced allocation overhead
- **Efficient serialization** with bincode for inter-workload communication

## 🔒 Security Considerations

### Platform Attestation
- All cryptographic operations can include platform measurements
- Remote attestation supported via platform-specific mechanisms
- Hardware-rooted trust chain validation

### Memory Protection
- All sensitive data encrypted in memory when possible
- Secure memory allocation patterns for TEE environments
- Stack and heap protection via platform features

### Network Security
- TLS 1.3 minimum for all network communications
- Certificate pinning and validation
- Perfect forward secrecy for all connections

## 📚 API Documentation

### Core Interfaces

| Interface | Purpose | Key Methods |
|-----------|---------|-------------|
| `ElasticTeeHal` | Main HAL entry point | `new()`, `initialize()`, `get_capabilities()` |
| `CryptoInterface` | Cryptographic operations | `encrypt()`, `decrypt()`, `sign()`, `verify()` |
| `StorageInterface` | Encrypted storage | `create_container()`, `store_object()`, `get_object()` |
| `SocketInterface` | Network communication | `create_tls_client()`, `send()`, `receive()` |
| `CommunicationInterface` | Inter-workload messaging | `setup_communication_buffer()`, `push_data_to_buffer()` |
| `GpuInterface` | GPU compute | `create_device()`, `create_compute_pipeline()`, `dispatch()` |
| `ResourceInterface` | Resource management | `allocate_memory()`, `allocate_cpu()`, `get_usage_stats()` |
| `EventInterface` | Event handling | `subscribe()`, `publish()`, `unsubscribe()` |

### Platform Types

```rust
pub enum PlatformType {
    AmdSev,    // AMD SEV-SNP
    IntelTdx,  // Intel TDX
}

pub struct PlatformCapabilities {
    pub platform_type: PlatformType,
    pub hal_version: String,
    pub features: CapabilityFeatures,
    pub limits: PlatformLimits,
    pub crypto_support: CryptoSupport,
}
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/syafiq/wasmhal.git
cd wasmhal

# Install Rust toolchain
rustup target add wasm32-wasi

# Build the project
cargo build

# Run tests
cargo test

# Check formatting and lints
cargo fmt
cargo clippy
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **ELASTIC Consortium** - For confidential computing research and development
- **WASI Community** - For WebAssembly System Interface specifications
- **AMD and Intel** - For TEE platform documentation and support
- **Rust Community** - For excellent async and cryptographic libraries

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/syafiq/wasmhal/issues)
- **Discussions**: [GitHub Discussions](https://github.com/syafiq/wasmhal/discussions)

---

**Built with ❤️ for Confidential Computing and Trusted Execution Environments**
