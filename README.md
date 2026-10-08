# ELASTIC TEE HAL

**Hardware Abstraction Layer for Trusted Execution Environments in Confidential Computing**

[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)
[![WASI](https://img.shields.io/badge/WASI-0.2-blue.svg)](https://wasi.dev)
[![TEE](https://img.shields.io/badge/TEE-AMD%20SEV--SNP-green.svg)](https://www.amd.com/en/developer/sev.html)
[![TDX](https://img.shields.io/badge/Intel%20TDX-Implemented-green.svg)](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

The ELASTIC TEE HAL (Hardware Abstraction Layer) provides a comprehensive interface for Trusted Execution Environment (TEE) workloads to interact with platform-specific hardware features while maintaining portability across different TEE implementations. Built for confidential computing applications, it offers WASI 0.2 compliance and supports both AMD SEV-SNP and Intel TDX platforms.

## Features

### Core Interfaces

- **Network Communication** - TCP/UDP sockets with TLS/DTLS support
- **Cryptographic Operations** - Symmetric/asymmetric crypto, signing, platform attestation
- **GPU Compute Interface** - Hardware-accelerated compute pipelines
- **Secure Random Generation** - Cryptographically secure RNG with hardware entropy
- **Time Operations** - System time and monotonic clocks with TEE-aware timekeeping
- **Encrypted Object Storage** - Container-based storage with AES-GCM encryption
- **Resource Management** - Dynamic memory, CPU, and resource allocation tracking
- **Event Handling** - Priority-based inter-workload event communication
- **Protected Communication** - Secure Wasm-to-Wasm message passing
- **Platform Capabilities** - Runtime feature discovery and platform limits
- **Platform Detection** - Automatic TEE platform identification and initialization

### Security Features

- **Hardware attestation:** generates SEV-SNP reports and TDX quotes through the Linux TSM interface, with a caller-supplied nonce bound into the report data. The relying party verifies the evidence.
- **Memory protection:** comes from the TEE itself. AMD SEV-SNP and Intel TDX encrypt and integrity-protect guest memory against the host.
- **Encrypted storage:** opt-in encrypted containers (AES-256-GCM, with keys generated per container).
- **Workload isolation:** the Wasm sandbox, plus composable WIT worlds, so each workload gets only the interfaces it needs.
- **Capability enforcement:** per-entity capabilities, rate limits and an audit log (`src/enforcement/`).
- **TLS:** client and server connections through rustls.

### Platform Support

- **AMD SEV-SNP** - Secure Nested Paging with guest attestation ✅ **Fully Implemented**
- **Intel TDX** - Trust Domain Extensions with measurement and attestation ✅ **Fully Implemented**
  - Hardware RNG (RDRAND/RDSEED)
  - TD Quote generation with MRTD and RTMR measurements
  - TSM (Trust Security Module) integration
  - All 4 WASI interfaces verified and operational
- **ARM TrustZone** - Future support planned
- **Generic TEE** - Fallback implementation for other platforms

## Requirements

- **Rust** (stable, 2021 edition), with the `wasm32-wasip2` target for building Wasm components (`rustup target add wasm32-wasip2`).
- **System packages** for the TPM support used on Azure confidential VMs: `pkg-config` and `libtss2-dev` (Debian/Ubuntu: `sudo apt-get install -y build-essential pkg-config libtss2-dev`).
- **A Confidential VM**, AMD SEV-SNP or Intel TDX, for attestation. Everything else also runs on ordinary Linux machines. See [Deployment](#deployment).
- **A GPU** (optional), for the compute features.

## Installation

The crate is not published on crates.io. Add it as a git dependency in your `Cargo.toml`:

```toml
[dependencies]
elastic-tee-hal = { git = "https://github.com/elasticproject-eu/wasmhal" }
```

To run Wasm components with the HAL linked in, use the `hal-runtime` crate in [`hal-runtime/`](hal-runtime/). It is a Wasmtime host library plus a `hal-runtime` command-line tool.

## Quick Start

### Basic HAL Initialization

```rust
use elastic_tee_hal::{ElasticTeeHal, HalResult};

#[tokio::main]
async fn main() -> HalResult<()> {
    // Initialize HAL with automatic platform detection
    // Detects AMD SEV-SNP or Intel TDX automatically
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

## Architecture

### Simplified System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    WASI 0.2 Applications                       │
│                 (WebAssembly Workloads)                        │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ELASTIC TEE HAL                             │
│                                                                 │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐ │
│  │   Crypto    │ │** Storage **│ │** Network **│ │** Clock **│ │
│  │             │ │ (WASI I/O)  │ │ (WASI)      │ │ (WASI)    │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └───────────┘ │
│                                                                 │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐ │
│  │     GPU     │ │  Resources  │ │    Events   │ │** Random**│ │
│  │             │ │             │ │             │ │ (WASI)    │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └───────────┘ │
│                                                                 │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐               │
│  │    Comm     │ │  Platform   │ │Capabilities │               │
│  │             │ │             │ │             │               │
│  └─────────────┘ └─────────────┘ └─────────────┘               │
│                                                                 │
│  ** Bold ** = WASI 0.2 Standard Interfaces                     │
│  Clock, Random, Network, Storage I/O                           │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                   TEE Hardware Platforms                       │
│                                                                 │
│           ┌─────────────┐              ┌─────────────┐          │
│           │ AMD SEV-SNP │              │ Intel TDX   │          │
│           │ ✅ Working  │              │ ✅ Working  │          │
│           └─────────────┘              └─────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

### Detailed System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           WASI 0.2 Runtime Layer                           │
│                        (Wasmtime, WasmEdge, etc.)                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ WIT Bindings
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        WebAssembly Component Model                         │
│                         (Component Instantiation)                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ELASTIC TEE HAL CORE                             │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐            │
│  │   Platform      │  │  Capabilities   │  │     Error       │            │
│  │   Detection     │  │   Discovery     │  │   Handling      │            │
│  │                 │  │                 │  │                 │            │
│  │ • Auto-detect   │  │ • Feature list  │  │ • Unified       │            │
│  │ • AMD SEV ✅    │  │ • Platform      │  │   error types   │            │
│  │ • Intel TDX ✅  │  │   limits        │  │ • Result<T,E>   │            │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                        ┌─────────────┼─────────────┐
                        │             │             │
                        ▼             ▼             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           INTERFACE LAYER                                  │
│                                                                             │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐ │
│  │    Crypto     │  │   Storage     │  │   Network     │  │    Clock    │ │
│  │ ============= │  │ ============= │  │ ============= │  │ =========== │ │
│  │ • Ed25519     │  │ • AES-256-GCM │  │ • TCP/UDP     │  │ • System    │ │
│  │ • AES/ChaCha  │  │ • Container   │  │ • TLS/DTLS    │  │ • Monotonic │ │
│  │ • HMAC/SHA    │  │   mgmt        │  │ • Rustls      │  │ • TEE-aware │ │
│  │ • Attestation │  │ • Encryption  │  │ • WebPKI      │  │   timing    │ │
│  └───────────────┘  └───────────────┘  └───────────────┘  └─────────────┘ │
│                                                                             │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐ │
│  │      GPU      │  │   Resources   │  │    Events     │  │   Random    │ │
│  │ ============= │  │ ============= │  │ ============= │  │ =========== │ │
│  │ • Compute     │  │ • Memory      │  │ • Priority    │  │ • Hardware  │ │
│  │   pipelines   │  │   allocation  │  │   queues      │  │   entropy   │ │
│  │ • WGPU (opt)  │  │ • CPU usage   │  │ • Publisher/  │  │ • Crypto    │ │
│  │ • Future      │  │ • Tracking    │  │   Subscriber  │  │   secure    │ │
│  └───────────────┘  └───────────────┘  └───────────────┘  └─────────────┘ │
│                                                                             │
│  ┌─────────────────────────────────────┐  ┌─────────────────────────────────┐ │
│  │          Communication              │  │       WIT Exports              │ │
│  │ ============================        │  │ ============================= │ │
│  │ • Inter-workload messaging          │  │ All 11 interfaces exported:   │ │
│  │ • Encrypted channels                │  │ • platform, capabilities      │ │
│  │ • Permission-based access           │  │ • crypto, storage, sockets    │ │
│  │ • Message priorities & types        │  │ • gpu, resources, events      │ │
│  └─────────────────────────────────────┘  │ • communication, clock, random │ │
│                                           └─────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                        ┌─────────────┼─────────────┐
                        │             │             │
                        ▼             ▼             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          PLATFORM LAYER                                    │
│                                                                             │
│  ┌─────────────────┐       ┌─────────────────┐       ┌───────────────────┐ │
│  │   AMD SEV-SNP   │       │   Intel TDX     │       │   Generic/Future  │ │
│  │ =============== │       │ =============== │       │ ================= │ │
│  │ ✅ Working      │       │ ✅ Working      │       │ Future Platforms  │ │
│  │                 │       │                 │       │                   │ │
│  │ Hardware:       │       │ Hardware:       │       │ • ARM TrustZone   │ │
│  │ • /dev/sev-*    │       │ • /dev/tdx_guest│       │ • RISC-V Keystone │ │
│  │ • TSM support   │       │ • TSM support   │       │ • Others...       │ │
│  │ • Real detect   │       │ • RDRAND/RDSEED │       │                   │ │
│  │ • Attestation   │       │ • TD Quote gen  │       │                   │ │
│  └─────────────────┘       └─────────────────┘       └───────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         HARDWARE/OS LAYER                                  │
│                                                                             │
│    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                  │
│    │    TEE      │    │   Crypto    │    │   Network   │                  │
│    │  Hardware   │    │  Hardware   │    │    Stack    │                  │
│    │             │    │             │    │             │                  │
│    │ • SEV-SNP   │    │ • AES-NI    │    │ • TCP/IP    │                  │
│    │ • TDX       │    │ • RDRAND    │    │ • TLS libs  │                  │
│    │ • TrustZone │    │ • RDSEED    │    │ • Sockets   │                  │
│    │   (future)  │    │ • Platform  │    │             │                  │
│    │             │    │   RNG       │    │             │                  │
│    └─────────────┘    └─────────────┘    └─────────────┘                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow Architecture

```
Application/Workload Request
         │
         ▼
┌─────────────────┐
│ WASI Component  │ ──► WIT Interface Binding
│     Runtime     │
└─────────────────┘
         │
         ▼
┌─────────────────┐
│ ElasticTeeHal   │ ──► Platform Detection & Capabilities
│   (Core HAL)    │
└─────────────────┘
         │
         ├──► CryptoInterface ──► ring/ed25519-dalek ──► Hardware crypto
         │
         ├──► StorageInterface ──► AES-GCM encryption ──► Filesystem
         │
         ├──► SocketInterface ──► tokio-rustls ──► Network stack
         │
         ├──► CommunicationInterface ──► Inter-workload channels
         │
         └──► Other interfaces...
                │
                ▼
         Platform-specific implementation
                │
                ▼
         Hardware/OS resources
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

## Testing

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

## Deployment

### Tested environments

| Platform | Environment | Status |
| --- | --- | --- |
| AMD SEV-SNP | GCP `n2d-standard-8` Confidential VM, Ubuntu 24.04, Linux 7.0 | Tested, including attestation |
| Intel TDX | GCP `c3-standard-8` Confidential VM, Ubuntu 24.04, Linux 7.0 | Tested, including attestation |
| AMD SEV-SNP (Azure) | Confidential VM with a paravisor (attestation through the vTPM) | Supported by platform detection |
| Non-TEE Linux (x86-64) | Any | Everything except attestation |

### What the guest needs for attestation

- **Linux 6.7 or later** with the TSM report interface (`CONFIG_TSM_REPORTS`), and configfs mounted at `/sys/kernel/config`. Ubuntu 24.04 on GCP provides both.
- **The TEE guest device:** `/dev/sev-guest` (SEV-SNP) or `/dev/tdx_guest` (TDX).
- **Root privileges** for the process that requests reports, because the configfs entries are root-owned.

You can check all three with:

```bash
sudo dmesg | grep -i 'Memory Encryption'     # "AMD SEV SEV-ES SEV-SNP" or "Intel TDX"
ls -l /dev/sev-guest /dev/tdx_guest          # one of them must exist
ls /sys/kernel/config/tsm/report             # TSM configfs is available
```

On GCP, such a VM is created with, for example:

```bash
gcloud compute instances create my-tdx-vm --zone us-central1-a \
  --machine-type c3-standard-8 --confidential-compute-type TDX \
  --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud
```

For SEV-SNP, use `--machine-type n2d-standard-8 --confidential-compute-type SEV_SNP`.

### Running a component

```bash
cd hal-runtime
cargo build --release
sudo ./target/release/hal-runtime path/to/component.wasm      # add -v for debug logging
```

The component must implement the `hal-consumer` world (`hal-runtime/wit/`), which exports `run`.

**Runtime settings:**
- `hal-runtime` stores storage-interface data under `/tmp/hal-storage`.
- Each open socket uses a file descriptor, so raise `ulimit -n` for workloads with many connections.

See [SECURITY.md](SECURITY.md) for deployment security guidelines.

## Troubleshooting and debugging

### Logging

The library logs through the [`log`](https://docs.rs/log) crate. Your application has to install a logger to see the output, for example `env_logger::init()`. Then choose the level with `RUST_LOG`:

```bash
RUST_LOG=elastic_tee_hal=debug cargo run              # HAL debug output
RUST_LOG=debug ./target/release/hal-runtime app.wasm  # everything
./target/release/hal-runtime -v app.wasm              # same as debug level
```

At debug level, platform detection logs each check it makes (CPU vendor, device nodes, TSM configfs, vTPM). That is usually the fastest way to see why a TEE was not detected.

### Common problems

| Symptom | Cause and fix |
| --- | --- |
| The build fails in `tss-esapi-sys` or reports that `tss2-sys`/`pkg-config` was not found | Install `pkg-config` and `libtss2-dev`. |
| `No supported TEE platform detected` | The process doesn't see a supported TEE. Run the three checks under [Deployment](#what-the-guest-needs-for-attestation), then look at the detection output with `RUST_LOG=debug`. On a non-TEE machine this error is expected. |
| `TSM configfs not available at /sys/kernel/config/tsm/report` | The kernel is older than 6.7, was built without `CONFIG_TSM_REPORTS`, or configfs isn't mounted (`sudo mount -t configfs none /sys/kernel/config`). |
| Attestation fails with `Permission denied` | Requesting reports through the configfs needs root. Run the host process with `sudo`. |
| `Too many open files` | Sockets weren't closed, or `ulimit -n` is too low for the workload. Close sockets with `sockets::close`, or raise the limit. |
| `test_platform_integration` fails | It needs TEE hardware. Run it on a Confidential VM. The TDX integration tests are `#[ignore]`d. Run them with `cargo test -- --ignored` on a TDX guest, with `ITA_API_KEY` set. |

### Debugging tests and examples

```bash
cargo test -- --nocapture              # show test output
RUST_LOG=debug cargo test <name> -- --nocapture
cargo run --release --example perf     # micro-benchmarks, see PERFORMANCE.md
```

## Performance

Measured on GCP Confidential VMs (AMD SEV-SNP and Intel TDX):

- **HAL calls from a Wasm component** cost about 0.1–0.5 µs more than native calls, plus data copying. That is 1–10 % for crypto, storage and network operations.
- **Attestation** (nonce plus evidence) takes about 82–96 ms.
- **Deploying a workload:** compiling a 271 KiB component takes 54–60 ms, and instantiating it takes 63–73 µs.
- **The enforcement layer** adds about 0.2–0.3 µs per call.

See [PERFORMANCE.md](PERFORMANCE.md) for the full results per WIT world, the method, and how to reproduce them.

## Security Considerations

- **Attestation:** the HAL produces attestation evidence: the SNP report or TDX quote, plus the measurements, with the caller's nonce bound into the report data. Verifying the hardware signature and the measurements is up to the relying party.
- **Isolation:** workloads are isolated by the Wasm sandbox, and can only use the HAL interfaces linked into their WIT world. The enforcement layer adds per-entity capabilities, rate limits and auditing.
- **What the TEE protects:** guest memory. Storage and network I/O leave the guest, so use encrypted storage containers and application-layer encryption for sensitive data.

See [SECURITY.md](SECURITY.md) for the security model, deployment guidelines, and how to report vulnerabilities.

## API Documentation

### Core Interfaces

| Interface                | Purpose                  | Key Methods                                                  |
| ------------------------ | ------------------------ | ------------------------------------------------------------ |
| `ElasticTeeHal`          | Main HAL entry point     | `new()`, `initialize()`, `get_capabilities()`                |
| `CryptoInterface`        | Cryptographic operations | `encrypt()`, `decrypt()`, `sign()`, `verify()`               |
| `StorageInterface`       | Encrypted storage        | `create_container()`, `store_object()`, `get_object()`       |
| `SocketInterface`        | Network communication    | `create_tls_client()`, `send()`, `receive()`                 |
| `CommunicationInterface` | Inter-workload messaging | `setup_communication_buffer()`, `push_data_to_buffer()`      |
| `GpuInterface`           | GPU compute              | `create_device()`, `create_compute_pipeline()`, `dispatch()` |
| `ResourceInterface`      | Resource management      | `allocate_memory()`, `allocate_cpu()`, `get_usage_stats()`   |
| `EventInterface`         | Event handling           | `subscribe()`, `publish()`, `unsubscribe()`                  |

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

## Contributing

We welcome contributions! In short: open an issue first for larger changes, work on a branch, make sure `cargo fmt`, `cargo clippy` and `cargo test` pass, and open a pull request against `main`. See the [Contributing Guide](CONTRIBUTING.md) for details. Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

### Development Setup

```bash
# Clone the repository
git clone https://github.com/elasticproject-eu/wasmhal.git
cd wasmhal

# Install the build dependencies and Wasm targets
sudo apt-get install -y build-essential pkg-config libtss2-dev
rustup target add wasm32-wasip1 wasm32-wasip2

# Build the project
cargo build

# Run tests
cargo test

# Check formatting and lints
cargo fmt
cargo clippy
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **ELASTIC Consortium** - For confidential computing research and development
- **WASI Community** - For WebAssembly System Interface specifications
- **AMD and Intel** - For TEE platform documentation and support
- **Rust Community** - For excellent async and cryptographic libraries

## Funding

This work has been partially supported by the [ELASTIC project](https://elasticproject.eu/), which received funding from the [Smart Networks and Services Joint Undertaking](https://smart-networks.europa.eu/) (SNS JU) under the European Union’s [Horizon Europe](https://research-and-innovation.ec.europa.eu/funding/funding-opportunities/funding-programmes-and-open-calls/horizon-europe_en) research and innovation programme under [Grant Agreement No. 101139067](https://cordis.europa.eu/project/id/101139067). Views and opinions expressed are however those of the author(s) only and do not necessarily reflect those of the European Union. Neither the European Union nor the granting authority can be held responsible for them.

## Support

- **Issues**: [GitHub Issues](https://github.com/elasticproject-eu/wasmhal/issues)
- **Security vulnerabilities**: see [SECURITY.md](SECURITY.md); please don't use public issues.

---

**Built for Confidential Computing and Trusted Execution Environments**
